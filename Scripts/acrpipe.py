#!/usr/bin/env python3
"""ACR capture pipeline: turn TV pcaps into readable CSVs plus a summary, and compare runs.

Usage:
  scripts/acrpipe.py process <pcap>... [--tv-ip IP] [--tv-mac MAC] [--no-lookup] [--force]
  scripts/acrpipe.py compare <run A> <run B>

Each pcap gets its own folder, processed/<pcap stem>/. Raw captures are only read, never changed.

Units:
  - Byte totals (bytes_up, bytes_down) are frame bytes, the same numbers Wireshark's
    Conversations window shows.
  - Packet sizes in up_top_sizes are transport lengths: udp.length (includes the 8-byte
    UDP header) for UDP, tcp.len (payload only) for TCP.

Server lookups (owner, country, reverse DNS) send IP addresses to whois.cymru.com and to
the system DNS resolver. Results are cached in processed/_ipinfo.json. Use --no-lookup to skip.
"""

import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "processed"
BLOCKLIST = ROOT / "refs" / "Watching-the-Watchers" / "Blocklist" / "blocklist.txt"

# Bump when the parsed.json layout changes so cached parses are redone.
PARSE_VERSION = 1

FIELDS = [
    "frame.time_epoch", "frame.len", "eth.src", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.len",
    "udp.srcport", "udp.dstport", "udp.length",
    "dns.flags.response", "dns.qry.name", "dns.a", "dns.cname",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ja4",
    "x509ce.dNSName",
    "http.request.method", "http.host", "http.request.uri", "http.user_agent",
]

# Names that indicate ACR or vendor telemetry. Matching is a lead, not proof:
# confirm by comparing a content run against the idle baseline.
ACR_PATTERNS = [
    (r"tvinteractive\.tv$", "Inscape (Vizio ACR)"),
    (r"inscape", "Inscape (Vizio ACR)"),
    (r"kinesis\.[a-z0-9-]+\.amazonaws\.com$", "AWS Kinesis (Vizio analytics)"),
    (r"samba\.tv$|samba", "Samba TV (ACR)"),
    (r"alphonso", "Alphonso (ACR)"),
    (r"acrcloud|gracenote", "ACR provider"),
    (r"amagi", "Amagi (WatchFree+ ad/stream partner)"),
    (r"(^|[.-])acr[.-]", "Name contains 'acr'"),
]

# Flows seen in earlier runs whose server has no DNS name, matched by protocol and port.
PORT_SIGNATURES = [
    ("udp", 5558, "UDP 5558 stream (ACR fingerprint candidate, seen in Vizio WatchFree+ runs)"),
]

# A flow counts as a periodic candidate when the TV sends at least this many packets
# over at least this long, with gaps this regular (coefficient of variation).
PERIODIC_MIN_PKTS = 20
PERIODIC_MIN_SECONDS = 60
PERIODIC_MAX_CV = 0.5


def iso(t):
    return dt.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds") if t else ""


def scope_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_multicast or ip == "255.255.255.255":
        return "multicast"
    if a.is_private or a.is_link_local:
        return "lan"
    return "internet"


def first(v):
    return v.split("|")[0] if v else ""


def read_notes(pcap):
    """Read the key: value notes file tv-record writes next to each pcap."""
    notes = {}
    p = pcap.with_suffix(".txt")
    if p.exists():
        for line in p.read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                notes[k.strip()] = v.strip()
    return notes


def available_fields():
    out = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True).stdout
    return {line.split("\t")[2] for line in out.splitlines() if line.count("\t") >= 2}


# ---------------------------------------------------------------- parsing

def parse_pcap(pcap, tv_ips, tv_mac):
    have = available_fields()
    fields = [f for f in FIELDS if f in have]
    missing = [f for f in FIELDS if f not in have]
    if missing:
        print(f"  note: this tshark lacks fields {missing}; those columns stay empty", file=sys.stderr)
    cmd = ["tshark", "-n", "-r", str(pcap), "-T", "fields",
           "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|", "-E", "quote=n"]
    for f in fields:
        cmd += ["-e", f]
    ix = {f: i for i, f in enumerate(fields)}

    tv_ips = set(tv_ips)
    flows = {}
    syn_time = {}
    rtt = {}
    names = defaultdict(dict)  # ip -> {name: source}
    dns_rows, tls_rows, http_rows = [], [], []
    total = non_ipv4 = not_tv = 0
    t_first = t_last = None

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, errors="replace")
    for line in proc.stdout:
        c = line.rstrip("\n").split("\t")
        c += [""] * (len(fields) - len(c))
        g = lambda f: c[ix[f]] if f in ix else ""
        total += 1
        t = float(first(g("frame.time_epoch")) or 0)
        t_first = t if t_first is None else t_first
        t_last = t
        src, dst = first(g("ip.src")), first(g("ip.dst"))
        if not src:
            non_ipv4 += 1
            continue
        if tv_mac and first(g("eth.src")).lower() == tv_mac and scope_of(src) == "lan":
            tv_ips.add(src)
        if src in tv_ips:
            up, remote = True, dst
        elif dst in tv_ips:
            up, remote = False, src
        else:
            not_tv += 1
            continue

        if g("tcp.srcport"):
            proto, sp, dp = "tcp", first(g("tcp.srcport")), first(g("tcp.dstport"))
            l4 = int(first(g("tcp.len")) or 0)
        elif g("udp.srcport"):
            proto, sp, dp = "udp", first(g("udp.srcport")), first(g("udp.dstport"))
            l4 = int(first(g("udp.length")) or 0)
        else:
            proto, sp, dp, l4 = "ip" + first(g("ip.proto")), "0", "0", 0
        lport, rport = (int(sp), int(dp)) if up else (int(dp), int(sp))
        key = (proto, remote, rport, lport)
        fl = flows.get(key)
        if fl is None:
            fl = flows[key] = {"first": t, "last": t, "pkts_up": 0, "pkts_down": 0,
                               "bytes_up": 0, "bytes_down": 0, "up_times": [],
                               "up_sizes": Counter(), "initiator": ""}
        fl["last"] = t
        flen = int(first(g("frame.len")) or 0)
        if up:
            fl["pkts_up"] += 1
            fl["bytes_up"] += flen
            fl["up_times"].append(t)
            fl["up_sizes"][l4] += 1
        else:
            fl["pkts_down"] += 1
            fl["bytes_down"] += flen

        syn, ack = g("tcp.flags.syn") == "True", g("tcp.flags.ack") == "True"
        if syn and not ack:
            fl["initiator"] = fl["initiator"] or ("tv" if up else "remote")
            if up:
                syn_time[key] = t
        elif syn and ack and not up and key in syn_time:
            ms = (t - syn_time.pop(key)) * 1000
            rtt[remote] = min(ms, rtt.get(remote, ms))

        qname = g("dns.qry.name")
        if qname:
            is_resp = g("dns.flags.response") == "True"
            answers = [a for a in g("dns.a").split("|") if a]
            for a in answers:
                names[a].setdefault(qname.split("|")[0], "dns")
            dns_rows.append([iso(t), "response" if is_resp else "query", src, dst,
                             qname, " ".join(answers), g("dns.cname").replace("|", " ")])

        types = g("tls.handshake.type").split("|")
        if "1" in types and up:
            sni = g("tls.handshake.extensions_server_name").split("|")[0]
            if sni:
                names[remote][sni] = "sni"
            tls_rows.append([iso(t), remote, rport, sni, first(g("tls.handshake.ja4"))])
        if "11" in types and not up:
            for n in g("x509ce.dNSName").split("|")[:5]:
                if n:
                    names[remote].setdefault(n, "cert")

        if g("http.request.method"):
            http_rows.append([iso(t), src, dst, rport if up else lport, first(g("http.request.method")),
                              first(g("http.host")), first(g("http.request.uri")),
                              first(g("http.user_agent"))])
    proc.wait()
    if proc.returncode:
        sys.exit(f"tshark failed on {pcap}")

    flow_list = []
    for (proto, remote, rport, lport), fl in flows.items():
        ts = fl.pop("up_times")
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(gaps) if gaps else 0
        cv = (statistics.pstdev(gaps) / mean) if len(gaps) > 1 and mean > 0 else None
        if fl["initiator"] == "tv":
            direction, svc = "outbound", rport
        elif fl["initiator"] == "remote":
            direction, svc = "inbound", lport
        else:  # no SYN seen (UDP, or TCP opened before the capture): assume the lower port is the service
            svc = min(rport, lport) if rport and lport else rport
            direction = "outbound" if svc == rport else "inbound"
        dur = fl["last"] - fl["first"]
        flow_list.append({
            "proto": proto, "remote_ip": remote, "remote_port": rport, "tv_port": lport,
            "service_port": svc, "direction": direction, "scope": scope_of(remote),
            "first": fl["first"], "last": fl["last"], "duration_s": round(dur, 3),
            "pkts_up": fl["pkts_up"], "pkts_down": fl["pkts_down"],
            "bytes_up": fl["bytes_up"], "bytes_down": fl["bytes_down"],
            "up_pkts_per_min": round(fl["pkts_up"] / (dur / 60), 2) if dur > 0 else None,
            "up_median_gap_s": round(statistics.median(gaps), 3) if gaps else None,
            "up_gap_cv": round(cv, 3) if cv is not None else None,
            "up_top_sizes": " ".join(f"{s}x{n}" for s, n in fl["up_sizes"].most_common(3)),
            "initiator": fl["initiator"] or "unknown",
        })
    return {
        "packets_total": total, "packets_non_ipv4": non_ipv4, "packets_not_tv": not_tv,
        "first": t_first, "last": t_last, "tv_ips": sorted(tv_ips),
        "flows": flow_list, "dns": dns_rows, "tls": tls_rows, "http": http_rows,
        "rtt_ms": {k: round(v, 1) for k, v in rtt.items()},
        "names": {ip: n for ip, n in names.items()},
    }


# ---------------------------------------------------------------- names and lookups

def load_all_parsed():
    runs = {}
    for p in sorted(OUT.glob("*/parsed.json")):
        try:
            runs[p.parent.name] = json.loads(p.read_text())
        except json.JSONDecodeError:
            pass
    return runs


def global_names(runs):
    """ip -> {name: (source, run)} across every processed capture."""
    g = defaultdict(dict)
    for run, d in runs.items():
        for ip, ns in d["names"].items():
            for n, src in ns.items():
                g[ip].setdefault(n, (src, run))
    return g


def names_for(ip, run, runs, gnames):
    """Return (names, source). Names seen in this run win; otherwise borrow from other runs."""
    local = runs[run]["names"].get(ip, {})
    if local:
        order = {"sni": 0, "dns": 1, "cert": 2}
        ns = sorted(local, key=lambda n: (order.get(local[n], 9), n))
        return ns, "/".join(sorted(set(local.values())))
    other = gnames.get(ip, {})
    if other:
        return sorted(other), "inferred from " + ", ".join(sorted({r for _, r in other.values()}))
    return [], ""


def aws_region(rdns):
    m = re.search(r"\.([a-z]{2}-[a-z]+-\d)\.compute\.amazonaws\.com", rdns)
    if m:
        return m.group(1)
    if "compute-1.amazonaws.com" in rdns:
        return "us-east-1"
    if "googleusercontent.com" in rdns:
        return "google-cloud"
    return ""


def lookup_ips(ips, enabled):
    cache_p = OUT / "_ipinfo.json"
    cache = json.loads(cache_p.read_text()) if cache_p.exists() else {}
    todo = [ip for ip in ips if ip not in cache and scope_of(ip) == "internet"]
    if enabled and todo:
        print(f"  looking up {len(todo)} new server IPs (whois.cymru.com, reverse DNS)", file=sys.stderr)
        for ip in todo:
            info = {"asn": "", "as_name": "", "country": "", "rdns": "", "region": ""}
            try:
                w = subprocess.run(["whois", "-h", "whois.cymru.com", f" -v {ip}"],
                                   capture_output=True, text=True, timeout=15).stdout.strip().splitlines()
                parts = [x.strip() for x in w[-1].split("|")] if w else []
                if len(parts) >= 7:
                    info.update(asn=parts[0], country=parts[3], as_name=parts[6])
                r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "-x", ip],
                                   capture_output=True, text=True, timeout=10).stdout.split()
                info["rdns"] = r[0].rstrip(".") if r else ""
                info["region"] = aws_region(info["rdns"])
            except (subprocess.TimeoutExpired, OSError):
                pass
            cache[ip] = info
        cache_p.write_text(json.dumps(cache, indent=1, sort_keys=True))
    return cache


def load_blocklist():
    if not BLOCKLIST.exists():
        return set()
    return {l.strip().lower() for l in BLOCKLIST.read_text().splitlines() if l.strip() and not l.startswith("#")}


def acr_labels(names, flow, blocklist):
    labels = []
    for n in names:
        for pat, label in ACR_PATTERNS:
            if re.search(pat, n, re.I):
                labels.append(("known domain", label, n))
        if blocklist and any(n == b or n.endswith("." + b) for b in blocklist):
            labels.append(("Watching-the-Watchers blocklist", "blocklisted ACR domain", n))
    for proto, port, label in PORT_SIGNATURES:
        if flow["proto"] == proto and flow["service_port"] == port and flow["scope"] == "internet":
            labels.append(("port signature", label, ""))
    # One row per indicator, even when several of the server's names match it.
    seen, unique = set(), []
    for kind, label, matched in labels:
        if (kind, label) not in seen:
            seen.add((kind, label))
            unique.append((kind, label, matched))
    return unique


# ---------------------------------------------------------------- writing

def write_csv(path, header, rows):
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def write_outputs(run, runs, gnames, ipinfo, blocklist):
    d = runs[run]
    meta = d["meta"]
    out = OUT / run
    # mDNS (.local) is LAN discovery chatter and carries the TV's device UUID, so leave it out.
    dns_rows = [r for r in d["dns"] if not r[4].split("|")[0].endswith(".local")]
    write_csv(out / "dns.csv", ["time", "type", "src", "dst", "query_name", "answers_a", "cname"], dns_rows)
    write_csv(out / "tls.csv", ["time", "server_ip", "server_port", "sni", "ja4"], d["tls"])
    write_csv(out / "http.csv", ["time", "src", "dst", "port", "method", "host", "uri", "user_agent"], d["http"])

    flow_rows, flag_rows = [], []
    per_server = defaultdict(lambda: {"flows": 0, "pkts_up": 0, "bytes_up": 0, "bytes_down": 0, "first": None})
    for fl in sorted(d["flows"], key=lambda f: f["first"]):
        ns, nsrc = names_for(fl["remote_ip"], run, runs, gnames)
        info = ipinfo.get(fl["remote_ip"], {})
        flow_rows.append([fl["proto"], fl["direction"], fl["scope"], fl["remote_ip"], " ".join(ns), nsrc,
                          info.get("as_name", ""), fl["service_port"], fl["remote_port"], fl["tv_port"],
                          iso(fl["first"]), fl["duration_s"], fl["pkts_up"], fl["pkts_down"],
                          fl["bytes_up"], fl["bytes_down"], fl["up_pkts_per_min"], fl["up_median_gap_s"],
                          fl["up_gap_cv"], fl["up_top_sizes"], fl["initiator"]])
        if fl["scope"] == "internet":
            s = per_server[fl["remote_ip"]]
            s["flows"] += 1
            s["pkts_up"] += fl["pkts_up"]
            s["bytes_up"] += fl["bytes_up"]
            s["bytes_down"] += fl["bytes_down"]
            s["first"] = s["first"] or fl["first"]
            base = [fl["remote_ip"], " ".join(ns), fl["proto"], fl["service_port"], fl["pkts_up"],
                    fl["bytes_up"], fl["up_median_gap_s"], fl["up_gap_cv"], iso(fl["first"])]
            for kind, label, matched in acr_labels(ns, fl, blocklist):
                flag_rows.append([kind, label, matched] + base)
            cv = fl["up_gap_cv"]
            if (fl["direction"] == "outbound" and fl["pkts_up"] >= PERIODIC_MIN_PKTS
                    and fl["duration_s"] >= PERIODIC_MIN_SECONDS and cv is not None and cv <= PERIODIC_MAX_CV):
                flag_rows.append(["periodic candidate",
                                  f"regular uploads every {fl['up_median_gap_s']}s", ""] + base)
    write_csv(out / "flows.csv",
              ["proto", "direction", "scope", "remote_ip", "remote_names", "name_source", "owner",
               "service_port", "remote_port", "tv_port", "first_seen", "duration_s", "pkts_up", "pkts_down",
               "bytes_up_frame", "bytes_down_frame", "up_pkts_per_min", "up_median_gap_s", "up_gap_cv",
               "up_top_sizes_l4", "initiator"], flow_rows)
    write_csv(out / "acr_flags.csv",
              ["flag_type", "label", "matched_name", "remote_ip", "remote_names", "proto", "service_port",
               "pkts_up", "bytes_up_frame", "up_median_gap_s", "up_gap_cv", "first_seen"], flag_rows)

    server_rows = []
    for ip, s in sorted(per_server.items(), key=lambda kv: -kv[1]["bytes_up"]):
        ns, nsrc = names_for(ip, run, runs, gnames)
        info = ipinfo.get(ip, {})
        server_rows.append([ip, " ".join(ns), nsrc, info.get("asn", ""), info.get("as_name", ""),
                            info.get("country", ""), info.get("region", ""), info.get("rdns", ""),
                            d["rtt_ms"].get(ip, ""), s["flows"], s["pkts_up"], s["bytes_up"], s["bytes_down"],
                            iso(s["first"])])
    write_csv(out / "servers.csv",
              ["ip", "names", "name_source", "asn", "owner", "country", "region", "rdns", "rtt_ms",
               "flows", "pkts_up", "bytes_up_frame", "bytes_down_frame", "first_seen"], server_rows)

    write_summary(out / "summary.md", run, d, flow_rows, flag_rows, server_rows)


def kb(n):
    return f"{n / 1000:,.1f} KB" if n < 1_000_000 else f"{n / 1_000_000:,.1f} MB"


def write_summary(path, run, d, flow_rows, flag_rows, server_rows):
    m = d["meta"]
    L = [f"# {m.get('label') or run}", "",
         f"- Capture file: `{m['pcap']}`",
         f"- TV IP: {', '.join(d['tv_ips'])}",
         f"- Time: {iso(d['first'])} to {iso(d['last'])} ({(d['last'] - d['first']):.0f} s)",
         f"- Packets: {d['packets_total']:,} total, {d['packets_non_ipv4']:,} non-IPv4 (ARP, IPv6), "
         f"{d['packets_not_tv']:,} not to or from the TV",
         f"- Notes file: {', '.join(f'{k}={v}' for k, v in m['notes'].items() if k in ('label', 'start', 'end')) or 'none'}",
         "", "## ACR and telemetry indicators", ""]
    if flag_rows:
        L += ["| Indicator | Server | Names | Proto/port | Packets up | Bytes up | Median gap (s) |",
              "|---|---|---|---|---|---|---|"]
        for r in flag_rows:
            L.append(f"| {r[0]}: {r[1]} | {r[3]} | {r[4] or '(no name)'} | {r[5]}/{r[6]} | {r[7]} | "
                     f"{kb(r[8])} | {r[9] if r[9] is not None else ''} |")
        L += ["", "Indicators are leads. Periodic candidates include ordinary keepalives; "
                  "compare against an idle or opted-out run before calling anything ACR."]
    else:
        L.append("None found.")
    L += ["", "## Internet servers (by bytes sent from the TV)", "",
          "| IP | Names | Name source | Owner | Country | Region | RTT (ms) | Flows | Pkts up | Bytes up | Bytes down |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in server_rows:
        L.append(f"| {r[0]} | {r[1] or '(no name)'} | {r[2]} | {r[4]} | {r[5]} | {r[6]} | {r[8]} | "
                 f"{r[9]} | {r[10]} | {kb(r[11])} | {kb(r[12])} |")
    lan = [r for r in flow_rows if r[2] != "internet"]
    if lan:
        peers = Counter((r[3], r[0], r[7], r[1]) for r in lan)
        L += ["", "## LAN and multicast peers", "", "| Peer | Proto | Service port | Direction | Flows |",
              "|---|---|---|---|---|"]
        for (ip, proto, port, direction), n in sorted(peers.items()):
            L.append(f"| {ip} | {proto} | {port} | {direction} | {n} |")
    if d["http"]:
        uniq = Counter((r[5], r[6], r[7]) for r in d["http"])
        L += ["", "## Plaintext HTTP requests", "", "| Count | Host | Path | User-Agent |", "|---|---|---|---|"]
        for (host, uri, ua), n in uniq.most_common():
            L.append(f"| {n} | {host} | {uri} | `{ua}` |")
    L += ["", "## Files", "",
          "- `flows.csv`: every conversation with the TV, with timing and size statistics",
          "- `servers.csv`: one row per internet server, with names, owner, country, region and round-trip time",
          "- `acr_flags.csv`: indicator matches", "- `dns.csv`, `tls.csv`, `http.csv`: raw name evidence",
          "", "Byte totals are frame bytes. Packet sizes (`up_top_sizes_l4`) are udp.length or tcp.len. "
              "Names marked 'inferred from' came from another capture, because this one missed the lookup."]
    path.write_text("\n".join(L) + "\n")


# ---------------------------------------------------------------- commands

def cmd_process(args):
    OUT.mkdir(exist_ok=True)
    for pcap in map(Path, args.pcaps):
        pcap = pcap.resolve()
        run = pcap.stem
        out = OUT / run
        out.mkdir(exist_ok=True)
        cache = out / "parsed.json"
        stamp = [pcap.stat().st_size, int(pcap.stat().st_mtime), PARSE_VERSION]
        if cache.exists() and not args.force and json.loads(cache.read_text())["meta"].get("stamp") == stamp:
            print(f"{run}: already parsed", file=sys.stderr)
            continue
        notes = read_notes(pcap)
        tv_ip = args.tv_ip or notes.get("tv_ip")
        tv_mac = (args.tv_mac or notes.get("tv_mac") or "").lower()
        if not tv_ip and not tv_mac:
            sys.exit(f"{pcap.name}: no notes file; pass --tv-ip (and ideally --tv-mac)")
        print(f"{run}: parsing", file=sys.stderr)
        d = parse_pcap(pcap, [tv_ip] if tv_ip else [], tv_mac)
        d["meta"] = {"pcap": str(pcap.relative_to(ROOT)) if pcap.is_relative_to(ROOT) else str(pcap),
                     "label": notes.get("label", ""), "notes": notes, "stamp": stamp}
        cache.write_text(json.dumps(d))

    # Rewrite every run's outputs so names learned from new captures fill gaps in older ones.
    runs = load_all_parsed()
    gnames = global_names(runs)
    ips = {f["remote_ip"] for d in runs.values() for f in d["flows"]}
    ipinfo = lookup_ips(sorted(ips), not args.no_lookup)
    blocklist = load_blocklist()
    for run in runs:
        write_outputs(run, runs, gnames, ipinfo, blocklist)
        print(f"{run}: wrote {OUT / run / 'summary.md'}", file=sys.stderr)


def resolve_run(s, runs):
    p = Path(s)
    if p.name in runs:
        return p.name
    if p.stem in runs:
        return p.stem
    hits = [r for r, d in runs.items() if s == d["meta"].get("label")] or [r for r in runs if s in r]
    if len(hits) != 1:
        sys.exit(f"'{s}' matches {len(hits)} processed runs: {hits}")
    return hits[0]


def cmd_compare(args):
    runs = load_all_parsed()
    a, b = resolve_run(args.a, runs), resolve_run(args.b, runs)
    gnames = global_names(runs)
    ipinfo = json.loads((OUT / "_ipinfo.json").read_text()) if (OUT / "_ipinfo.json").exists() else {}
    blocklist = load_blocklist()

    def groups(run):
        """Group flows by server name (or ip:port when unnamed), protocol and service port,
        because servers behind one name rotate IPs between runs."""
        g = defaultdict(lambda: {"flows": 0, "pkts_up": 0, "bytes_up": 0, "bytes_down": 0, "flags": set()})
        for fl in runs[run]["flows"]:
            if fl["scope"] != "internet":
                continue
            ns, _ = names_for(fl["remote_ip"], run, runs, gnames)
            who = ns[0] if ns else (ipinfo.get(fl["remote_ip"], {}).get("as_name", "") + " " + fl["remote_ip"]).strip()
            k = (who, fl["proto"], fl["service_port"])
            x = g[k]
            x["flows"] += 1
            x["pkts_up"] += fl["pkts_up"]
            x["bytes_up"] += fl["bytes_up"]
            x["bytes_down"] += fl["bytes_down"]
            x["flags"].update(label for _, label, _ in acr_labels(ns, fl, blocklist))
        return g

    ga, gb = groups(a), groups(b)
    la, lb = runs[a]["meta"].get("label") or a, runs[b]["meta"].get("label") or b
    rows = []
    for k in set(ga) | set(gb):
        x, y = ga.get(k), gb.get(k)
        status = "both" if x and y else ("only A" if x else "only B")
        flags = sorted((x["flags"] if x else set()) | (y["flags"] if y else set()))
        rows.append((0 if flags else 1, {"only A": 0, "only B": 1, "both": 2}[status], k, status, x, y, flags))
    rows.sort(key=lambda r: (r[0], r[1], r[2]))
    cell = lambda x, f: (kb(x[f]) if f.startswith("bytes") else str(x[f])) if x else "-"
    L = [f"# Compare: A = {la}, B = {lb}", "",
         f"- A: {iso(runs[a]['first'])}, {runs[a]['last'] - runs[a]['first']:.0f} s",
         f"- B: {iso(runs[b]['first'])}, {runs[b]['last'] - runs[b]['first']:.0f} s", "",
         "Internet traffic grouped by server name, protocol and service port. Rows with ACR or telemetry "
         "indicators come first.", "",
         "| Server | Proto/port | In | Indicators | Flows A | Flows B | Pkts up A | Pkts up B | Bytes up A | Bytes up B |",
         "|---|---|---|---|---|---|---|---|---|---|"]
    for _, _, (who, proto, port), status, x, y, flags in rows:
        L.append(f"| {who} | {proto}/{port} | {status} | {'; '.join(flags)} | {cell(x, 'flows')} | "
                 f"{cell(y, 'flows')} | {cell(x, 'pkts_up')} | {cell(y, 'pkts_up')} | "
                 f"{cell(x, 'bytes_up')} | {cell(y, 'bytes_up')} |")
    dest = OUT / "compare"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{la}__vs__{lb}.md"
    path.write_text("\n".join(L) + "\n")
    print("\n".join(L))
    print(f"\nwrote {path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("process", help="parse pcaps into processed/<stem>/")
    p.add_argument("pcaps", nargs="+")
    p.add_argument("--tv-ip", help="TV IP, needed when there is no tv-record notes file")
    p.add_argument("--tv-mac", help="TV MAC, also counts any IP this MAC uses")
    p.add_argument("--no-lookup", action="store_true", help="skip owner/country/reverse-DNS lookups")
    p.add_argument("--force", action="store_true", help="re-parse even if the cached parse is current")
    p.set_defaults(func=cmd_process)
    c = sub.add_parser("compare", help="compare two processed runs (folder, pcap stem, or label)")
    c.add_argument("a")
    c.add_argument("b")
    c.set_defaults(func=cmd_compare)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
