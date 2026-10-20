# Vizio SmartCast ACR Findings

Smart TV ACR Hackathon, Northeastern University, October 19-20 2026.

Device: Vizio SmartCast (`s-viziotv-2`), model `D32fM-K01`, firmware `3.720.9.1-1`, TV IP `192.168.103.133`. Captured 2026-10-19 on the Mac Internet-Sharing bridge, the TV's only path to the internet. 14 runs, about 10 minutes each. Per-run metadata is in `runs-metadata.md`.

## ACR signals

| Signal | What it is | How detected |
|---|---|---|
| `:5558` stream | UDP to an Amazon us-east-1 IP, port 5558. One packet every 0.75 s, 800 in 10 min, ~440 bytes each. No TLS. Likely the fingerprint upload. | `tshark -Y 'udp.port==5558'`; rate from inter-packet timing |
| Inscape control | TLS to `*.tvinteractive.tv` (`control2`, `control-zoo-*`, `tvevents`). Vizio's Inscape control plane. Checks in a few minutes into playback. | TLS SNI filter `tls.handshake.extensions_server_name contains "tvinteractive"` |
| Kinesis | TLS to `kinesis.us-west-2.amazonaws.com`. Vizio analytics. Present in nearly every run. | TLS SNI filter on `kinesis.us-west-2.amazonaws.com` |

## Findings

### 1. The `:5558` stream only runs in WatchFree+

| Scenario | `:5558` |
|---|---|
| Idle, ACR on | absent |
| WatchFree+ Fox News | present, 800 pkt |
| WatchFree+ CNN | present, 800 pkt |
| HDMI Fox News | absent |
| YouTube Fox News | absent |
| Sesame Street kids app | absent |

The stream fired only in Vizio's own WatchFree+ app, never on HDMI, YouTube, or the kids app. YouTube matches the prior "Watching the Watchers" paper, which found YouTube was never tracked.

Method: one 10-minute capture per scenario, each filtered with `tshark -Y 'udp.port==5558'`. Present means 800 packets at the 0.75 s cadence; absent means zero.

### 1a. The `:5558` collector changed IP right after an Inscape exchange

We caught the fingerprint stream switch from one collector IP to another, once, in the continuous bridge capture. Times are relative to a slice starting 2026-10-19 16:43:00 EDT.

| Event | Rel. time | Wall clock |
|---|---|---|
| `:5558` to `44.211.61.115`, last packet | 70.78 s | 16:44:10.8 |
| TLS to Inscape `control2` + `control-zoo-dtsprod` | 68.1-71.1 s | 16:44:08-16:44:11 |
| `:5558` to `3.95.164.21`, first packet | 72.02 s | 16:44:12.1 |

Observed: the stream to the first collector stops, the TV runs a short TLS exchange with the Inscape control servers (about 39 KB with `control-zoo-dtsprod`, 6 KB with `control2`), and 1.3 s later the stream resumes to a different collector IP. Neither collector IP was ever requested in DNS.

Our assumption, not confirmed: Inscape handed the TV the new collector address. We cannot verify it. The Inscape exchange is TLS-encrypted, so we cannot read what was sent. All we can say for certain is that the new IP did not come from DNS, and the only traffic in the gap was the Inscape exchange.

Owner: not nameable from packets. Reverse DNS is the generic AWS default (`ec2-3-95-164-21.compute-1.amazonaws.com`), the stream is plaintext UDP with no cert or SNI, and the IP is never looked up. The collector sits on AWS us-east-1.

Method: sliced the change-over window from the continuous bridge capture with `editcap -A/-B`, then correlated `:5558` start/stop (`tshark -z conv,udp`) against Inscape SNI timing. Confirmed no DNS answer resolves to either collector IP (`tshark -Y 'dns.flags.response==1'`).

### 2. HDMI was not fingerprinted

With Viewing Data on and real HDMI content (with sound) playing, no `:5558` stream and no Inscape uploads over 10 minutes. This contradicts Vizio's consent text, which says ACR covers "devices connected to" the TV.

Method: 10-minute HDMI capture, checked for `udp.port==5558` and for `tvinteractive` SNI. Both zero.

### 3. Do Not Sell removed Inscape but kept Kinesis

Two Sesame Street runs, identical except the CCPA "Do Not Sell My Personal Information" toggle:

| Signal | DNS off | DNS on |
|---|---|---|
| `:5558` | absent | absent |
| Inscape | present, 2 check-ins, ~5 KB up | gone, 0 flows |
| Kinesis | 5 flows, 85.2 KB up | 5 flows, 86.5 KB up |

Opt-out dropped the Inscape control plane but left Kinesis analytics at full volume. Consistent with Vizio's opt-out being incomplete.

Method: two back-to-back kids-app captures, one toggle changed. Compared Inscape and Kinesis flow counts and upload bytes side by side (`tshark -z conv,tcp`).

### 4. WatchFree+ leaks the program name in plaintext

With ACR off, WatchFree+ content comes from Amagi (`*.amagi.tv`) and the program is readable in the plaintext hostname via DNS and TLS SNI, for example `vizioaaaa-foxnewsnow-vizio-*.amagi.tv` and `amg01918-cnnus-*.playouts.now.amagi.tv`. The channel (Fox News, CNN) is visible without decryption. Reproduces the prior paper's Amagi finding.

Method: extracted DNS query names and TLS SNI (`tshark -e dns.qry.name -e tls.handshake.extensions_server_name`) and grepped for `amagi.tv`.
