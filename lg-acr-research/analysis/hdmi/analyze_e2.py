"""Offline HDMI E2 analysis. Never emit payloads, identities or location values."""
from pathlib import Path
import base64
import collections
import csv
import datetime as dt
import hashlib
import json
import math
import re
import statistics
import struct
import subprocess
import sys
import tarfile
import os

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(os.environ['ACR_PRIVATE_DIR'])
OUT = Path(os.environ['ACR_OUTPUT_DIR'])
ARCHIVE = Path(os.environ['ACR_HDMI_ARCHIVE'])
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from inspect_flows import parse, text, content


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec='milliseconds')


def stats(values):
    return {'n': len(values), 'min': min(values), 'median': statistics.median(values),
            'max': max(values)} if values else None


def decode(flow):
    body, headers = content(flow['request'])
    declared = headers.get('content-length')
    if declared is not None and int(declared) != len(body):
        raise ValueError('Content-Length mismatch')
    result = {'body_bytes': len(body), 'json_valid': True, 'legacy_records': 0,
              'v3_frames': 0, 'client_end_epoch': None}
    try:
        j = json.loads(body)
    except json.JSONDecodeError as error:
        # Retain the actual message as invalid. Parsing a repaired prefix is
        # diagnostic only, never represented as valid sent JSON or a fingerprint.
        assert error.pos == len(body) and body.endswith(b',')
        prefix = json.loads(body + b'"_LOCAL_DIAGNOSTIC_ONLY":true}')
        assert prefix.get('type') == 'end' and 'payload' not in prefix
        assert 'v3_fps_payload' not in prefix
        result.update(json_valid=False, malformed_kind='trailing-comma end, no fingerprint fields',
                      declared_content_length=int(declared), error_offset=error.pos,
                      message_type='end')
        return result, [], []
    assert isinstance(j, dict)
    legacy = base64.b64decode(j['payload'], validate=True)
    assert len(legacy) == j['length'] and len(legacy) % 76 == 0
    indices = [struct.unpack_from('<I', legacy, p)[0] for p in range(0, len(legacy), 76)]
    signatures = [legacy[p + 4:p + 76] for p in range(0, len(legacy), 76)]
    features = []
    if 'v3_frames_payload' in j:
        frames_raw = base64.b64decode(j['v3_frames_payload'], validate=True)
        values_raw = base64.b64decode(j['v3_fps_payload'], validate=True)
        assert len(frames_raw) == j['v3_frames_length'] and len(frames_raw) % 4 == 0
        assert len(values_raw) == j['v3_fps_length'] == len(frames_raw) // 4 * 126
        frames = struct.unpack('<' + 'I' * (len(frames_raw) // 4), frames_raw)
        values = struct.unpack('<' + 'e' * (len(values_raw) // 2), values_raw)
        assert all(math.isfinite(v) for v in values) and set(frames) <= set(indices)
        features = [values[p:p + 63] for p in range(0, len(values), 63)]
    end = j.get('ts_end')
    if isinstance(end, (int, float)) and 1e12 < end < 1e13:
        result['client_end_epoch'] = end / 1000
    result.update(legacy_records=len(signatures), v3_frames=len(features),
                  record_failure=j.get('record_failure'), message_type=j.get('type'),
                  input_is_hdmi=str(j.get('device_input', '')).upper().startswith('HDMI'))
    return result, signatures, features


def main():
    assert sha(ARCHIVE) == 'd73d8182a7831d9001dd48bf5f5cfe9b0f2c4cfa09f02cac036659e70633949b'
    PRIVATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    PRIVATE.chmod(0o700)
    allowed = {'flows.mitm', 'phases.tsv', 'network-headers.pcap', 'capture.log',
               'proxy.log', 'fingerprint-events.tsv', 'trial.txt', 'launcher.sh', 'e2-counter.py'}
    seen = set()
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        for member in archive:
            if member.name not in allowed:
                continue
            assert member.name not in seen and member.isfile() and 0 <= member.size <= 512 * 1024 * 1024
            seen.add(member.name)
            with archive.extractfile(member) as source, (PRIVATE / member.name).open('wb') as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
            (PRIVATE / member.name).chmod(0o600)
    assert seen == allowed
    OUT.mkdir(parents=True, exist_ok=True)
    phase_rows = list(csv.DictReader((PRIVATE / 'phases.tsv').open(), delimiter='\t'))
    playback_path = Path(os.environ['ACR_PLAYBACK_LOG'])
    playback = [json.loads(line) for line in playback_path.read_text().splitlines()]
    assert not any(r['event'] == 'playback_interrupted' for r in playback)
    assert [r['clip'] for r in playback] == ['av.mp4', 'v_only.mp4', 'a_only.mp4', 'av.mp4']
    switches = [dt.datetime.fromisoformat(r['utc']).timestamp() for r in playback]
    windows = []
    for index, phase in enumerate(['av1', 'v_only', 'a_only', 'av2']):
        entries = [r for r in phase_rows if r['phase'] == phase]
        def when(event):
            selected = [r for r in entries if r['event'] == event]
            assert len(selected) == 1
            return float(selected[0]['epoch_utc'])
        confirmed = when('setting_confirmed')
        start, end = when('measure_start'), when('measure_end')
        assert switches[index] <= confirmed < start < end
        if index < 3:
            assert end < switches[index + 1]
        windows.append({'phase': phase, 'start_epoch': start, 'end_epoch': end,
                        'start_utc': iso(start), 'end_utc': iso(end),
                        'duration_seconds': end - start,
                        'owner_confirmed_epoch': confirmed,
                        'local_clip_command_epoch': switches[index],
                        'settle_seconds': start - when('settle_start')})
    data = (PRIVATE / 'flows.mitm').read_bytes()
    flows, pos = [], 0
    while pos < len(data):
        flow, pos = parse(data, pos)
        flows.append(flow)
    assert pos == len(data)
    uploads = []
    for f in flows:
        req = f.get('request') or {}
        if text(req.get('path', '')).split('?', 1)[0] != '/v5/audio/fingerprint':
            continue
        assert text(req['method']) == 'POST'
        metrics, signatures, features = decode(f)
        uploads.append((f, metrics, signatures, features))
    signatures_by_phase, features_by_phase, request_rows = {}, {}, []
    for w in windows:
        selected = [u for u in uploads if w['start_epoch'] <= u[0]['request']['timestamp_start'] < w['end_epoch']]
        valid = [u for u in selected if u[1]['json_valid']]
        ages = [u[0]['request']['timestamp_start'] - u[1]['client_end_epoch']
                for u in valid if u[1]['client_end_epoch'] is not None]
        signatures = [s for u in valid for s in u[2]]
        features = [v for u in valid for v in u[3]]
        signatures_by_phase[w['phase']] = signatures
        features_by_phase[w['phase']] = features
        statuses = collections.Counter(str((u[0].get('response') or {}).get('status_code')) for u in selected)
        w.update(fingerprint_posts=len(selected), valid_json_fingerprint_posts=len(valid),
                 malformed_end_posts=len(selected) - len(valid), http_statuses=dict(statuses),
                 fingerprint_posts_per_minute=len(selected) * 60 / w['duration_seconds'],
                 legacy_records=len(signatures), unique_legacy_signatures=len(set(signatures)),
                 v3_frames=len(features), unique_v3_vectors=len(set(features)),
                 record_failure_values=dict(collections.Counter(str(u[1].get('record_failure')) for u in valid)),
                 valid_uploads_reporting_hdmi=sum(u[1]['input_is_hdmi'] for u in valid),
                 request_minus_client_end_seconds=stats(ages),
                 valid_uploads_reporting_end_before_clip_command=sum(u[1]['client_end_epoch'] is not None
                     and u[1]['client_end_epoch'] < w['local_clip_command_epoch'] for u in valid))
        routes = collections.Counter()
        for f in flows:
            if w['start_epoch'] <= (f.get('request') or {}).get('timestamp_start', -1) < w['end_epoch']:
                path = text(f['request'].get('path', '')).split('?', 1)[0]
                assert path in ('/v5/audio/fingerprint', '/v5/user/lookups', '/v5/user/appsource')
                routes[path] += 1
        w['observed_route_counts'] = dict(routes)
        for f, metrics, _, _ in selected:
            request_rows.append({'phase': w['phase'], 'request_epoch': f['request']['timestamp_start'],
                                 'request_utc': iso(f['request']['timestamp_start']),
                                 'http_status': (f.get('response') or {}).get('status_code'), **metrics})
    # Cross-check addon events independently of the parsed mitm stream.
    events = list(csv.reader((PRIVATE / 'fingerprint-events.tsv').open(), delimiter='\t'))
    for w in windows:
        n = sum(r[1] == 'request' and w['start_epoch'] <= float(r[0]) < w['end_epoch'] for r in events)
        assert n == w['fingerprint_posts']
        w['addon_counter_agrees'] = True
    # Packet dissection: process only this TV's scoped file, use no DNS, retain
    # peer identities privately and publish only counts/volume.
    launcher = (PRIVATE / 'launcher.sh').read_text()
    tv_ip = re.search(r'^tv_ip=([0-9.]+)$', launcher, re.M).group(1)
    remote_ip = re.search(r'^remote_ip=([0-9.]+)$', launcher, re.M).group(1)
    packet_stats = {w['phase']: collections.Counter() for w in windows}
    fields = ['frame.time_epoch', 'frame.len', 'ip.src', 'ip.dst', 'tcp.srcport',
              'tcp.dstport', 'tcp.len']
    cmd = ['tshark', '-n', '-r', str(PRIVATE / 'network-headers.pcap'), '-T', 'fields', '-E', 'occurrence=f']
    for field in fields:
        cmd += ['-e', field]
    packet_count = 0
    with (PRIVATE / 'packet-dissection.log').open('w') as log:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=log, text=True)
        for line in process.stdout:
            row = line.rstrip('\n').split('\t')
            assert len(row) == len(fields)
            t, length, src, dst, sport, dport, tcp_len = row
            packet_count += 1
            for w in windows:
                if not w['start_epoch'] <= float(t) < w['end_epoch']:
                    continue
                c = packet_stats[w['phase']]
                c['all_packets'] += 1
                c['all_wire_bytes'] += int(length)
                if '4437' in (sport, dport):
                    c['all_tcp4437_packets'] += 1
                    c['tcp4437_wire_bytes'] += int(length)
                    c['tcp4437_reported_payload_bytes_including_retransmissions'] += int(tcp_len or 0)
                    if remote_ip in (src, dst):
                        c['selected_destination_tcp4437_packets'] += 1
                    if src == tv_ip:
                        c['outbound_tcp4437_packets'] += 1
                else:
                    c['other_packets'] += 1
                    c['other_wire_bytes'] += int(length)
        assert process.wait() == 0
    for w in windows:
        # Include explicit zeros for the independent null check.
        for key in ['all_packets', 'all_wire_bytes', 'all_tcp4437_packets',
                    'selected_destination_tcp4437_packets', 'tcp4437_wire_bytes',
                    'tcp4437_reported_payload_bytes_including_retransmissions',
                    'outbound_tcp4437_packets', 'other_packets', 'other_wire_bytes']:
            w[key] = packet_stats[w['phase']][key]
    capture_log = (PRIVATE / 'capture.log').read_text()
    drops = int(re.search(r'(\d+) packets dropped by kernel', capture_log).group(1))
    captured = int(re.search(r'(\d+) packets captured', capture_log).group(1))
    assert captured == packet_count
    # Compare frame signatures after removing their frame indices. Exact
    # equality supports shared features, not recognition or calibrated matching.
    overlaps = []
    for left, right in [('av1', 'a_only'), ('av1', 'av2'), ('a_only', 'av2')]:
        a, b = set(signatures_by_phase[left]), set(signatures_by_phase[right])
        va, vb = set(features_by_phase[left]), set(features_by_phase[right])
        overlaps.append({'left': left, 'right': right,
                         'exact_shared_72byte_signatures': len(a & b),
                         'exact_shared_63value_vectors': len(va & vb)})
    result = {'study': 'HDMI E2 audio/video isolation', 'archive': 'hdmi.tgz',
              'archive_sha256': sha(ARCHIVE), 'flows_sha256': sha(PRIVATE / 'flows.mitm'),
              'packets_sha256': sha(PRIVATE / 'network-headers.pcap'),
              'playback_log_sha256': sha(playback_path),
              'all_four_phases_complete': True, 'playback_command_log_consistent_with_windows': True,
              'playback_interruption_logged': False,
              'whole_capture_http_flows': len(flows), 'whole_capture_fingerprint_posts': len(uploads),
              'whole_capture_fingerprint_http_statuses': dict(collections.Counter(
                  str((u[0].get('response') or {}).get('status_code')) for u in uploads)),
              'whole_capture_malformed_end_posts': sum(not u[1]['json_valid'] for u in uploads),
              'captured_packets': captured, 'kernel_packet_drops': drops, 'windows': windows,
              'exact_frame_comparisons': overlaps,
              'limitations': [
                  'One rooted TV, one HDMI setup, one selected intercepted IPv4 destination.',
                  'Owner-observed playback/audio path; IPC acknowledgements do not prove every rendered frame.',
                  'Matching soundtrack can reach an electronic tap or a microphone hearing TV speakers.',
                  'Fixed phase order and short repeated source, not a randomized general source survey.',
                  'No measured silent-source uploads means no silent payload vectors to compare.',
                  'Client timestamp proximity does not independently establish audio capture time or exclude queues.',
                  'HTTP202 is acceptance, not a demonstrated content match.',
                  'Invalid end messages remain counted as POST attempts, not valid fingerprint payloads.',
                  'No inference that video processing, raw audio, voice logs or other telemetry are absent elsewhere.'
              ]}
    (OUT / 'e2-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    with (OUT / 'measured-requests.csv').open('w', newline='') as output:
        keys = sorted({k for r in request_rows for k in r})
        writer = csv.DictWriter(output, fieldnames=keys)
        writer.writeheader(); writer.writerows(request_rows)
    for w in windows:
        print(w['phase'], 'POSTs', w['fingerprint_posts'], 'HTTP', w['http_statuses'],
              'legacy records', w['legacy_records'], 'V3 vectors', w['v3_frames'],
              'TCP4437 packets', w['all_tcp4437_packets'], 'other packets', w['other_packets'])
    print('Packet drops:', drops, 'whole-recording packets:', captured)
    print('Exact frame comparisons:', overlaps)


if __name__ == '__main__':
    main()
