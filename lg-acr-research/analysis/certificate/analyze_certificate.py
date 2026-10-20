"""Reproduce certificate acceptance checks from the preserved local evidence."""
from pathlib import Path
import base64
import collections
import csv
import datetime as dt
import hashlib
import json
import math
import struct
import subprocess
import sys
import os

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = Path(os.environ['ACR_PRIVATE_DIR'])
ARCHIVE = Path(os.environ['ACR_CERT_ARCHIVE'])
OUT = Path(os.environ['ACR_OUTPUT_DIR']) / 'certificate-summary.json'
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from inspect_flows import parse, text, content


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def der_hash(path):
    return hashlib.sha256(subprocess.check_output(
        ['openssl', 'x509', '-in', str(path), '-outform', 'DER'])).hexdigest()


def main():
    assert sha(ARCHIVE) == '354f4b4396bc4d78d6a32b7a4e2261a2cfcac72aa0042f1ead476964ec6baeee'
    phases = list(csv.DictReader((PRIVATE / 'phases.tsv').open(), delimiter='\t'))
    start = float(next(r['epoch_utc'] for r in phases if r['event'] == 'measure_start'))
    end = float(next(r['epoch_utc'] for r in phases if r['event'] == 'measure_end'))
    settle = float(next(r['epoch_utc'] for r in phases if r['event'] == 'settle_start'))
    config = json.loads((PRIVATE / 'expected-peer.json').read_text())
    controls = json.loads((PRIVATE / 'certificate-controls.json').read_text())
    events = [json.loads(line) for line in (PRIVATE / 'tls-events.jsonl').read_text().splitlines()]
    tls = {r['connection_ordinal']: r for r in events if r['event'] == 'client_tls_established'}
    request_events = [r for r in events if r['event'] == 'fingerprint_request']
    requests = {r['request_epoch']: r for r in request_events}
    assert len(requests) == len(request_events)
    leaf = PRIVATE / 'test-leaf-cert.pem'
    ca = PRIVATE / 'test-root-ca.pem'
    expected = der_hash(leaf)
    assert expected == controls['leaf_der_sha256']
    presented = list(PRIVATE.glob('presented-leaf-*.pem'))
    for path in presented:
        assert b'PRIVATE KEY' not in path.read_bytes() and der_hash(path) == expected
    for r in tls.values():
        assert r['matches_configured_test_leaf'] and r['presented_leaf_der_sha256'] == expected
        assert r['sni_category'] == 'expected_dns'
    verification = {}
    for label, options, wanted in [
            ('default_trust', [], False), ('explicit_test_ca_dns', ['-CAfile', str(ca)], True)]:
        command = ['openssl', 'verify', '-attime', str(int(start)), '-purpose', 'sslserver',
                   '-verify_hostname', config['server_name'], *options,
                   '-untrusted', str(ca), str(leaf)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert (result.returncode == 0) == wanted
        log = PRIVATE / ('independent-verify-' + label + '.txt')
        log.write_bytes(result.stdout + result.stderr); log.chmod(0o600)
        verification[label + '_accepted'] = result.returncode == 0
    data = (PRIVATE / 'flows.mitm').read_bytes()
    flows, pos = [], 0
    while pos < len(data):
        f, pos = parse(data, pos)
        flows.append(f)
    whole, measured, records = collections.Counter(), collections.Counter(), collections.Counter()
    measured_connections = set()
    for f in flows:
        q = f.get('request') or {}
        if text(q.get('path', '')).split('?', 1)[0] != '/v5/audio/fingerprint':
            continue
        event = requests[q['timestamp_start']]
        connection = tls[event['connection_ordinal']]
        assert connection['epoch'] <= event['epoch']
        assert f['client_conn']['sni'] == config['server_name']
        assert f['server_conn']['peername'][0] == config['server_ip']
        assert f['server_conn']['peername'][1] == 4437
        status = (f.get('response') or {}).get('status_code')
        whole[str(status)] += 1
        body, headers = content(q)
        assert len(body) == int(headers['content-length'])
        legacy_count, vector_count = 0, 0
        try:
            j = json.loads(body)
            legacy = base64.b64decode(j['payload'], validate=True)
            assert len(legacy) == j['length'] and len(legacy) > 0 and len(legacy) % 76 == 0
            legacy_count = len(legacy) // 76
            indices = {struct.unpack_from('<I', legacy, n)[0] for n in range(0, len(legacy), 76)}
            if 'v3_frames_payload' in j:
                a = base64.b64decode(j['v3_frames_payload'], validate=True)
                b = base64.b64decode(j['v3_fps_payload'], validate=True)
                assert len(a) == j['v3_frames_length'] and len(a) % 4 == 0
                assert len(b) == j['v3_fps_length'] == len(a) // 4 * 126
                assert set(struct.unpack('<' + 'I' * (len(a) // 4), a)) <= indices
                assert all(math.isfinite(v) for v in struct.unpack('<' + 'e' * (len(b) // 2), b))
                vector_count = len(a) // 4
            valid = True
        except json.JSONDecodeError as error:
            assert error.pos == len(body) == 227 and body.endswith(b',') and status == 400
            valid = False
        assert valid == event['nonempty_legacy_layout_valid']
        if start <= q['timestamp_start'] < end:
            measured[str(status)] += 1
            measured['valid_payloads'] += valid
            measured_connections.add(event['connection_ordinal'])
            if valid:
                records['legacy_records'] += legacy_count
                records['v3_vectors'] += vector_count
    capture = (PRIVATE / 'capture.log').read_text()
    import re
    captured = int(re.search(r'(\d+) packets captured', capture).group(1))
    drops = int(re.search(r'(\d+) packets dropped by kernel', capture).group(1))
    packet_output = subprocess.run(['tshark', '-n', '-r', str(PRIVATE / 'network-headers.pcap'),
                                    '-T', 'fields', '-e', 'frame.number'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    assert len(packet_output.stdout.splitlines()) == captured
    summary = {
        'archive': 'certificate.tgz', 'archive_bytes': ARCHIVE.stat().st_size, 'archive_sha256': sha(ARCHIVE),
        'flows_sha256': sha(PRIVATE / 'flows.mitm'), 'packets_sha256': sha(PRIVATE / 'network-headers.pcap'),
        'measurement_start_utc': dt.datetime.fromtimestamp(start, dt.timezone.utc).isoformat(),
        'measurement_end_utc': dt.datetime.fromtimestamp(end, dt.timezone.utc).isoformat(),
        'measurement_seconds': end - start, 'settling_seconds': start - settle,
        'measured_post_attempts': sum(v for k, v in measured.items() if k != 'valid_payloads'),
        'measured_http_statuses': {k: v for k, v in measured.items() if k != 'valid_payloads'},
        'measured_valid_fingerprint_messages': measured['valid_payloads'],
        'measured_client_connections': len(measured_connections), **dict(records),
        'whole_recording_fingerprint_http_statuses': dict(whole),
        'whole_recording_completed_client_tls_connections': len(tls),
        'matching_recorded_public_leaf_files': len(presented),
        'client_tls_failure_events': sum(r['event'] == 'client_tls_failed' for r in events),
        'upstream_tls_failure_events': sum(r['event'] == 'upstream_tls_failed' for r in events),
        'leaf_der_sha256': expected, 'router_certificate_controls': controls,
        'independent_verification_at_measurement_time': verification,
        'captured_packets': captured, 'kernel_packet_drops': drops,
        'limits': ['One rooted TV/path, not stock-firmware or all-app behavior.',
                   'No independent TV trust-store or complete rooting-history audit.',
                   'No separate wrong-hostname or expiration test.',
                   'Local selected certificate recorded per completed connection; TLS resumption not separately instrumented.',
                   'HTTP202 is acceptance for processing, not content recognition.']}
    OUT.write_text(json.dumps(summary, indent=2) + '\n')
    print('Measured:', summary['measured_post_attempts'], 'attempts;', measured['valid_payloads'],
          'valid fingerprint messages;', measured['202'], 'HTTP202; connections:', len(measured_connections))
    print('Independent certificate, payload, connection and packet checks passed.')


if __name__ == '__main__':
    main()
