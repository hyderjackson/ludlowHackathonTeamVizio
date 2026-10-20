"""mitmproxy hook evidence: local presented certificate and sanitized counters."""
import base64
import hashlib
import json
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives import serialization

os.umask(0o077)
ROOT = Path(os.environ['ACR_EVENT_DIR'])
CONNECTIONS = {}


def number(conn):
    key = conn.id
    if key not in CONNECTIONS:
        CONNECTIONS[key] = len(CONNECTIONS) + 1
    return CONNECTIONS[key]


def emit(event, conn, **fields):
    row = {'epoch': time.time(), 'event': event, 'connection_ordinal': number(conn), **fields}
    with (ROOT / 'tls-events.jsonl').open('a') as output:
        output.write(json.dumps(row) + '\n')


def tls_established_client(data):
    try:
        cert = data.ssl_conn.get_certificate()
        if hasattr(cert, 'to_cryptography'):
            cert = cert.to_cryptography()
        der = cert.public_bytes(serialization.Encoding.DER)
        pem = cert.public_bytes(serialization.Encoding.PEM)
        expected = json.loads((ROOT / 'certificate-controls.json').read_text())['leaf_der_sha256']
        digest = hashlib.sha256(der).hexdigest()
        (ROOT / ('presented-leaf-' + str(number(data.conn)) + '.pem')).write_bytes(pem)
        emit('client_tls_established', data.conn, presented_leaf_der_sha256=digest,
             matches_configured_test_leaf=digest == expected,
             sni_category=sni_category(data.conn.sni), tls_version=data.conn.tls_version)
    except Exception as error:
        # Never emit exception messages: they can contain addresses or URLs.
        emit('certificate_evidence_unavailable', data.conn, exception_type=type(error).__name__)


def sni_category(sni):
    # Expected values are private runtime config, not copied from request bodies.
    config = json.loads((ROOT / 'expected-peer.json').read_text())
    if sni == config['server_name']:
        return 'expected_dns'
    if sni == config['server_ip']:
        return 'expected_ip'
    return 'absent' if not sni else 'other'


def tls_failed_client(data):
    reason = (data.conn.error or '').lower()
    category = 'certificate_related' if any(x in reason for x in ('certificate', 'unknown ca')) else 'other'
    emit('client_tls_failed', data.conn, reason_category=category)


def tls_established_server(data):
    emit('upstream_tls_established', data.conn)


def tls_failed_server(data):
    emit('upstream_tls_failed', data.conn)


def matches(flow):
    return flow.request.method == 'POST' and flow.request.path.split('?', 1)[0] == '/v5/audio/fingerprint'


def request(flow):
    if not matches(flow):
        return
    valid = False
    try:
        body = json.loads(flow.request.raw_content)
        payload = base64.b64decode(body['payload'], validate=True)
        valid = len(payload) > 0 and len(payload) == body['length'] and len(payload) % 76 == 0
    except (ValueError, TypeError, KeyError, UnicodeError):
        pass
    emit('fingerprint_request', flow.client_conn, request_epoch=flow.request.timestamp_start,
         nonempty_legacy_layout_valid=valid)
    with (ROOT / 'fingerprint-events.tsv').open('a') as output:
        output.write(f'{flow.request.timestamp_start:.9f}\trequest\t-\t-\n')


def response(flow):
    if matches(flow):
        emit('fingerprint_response', flow.client_conn, request_epoch=flow.request.timestamp_start,
             http_status=flow.response.status_code)
        with (ROOT / 'fingerprint-events.tsv').open('a') as output:
            output.write(f'{flow.request.timestamp_start:.9f}\tresponse\t{flow.response.status_code}\t-\n')
