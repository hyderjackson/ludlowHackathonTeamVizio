"""mitmproxy addon: sanitized request/response counters, no bodies or URLs."""
from pathlib import Path
import json
import os
import math

# Require a private runtime output directory; never write beside the source.
os.umask(0o077)
TARGET = Path(os.environ['ACR_EVENT_DIR']) / 'fingerprint-events.tsv'


def matches(flow):
    return (flow.request.method == 'POST'
            and flow.request.path.split('?', 1)[0] == '/v5/audio/fingerprint')


def request(flow):
    if matches(flow):
        client_end = '-'
        try:
            value = json.loads(flow.request.raw_content).get('ts_end')
            if isinstance(value, (int, float)) and math.isfinite(value) and 1e12 < value < 1e13:
                client_end = f'{value / 1000:.9f}'
        except (ValueError, TypeError, AttributeError, UnicodeError):
            pass
        with TARGET.open('a') as record:
            record.write(f'{flow.request.timestamp_start:.9f}\trequest\t-\t{client_end}\n')


def response(flow):
    if matches(flow):
        with TARGET.open('a') as record:
            record.write(f'{flow.request.timestamp_start:.9f}\tresponse\t{flow.response.status_code}\t-\n')
