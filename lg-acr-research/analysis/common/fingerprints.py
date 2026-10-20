"""Portable field validator derived from the retained HDMI/baseline checks.

Returns counts, never identifier fields or full feature values. It validates the
wire representation, not server recognition or the physical recording source.
"""
import base64
import math
import struct


def validate_message(message):
    raw = base64.b64decode(message['payload'], validate=True)
    if not raw or len(raw) != message['length'] or len(raw) % 76:
        raise ValueError('Legacy length/stride')
    indices = [struct.unpack_from('<I', raw, offset)[0] for offset in range(0, len(raw), 76)]
    v3_fields = {'v3_frames_payload', 'v3_frames_length', 'v3_fps_payload', 'v3_fps_length'}
    present = v3_fields & message.keys()
    count = 0
    if present:
        if present != v3_fields:
            raise ValueError('Incomplete V3 fields')
        frames = base64.b64decode(message['v3_frames_payload'], validate=True)
        features = base64.b64decode(message['v3_fps_payload'], validate=True)
        if len(frames) != message['v3_frames_length'] or len(frames) % 4:
            raise ValueError('V3 index length')
        count = len(frames) // 4
        if len(features) != message['v3_fps_length'] or len(features) != count * 126:
            raise ValueError('V3 vector length')
        v3_indices = struct.unpack('<' + 'I' * count, frames)
        if not set(v3_indices) <= set(indices):
            raise ValueError('V3 index is not in legacy records')
        values = struct.unpack('<' + 'e' * (len(features) // 2), features)
        if not all(math.isfinite(value) for value in values):
            raise ValueError('Nonfinite feature value')
    return {'legacy_records': len(indices), 'legacy_bytes': len(raw),
            'v3_vectors': count, 'values_per_v3_vector': 63,
            'v3_indices_subset_of_legacy': True}
