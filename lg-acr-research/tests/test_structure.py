import base64
import copy
import json
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis/common'))
from fingerprints import validate_message
from inspect_flows import parse


class StructuralChecks(unittest.TestCase):
    def setUp(self):
        self.message = json.loads((Path(__file__).resolve().parents[1] /
                                   'data/examples/synthetic-fingerprint.json').read_text())

    def test_synthetic_layout(self):
        self.assertEqual(validate_message(self.message)['legacy_records'], 3)
        self.assertEqual(validate_message(self.message)['v3_vectors'], 1)

    def test_incorrect_declared_length(self):
        self.message['length'] += 1
        with self.assertRaises(ValueError):
            validate_message(self.message)

    def test_incomplete_v3(self):
        del self.message['v3_fps_length']
        with self.assertRaises(ValueError):
            validate_message(self.message)

    def test_v3_index_must_reference_a_legacy_record(self):
        self.message['v3_frames_payload'] = base64.b64encode(struct.pack('<I', 999)).decode()
        with self.assertRaises(ValueError):
            validate_message(self.message)

    def test_nan_is_rejected(self):
        values = struct.pack('<63e', float('nan'), *([0.] * 62))
        self.message['v3_fps_payload'] = base64.b64encode(values).decode()
        with self.assertRaises(ValueError):
            validate_message(self.message)

    def test_typed_netstring_truncation(self):
        with self.assertRaises((ValueError, IndexError)):
            parse(b'8:short,')


if __name__ == '__main__':
    unittest.main()
