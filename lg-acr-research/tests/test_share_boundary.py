from contextlib import redirect_stderr
import io
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audit_share import audit


class ShareBoundary(unittest.TestCase):
    def test_export_manifest_is_not_reexported_as_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'README.md').write_text('Guide')
            (root / 'MANIFEST.sha256').write_text('generated checksum list')
            self.assertEqual([p.name for p in audit(root)], ['README.md'])

    def test_private_runs_are_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'README.md').write_text('Public guide')
            (root / 'private-runs').mkdir()
            (root / 'private-runs' / 'capture.mitm').write_bytes(b'private evidence')
            self.assertEqual([p.name for p in audit(root)], ['README.md'])

    def test_capture_file_in_public_tree_blocks_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'data').mkdir()
            (root / 'data' / 'capture.pcap').write_bytes(b'capture')
            with redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                audit(root)

    def test_symlink_blocks_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'README.md').write_text('Guide')
            (root / 'docs').mkdir()
            (root / 'docs' / 'alias.md').symlink_to(root / 'README.md')
            with redirect_stderr(io.StringIO()), self.assertRaises(ValueError):
                audit(root)

    def test_key_marker_is_blocked_without_printing_its_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'docs').mkdir()
            marker = '-----BEGIN ' + 'PRIVATE KEY-----'
            (root / 'docs' / 'note.md').write_text(marker)
            output = io.StringIO()
            with redirect_stderr(output), self.assertRaises(ValueError):
                audit(root)
            self.assertNotIn(marker, output.getvalue())


if __name__ == '__main__':
    unittest.main()
