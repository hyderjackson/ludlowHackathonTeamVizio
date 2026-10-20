#!/usr/bin/env python3
"""Export audited source/docs only. Private outputs and Git internals stay out."""
import argparse
import hashlib
import os
from pathlib import Path
import zipfile
from audit_share import ROOT, audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    target = args.out.resolve()
    if target.is_relative_to(ROOT):
        parser.error('Write the share archive outside the repository')
    if target.exists():
        parser.error('Output already exists; choose a new archive name')
    paths = audit()
    manifest = '\n'.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' +
                         str(p.relative_to(ROOT)) for p in paths) + '\n'
    os.umask(0o077)
    with target.open('xb') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for path in paths:
                archive.write(path, 'lg-acr-research/' + str(path.relative_to(ROOT)))
            archive.writestr('lg-acr-research/MANIFEST.sha256', manifest)
    print(f'Created audited share archive with {len(paths)} source/document files and a hash manifest.')


if __name__ == '__main__':
    main()
