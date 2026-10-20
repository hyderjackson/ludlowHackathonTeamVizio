#!/usr/bin/env python3
"""Audit the allowlisted code/document bundle. Never prints matched values."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {'README.md', 'SHARING.md', 'THIRD_PARTY.md', '.gitignore',
              'requirements-analysis.txt', 'SOURCE_MAP.json', 'reproduce.py'}
DIRECTORIES = {'docs', 'data', 'analysis', 'experiments', 'instrumentation', 'tools', 'tests'}
SKIP = {'.git', '.venv', '__pycache__', 'private-runs'}
SUFFIXES = {'.md', '.py', '.sh', '.json', '.txt'}
PATTERNS = {
    'private key material': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'private IPv4 address': re.compile(r'(?<![\w.])(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\w.])'),
    'MAC address': re.compile(r'(?i)(?<![\w:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![\w:])'),
    'personal home path': re.compile(r'/(?:home|Users)/[A-Za-z0-9_.-]+/'),
    'credential query value': re.compile(r'(?i)[?&](?:api_key|alp_uid|access_token|client_key)=(?!<|REDACTED|SYNTHETIC)[A-Za-z0-9_-]{6,}'),
}


def selected_files(root=ROOT):
    files, problems = [], []
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(part in SKIP for part in relative.parts):
            continue
        # A bundle carries this generated checksum list. It is not source and
        # must not be re-included recursively when exporting an unpacked copy.
        if str(relative) == 'MANIFEST.sha256' and not path.is_symlink():
            continue
        if path.is_symlink():
            problems.append((str(relative), 'symlink excluded'))
            continue
        if not path.is_file():
            continue
        approved = (str(relative) in ROOT_FILES or
                    (relative.parts[0] in DIRECTORIES and path.suffix in SUFFIXES))
        if not approved:
            problems.append((str(relative), 'unexpected file outside the share allowlist'))
            continue
        if path.stat().st_size > 2 * 1024 * 1024:
            problems.append((str(relative), 'unexpectedly large file'))
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeError:
            problems.append((str(relative), 'non-text file'))
            continue
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                problems.append((str(relative), label))
        files.append(path)
    return files, problems


def audit(root=ROOT):
    files, problems = selected_files(root)
    if problems:
        for path, category in problems:
            print(f'BLOCKED: {path}: {category}', file=sys.stderr)
        raise ValueError('Share audit failed; matched values were not printed')
    return files


if __name__ == '__main__':
    try:
        paths = audit()
    except ValueError:
        sys.exit(1)
    print(f'Share audit passed for {len(paths)} allowlisted text files.')
