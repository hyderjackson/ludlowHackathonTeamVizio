#!/usr/bin/env python3
"""Inspect the structural fields of a local JSON message, without printing it."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis/common'))
from fingerprints import validate_message

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('message', type=Path)
    args = parser.parse_args()
    try:
        result = validate_message(json.loads(args.message.read_text()))
    except (ValueError, TypeError, KeyError):
        parser.exit(1, 'Message rejected: invalid JSON or fingerprint field structure.\n')
    print(json.dumps(result, indent=2))
