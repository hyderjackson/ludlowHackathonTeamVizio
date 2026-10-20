#!/usr/bin/env python3
"""Run the retained analysis offline. Inputs and generated evidence stay private."""
import argparse
import hashlib
import os
from pathlib import Path
import runpy
import sys
import tarfile

ROOT = Path(__file__).resolve().parent


def run(relative):
    runpy.run_path(str(ROOT / relative), run_name='__main__')


def certificate_members(archive, folder):
    expected = '354f4b4396bc4d78d6a32b7a4e2261a2cfcac72aa0042f1ead476964ec6baeee'
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError('Certificate archive does not match the retained experiment')
    required = {'phases.tsv', 'expected-peer.json', 'certificate-controls.json',
                'tls-events.jsonl', 'test-leaf-cert.pem', 'test-root-ca.pem',
                'flows.mitm', 'network-headers.pcap', 'capture.log'}
    seen = set()
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            leaf = member.name.startswith('presented-leaf-') and member.name.endswith('.pem')
            if member.name not in required and not leaf:
                continue
            if (Path(member.name).name != member.name or member.name in seen
                    or not member.isfile() or not 0 <= member.size <= 512 * 1024 * 1024):
                raise ValueError('Unexpected certificate archive member')
            seen.add(member.name)
            target = folder / member.name
            with source.extractfile(member) as src, target.open('xb') as dst:
                while block := src.read(1024 * 1024):
                    dst.write(block)
            target.chmod(0o600)
    if not required <= seen:
        raise ValueError('Missing certificate evidence')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='study', required=True)
    for name in ('baseline', 'live-plus', 'hdmi', 'certificate'):
        item = sub.add_parser(name)
        item.add_argument('--out', type=Path, required=True,
                          help='New private output directory, preferably outside this repository')
        if name == 'baseline':
            item.add_argument('--flows', type=Path, required=True)
            item.add_argument('--features', action='store_true', help='Also validate/plot V3 (NumPy/Matplotlib)')
        elif name == 'live-plus':
            item.add_argument('--study-archive', type=Path, required=True)
            item.add_argument('--off2-archive', type=Path, required=True)
            item.add_argument('--tv-ip', help='Private TV source IPv4, used only for offline packet attribution')
            item.add_argument('--tv-mac', default='')
            item.add_argument('--skip-packets', action='store_true')
            item.add_argument('--plot', action='store_true')
        else:
            item.add_argument('--archive', type=Path, required=True)
            if name == 'hdmi':
                item.add_argument('--playback-log', type=Path, required=True)
                item.add_argument('--plot', action='store_true')
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('Run without -O: original analysis scripts use assertions for evidence checks')
    output = args.out.resolve()
    if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / 'private-runs'):
        parser.error('In-repository outputs must be under ignored private-runs/')
    if output.exists():
        parser.error('Choose a new output directory; existing evidence is never overwritten')
    inputs = [value for key, value in vars(args).items() if isinstance(value, Path) and key != 'out']
    if not all(p.is_file() for p in inputs):
        parser.error('A required local input file is missing')
    if args.study == 'live-plus' and not args.skip_packets and not args.tv_ip:
        parser.error('Supply --tv-ip for packet attribution, or select --skip-packets')
    if args.study == 'live-plus' and args.plot and args.skip_packets:
        parser.error('The original Live Plus figure also requires packet results')
    os.umask(0o077)
    output.mkdir(parents=True, mode=0o700)
    private = output / 'evidence'
    private.mkdir(mode=0o700)
    results = output / 'results'
    results.mkdir(mode=0o700)
    os.environ.update(ACR_PRIVATE_DIR=str(private), ACR_OUTPUT_DIR=str(results),
                      MPLCONFIGDIR=str(private / 'mplconfig'))
    if args.study == 'baseline':
        os.environ['ACR_BASELINE_FLOWS'] = str(args.flows.resolve())
        run('analysis/baseline/decode_legacy.py')
        if args.features:
            run('analysis/baseline/decode_v3_structure.py')
    elif args.study == 'live-plus':
        os.environ.update(ACR_STUDY_ARCHIVE=str(args.study_archive.resolve()),
                          ACR_OFF2_ARCHIVE=str(args.off2_archive.resolve()),
                          ACR_TV_IP=args.tv_ip or '', ACR_TV_MAC=args.tv_mac)
        run('analysis/live_plus/compare_study.py')
        if not args.skip_packets:
            run('analysis/live_plus/check_packets.py')
        if args.plot:
            run('analysis/live_plus/plot_results.py')
    elif args.study == 'hdmi':
        os.environ.update(ACR_HDMI_ARCHIVE=str(args.archive.resolve()),
                          ACR_PLAYBACK_LOG=str(args.playback_log.resolve()))
        run('analysis/hdmi/analyze_e2.py')
        if args.plot:
            run('analysis/hdmi/plot_e2.py')
    else:
        os.environ['ACR_CERT_ARCHIVE'] = str(args.archive.resolve())
        certificate_members(args.archive, private)
        run('analysis/certificate/analyze_certificate.py')
    print('Offline analysis finished. Generated files remain private; they are not part of the share bundle.')


if __name__ == '__main__':
    main()
