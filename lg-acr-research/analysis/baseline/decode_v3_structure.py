"""Offline V3 layout validation; never contacts the TV or replays requests."""
from pathlib import Path
import base64
import collections
import csv
import hashlib
import json
import os
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

import numpy as np
from inspect_flows import read_all, content, text


def main():
    os.umask(0o077)
    out = Path(os.environ['ACR_OUTPUT_DIR'])
    out.mkdir(exist_ok=True)
    private = Path(os.environ['ACR_PRIVATE_DIR'])
    private.mkdir(mode=0o700, exist_ok=True)
    matrices, records, group_ids = [], [], {}
    for f in read_all():
        req = f.get('request') or {}
        if text(req.get('path', '')).split('?')[0] != '/v5/audio/fingerprint':
            continue
        j = json.loads(content(req)[0])
        group_ids.setdefault(j['token'], len(group_ids) + 1)
        if 'v3_fps_payload' not in j:
            continue
        raw_indices = base64.b64decode(j['v3_frames_payload'], validate=True)
        raw_features = base64.b64decode(j['v3_fps_payload'], validate=True)
        assert len(raw_indices) == j['v3_frames_length']
        assert len(raw_features) == j['v3_fps_length']
        assert len(raw_indices) % 4 == 0
        idx = np.frombuffer(raw_indices, dtype='<u4')
        assert len(raw_features) == len(idx) * 126
        x = np.frombuffer(raw_features, dtype='<f2').astype(float).reshape(-1, 63)
        assert np.isfinite(x).all()
        matrices.append(x)
        for i, row in zip(idx, x):
            records.append((group_ids[j['token']], int(i), row))
    x = np.concatenate(matrices)
    bands, delta = x[:, :32], x[:, 32:]
    d = np.diff(bands, axis=1)
    predicted = (d - d.mean(axis=1, keepdims=True)) / d.std(axis=1, keepdims=True)
    error = np.abs(predicted - delta)
    def describe(a):
        return {'maximum_absolute_frame_mean': float(np.abs(a.mean(axis=1)).max()),
                'minimum_frame_population_sd': float(a.std(axis=1).min()),
                'maximum_frame_population_sd': float(a.std(axis=1).max())}
    summary = {
        'source': 'user-supplied baseline flow file; not On/Off study',
        'source_flow_sha256': hashlib.sha256(Path(os.environ['ACR_BASELINE_FLOWS']).read_bytes()).hexdigest(),
        'messages': len(matrices), 'frames': len(x), 'coefficients_per_frame': 63,
        'first_32': describe(bands), 'last_31': describe(delta),
        'delta_prediction_from_quantized_first_32': {
            'formula': 'population_zscore(diff(first_32))',
            'maximum_absolute_error': float(error.max()),
            'median_absolute_error': float(np.median(error)),
            'rmse': float(np.sqrt(np.mean(error ** 2))),
            'caveat': 'First 32 values are already quantized; this is not byte-exact upstream reconstruction.'},
        'layout_evidence': {
            'processAudioFrame': '0xf5f3c', 'standardize_copy_call': '0xf60a4',
            'raw_adjacent_difference_loop': '0xf6140-0xf6160',
            'standardize_differences_call': '0xf616c',
            'concatenate_loops': '0xf6194-0xf61e4',
            'standardize': '0x110150', 'getMean': '0x110070', 'getStdev': '0x1100c8',
            'melBands': '0xcdbdc', 'mel_magnitude_loop': '0xcdc80-0xcdcf8'},
        'not_established': ['exact active band-center frequencies and rolling window',
                            'complete PCM-to-feature bit-exact reproduction',
                            'original audio reconstruction', 'microphone route', 'video upload']}
    (out / 'v3-structure-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    fields = ['capture_group', 'audio_frame_index'] + [f'band_z_{i}' for i in range(32)] + [f'adjacent_difference_z_{i}' for i in range(31)]
    csv_path = private / 'all-v3-feature-values.csv'
    with csv_path.open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(fields)
        for group, index, row in records:
            writer.writerow([group, index, *row.tolist()])
    os.chmod(csv_path, 0o600)
    os.environ.setdefault('MPLCONFIGDIR', str(private / 'mplconfig'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    first_group = records[0][0]
    selected = [r for r in records if r[0] == first_group]
    indices = np.array([r[1] for r in selected])
    matrix = np.stack([r[2] for r in selected])
    edges = np.r_[indices[0] - (indices[1] - indices[0]) / 2,
                  (indices[:-1] + indices[1:]) / 2,
                  indices[-1] + (indices[-1] - indices[-2]) / 2]
    fig, axes = plt.subplots(2, 1, figsize=(11, 6.5), layout='constrained', sharex=True)
    vmax = float(abs(matrix).max())
    for ax, values, title in zip(axes, [matrix[:, :32], matrix[:, 32:]],
                               ['First 32: standardized Mel-band magnitude averages',
                                'Last 31: standardized differences between neighboring bands']):
        im = ax.pcolormesh(edges, np.arange(values.shape[1] + 1) - .5, values.T,
                           cmap='RdBu_r', vmin=-vmax, vmax=vmax, rasterized=True)
        ax.set(title=title, ylabel='Feature index')
    axes[1].set_xlabel('SDK audio-frame index (first capture group)')
    fig.colorbar(im, ax=axes, label='Decoded binary16 value', shrink=.9)
    fig.suptitle('The 63 uploaded V3 values have a 32 + 31 structure', fontsize=15)
    fig.savefig(out / 'v3-feature-structure.png', dpi=200)
    fig.savefig(out / 'v3-feature-structure.svg')
    print(json.dumps({'frames': len(x), 'private_csv': str(csv_path),
                      'summary': str(out / 'v3-structure-summary.json')}))


if __name__ == '__main__':
    main()
