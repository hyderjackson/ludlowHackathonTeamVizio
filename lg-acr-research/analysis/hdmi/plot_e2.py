from pathlib import Path
import json
import os

ROOT = Path(__file__).resolve().parents[2]
os.environ['MPLCONFIGDIR'] = str(Path(os.environ['ACR_PRIVATE_DIR']) / 'mplconfig')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

out = Path(os.environ['ACR_OUTPUT_DIR'])
windows = json.loads((out / 'e2-summary.json').read_text())['windows']
accepted = [w['http_statuses'].get('202', 0) for w in windows]
rejected = [w['http_statuses'].get('400', 0) for w in windows]
missing = [w['http_statuses'].get('None', 0) for w in windows]
fig, ax = plt.subplots(figsize=(12, 7))
fig.subplots_adjust(left=.1, right=.97, top=.76, bottom=.27)
fig.text(.1, .93, 'HDMI soundtrack isolation: observed ACR uploads', fontsize=22, fontweight='bold')
fig.text(.1, .87, 'Live Plus On throughout · same HDMI connection · about 3 measured minutes per condition',
         fontsize=11, color='#444444')
x = range(4)
ax.bar(x, accepted, color='#267cb2', width=.58, label='HTTP 202: accepted')
ax.bar(x, rejected, bottom=accepted, color='#d89538', width=.58,
       label='HTTP 400: malformed end message')
ax.bar(x, missing, bottom=[a + b for a, b in zip(accepted, rejected)], color='#9a9a9a',
       width=.58, label='No response retained')
for i, a, b, c in zip(x, accepted, rejected, missing):
    ax.text(i, a + b + c + 1.2, str(a + b + c), ha='center', fontsize=19, fontweight='bold')
    if a:
        ax.text(i, a / 2, str(a) + ' accepted', ha='center', va='center', fontsize=12, color='white')
ax.set(ylim=(0, 59), ylabel='POST attempts to /v5/audio/fingerprint', xticks=list(x),
       xticklabels=['Normal picture\nand sound', 'Moving picture\nwith silence',
                    'Black picture\nwith sound', 'Normal picture\nand sound again'])
ax.set_axisbelow(True)
ax.grid(axis='y', alpha=.17)
ax.spines[['top', 'right']].set_visible(False)
ax.tick_params(labelsize=11)
ax.legend(loc='lower left', bbox_to_anchor=(0, 1.02), ncol=3, frameon=False, fontsize=9)
fig.text(.1, .12, 'Silent window: 0 fingerprint POSTs, while 53 TCP 4437 packets and 465 other TV packets continued.', fontsize=11)
fig.text(.1, .075, 'Supports audio dependence of this path. Does not distinguish an internal tap from a mic hearing TV speakers.',
         fontsize=10, color='#444444')
fig.text(.1, .035, 'One rooted TV and selected endpoint. Zero kernel drops. HTTP 202 establishes acceptance, not recognition.',
         fontsize=10, color='#444444')
fig.savefig(out / 'hdmi-audio-isolation.png', dpi=200)
fig.savefig(out / 'hdmi-audio-isolation.svg')
plt.close(fig)
print('Saved HDMI evidence figure.')
