from pathlib import Path
import json
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(os.environ['ACR_OUTPUT_DIR'])
summary=json.loads((OUT/'study-summary.json').read_text())
packets=json.loads((OUT/'packet-summary.json').read_text())
windows=summary['windows']
x=[0,1,2,3.35]
colors=['#ce6b25','#276caa','#ce6b25','#276caa']
fig,(a,b)=plt.subplots(2,1,figsize=(12,7.5),gridspec_kw={'height_ratios':[1.6,1]},sharex=True)
fig.subplots_adjust(left=.1,right=.98,top=.84,bottom=.19,hspace=.16)
fig.suptitle('Live Plus On / Off: observed ACR uploads',fontsize=21,y=.97,ha='left',x=.1)
fig.text(.1,.895,'Same LG TV · LG Channels, NFL Channel 435 · approximately 10 measured minutes per window',fontsize=11,color='#444444')
a.bar(x,[w['fingerprint_posts'] for w in windows],color=colors,width=.62)
for pos,w in zip(x,windows):
    n=w['fingerprint_posts']
    a.text(pos,n+7,str(n),ha='center',va='bottom',fontsize=19,fontweight='bold')
a.set(ylabel='Fingerprint POSTs',ylim=(0,260),yticks=[0,50,100,150,200,250])
fig.text(.1,.86,'All 430 measured fingerprint POSTs received HTTP 202',fontsize=10,color='#444444')
b.bar(x,[p['wire_bytes']/1e6 for p in packets],color=colors,width=.62,alpha=.65)
for pos,p in zip(x,packets):
    b.text(pos,p['wire_bytes']/1e6+7,f"{p['wire_bytes']/1e6:.1f}",ha='center',fontsize=11)
b.set(ylabel='All TV traffic\n(MB, wire lengths)',ylim=(0,350),yticks=[0,100,200,300],xticks=x,
      xticklabels=['On1','Off1','On2','Off2*'])
for ax in (a,b):
    ax.set_axisbelow(True);ax.grid(axis='y',alpha=.18)
    ax.spines[['top','right']].set_visible(False)
    ax.axvline(2.67,color='#888888',linestyle='--',alpha=.55)
    ax.tick_params(labelsize=11)
fig.text(.1,.095,'Off windows: zero packets on TCP 4437; other TV traffic continued. Capture logs report zero kernel drops.',fontsize=10)
fig.text(.1,.055,'*Off2 used a separate proxy session after a gap. One rooted TV and one selected ACR endpoint; no claim about all tracking.',fontsize=10,color='#444444')
fig.savefig(OUT/'live-plus-on-off.png',dpi=220)
fig.savefig(OUT/'live-plus-on-off.svg')
print('Saved PNG and SVG study figure.')
