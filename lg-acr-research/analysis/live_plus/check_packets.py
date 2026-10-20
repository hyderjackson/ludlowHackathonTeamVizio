"""Independently count packet headers in the measured windows, offline."""
from pathlib import Path
import collections,json,subprocess,os

ROOT=Path(__file__).resolve().parents[2]
OUT=Path(os.environ['ACR_OUTPUT_DIR'])
TV_IP=os.environ['ACR_TV_IP']
TV_MAC=os.environ.get('ACR_TV_MAC','')
REMOTE_IP=os.environ.get('ACR_REMOTE_IP','94.26.73.21')
summary=json.loads((OUT/'study-summary.json').read_text())
result=[]
for archive in summary['archives']:
    name=archive['archive']
    windows=[w for w in summary['windows'] if w['archive']==name]
    counters={w['phase']:{'packets':0,'wire_bytes':0,'ipv4_packets':0,'ipv6_packets':0,
        'target_4437_packets':0,'any_tcp_4437_packets':0,'outbound_tcp_ports':collections.Counter(),
        'outbound_udp_ports':collections.Counter(),'observed_tcp_4437_peers':set()} for w in windows}
    path=Path(os.environ['ACR_PRIVATE_DIR'])/name.removesuffix('.tgz')/'network-headers.pcap'
    fields=['frame.time_epoch','frame.len','eth.src','ip.src','ip.dst','ipv6.src','ipv6.dst',
            'tcp.srcport','tcp.dstport','udp.srcport','udp.dstport']
    cmd=['tshark','-n','-r',str(path),'-T','fields','-E','occurrence=f']
    for f in fields: cmd+=['-e',f]
    with (path.parent/'packet-analysis.log').open('w') as log:
        p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=log,text=True)
        for line in p.stdout:
            values=line.rstrip('\n').split('\t')
            if len(values)!=len(fields):raise ValueError('Unexpected packet row')
            t,length,mac,src,dst,src6,dst6,tsp,tdp,usp,udp=values
            t=float(t)
            active=[w for w in windows if w['start_epoch']<=t<w['end_epoch']]
            if not active:continue
            c=counters[active[0]['phase']]
            c['packets']+=1;c['wire_bytes']+=int(length)
            c['ipv4_packets']+=bool(src);c['ipv6_packets']+=bool(src6)
            if '4437' in (tsp,tdp):
                c['any_tcp_4437_packets']+=1
                c['observed_tcp_4437_peers'].add(dst if src==TV_IP or (bool(TV_MAC) and mac.lower()==TV_MAC.lower()) else src)
                if REMOTE_IP in (src,dst):c['target_4437_packets']+=1
            if (bool(TV_MAC) and mac.lower()==TV_MAC.lower()) or src==TV_IP:
                if tdp:c['outbound_tcp_ports'][tdp]+=1
                if udp:c['outbound_udp_ports'][udp]+=1
        if p.wait()!=0:raise RuntimeError('Packet dissection failed; inspect private log')
    for w in windows:
        c=counters[w['phase']]
        c['observed_tcp_4437_peers']=sorted(c['observed_tcp_4437_peers'])
        result.append({'phase':w['phase'],**c})
        print(w['phase'],'packets',c['packets'],'wire bytes',c['wire_bytes'],
              'target 4437 packets',c['target_4437_packets'],'all TCP4437',c['any_tcp_4437_packets'])
(OUT/'packet-summary.json').write_text(json.dumps(result,indent=2)+'\n')
