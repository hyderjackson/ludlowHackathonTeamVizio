"""Offline, phase-bound comparison. Never prints credentials or raw bodies."""
from pathlib import Path
import base64, collections, csv, datetime as dt, hashlib, io, json, math
import statistics, struct, sys, tarfile, os

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'common'))
from inspect_flows import parse, text, content

ARCHIVE_PATHS = {'live-plus.tgz': Path(os.environ['ACR_STUDY_ARCHIVE']), 'off2.tgz': Path(os.environ['ACR_OFF2_ARCHIVE'])}
PRIVATE = Path(os.environ['ACR_PRIVATE_DIR'])
OUT = Path(os.environ['ACR_OUTPUT_DIR'])
ARCHIVES = ['live-plus.tgz', 'off2.tgz']
MEMBERS = {'flows.mitm', 'phases.tsv', 'capture.log', 'proxy.log', 'network-headers.pcap'}

def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat(timespec='milliseconds')

def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(1024 * 1024): h.update(chunk)
    return h.hexdigest()

def read_evidence(name):
    path = ARCHIVE_PATHS[name]
    folder = PRIVATE / name.removesuffix('.tgz')
    folder.mkdir(mode=0o700, exist_ok=True)
    seen = set()
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            if member.name not in MEMBERS: continue
            if member.name in seen or not member.isfile() or not 0 <= member.size <= 512*1024*1024:
                raise ValueError('Invalid evidence member')
            seen.add(member.name)
            target = folder / member.name
            # Read through tar's verified member boundaries, never extractall.
            with archive.extractfile(member) as src, target.open('wb') as dst:
                while chunk := src.read(1024*1024): dst.write(chunk)
            target.chmod(0o600)
    if seen != MEMBERS: raise ValueError('Missing required member')
    data = (folder / 'flows.mitm').read_bytes()
    flows, pos = [], 0
    while pos < len(data):
        flow, pos = parse(data, pos)
        flows.append(flow)
    rows = list(csv.DictReader((folder/'phases.tsv').open(), delimiter='\t'))
    windows = []
    for row in rows:
        if row['event'] != 'measure_start': continue
        ends = [r for r in rows if r['event']=='measure_end' and r['phase']==row['phase']]
        if len(ends) != 1: raise ValueError('Incomplete/duplicate measurement')
        confirmed = next(r for r in rows if r['event']=='setting_confirmed' and r['phase']==row['phase'])
        start, end = float(row['epoch_utc']), float(ends[0]['epoch_utc'])
        if not start < end: raise ValueError('Invalid measurement bounds')
        windows.append({'phase':row['phase'], 'condition':row['condition'],
                        'start_epoch':start, 'end_epoch':end,
                        'confirmed_epoch':float(confirmed['epoch_utc'])})
    return folder, flows, windows, rows

def decode_upload(flow):
    req = flow['request']
    raw = content(req)[0]
    j = json.loads(raw)
    legacy = base64.b64decode(j['payload'], validate=True)
    if len(legacy) != j['length'] or len(legacy)%76: raise ValueError('Legacy layout')
    indices = [struct.unpack_from('<I',legacy,p)[0] for p in range(0,len(legacy),76)]
    frames, features = (), ()
    if 'v3_frames_payload' in j:
        a = base64.b64decode(j['v3_frames_payload'],validate=True)
        b = base64.b64decode(j['v3_fps_payload'],validate=True)
        if len(a)!=j['v3_frames_length'] or len(b)!=j['v3_fps_length'] or len(a)%4 or len(b)!=len(a)//4*126:
            raise ValueError('V3 layout')
        frames=struct.unpack('<'+'I'*(len(a)//4),a)
        features=struct.unpack('<'+'e'*(len(b)//2),b)
        if not all(math.isfinite(x) for x in features) or not set(frames)<=set(indices):
            raise ValueError('V3 values or index relationship')
    return j, {'body_bytes':len(raw), 'legacy_records':len(indices),
               'v3_frames':len(frames), 'v3_feature_bytes':len(features)*2,
               'payload_digest':hashlib.sha256(legacy).hexdigest()}

def summary_stats(values):
    return {'count':len(values), 'min':min(values), 'median':statistics.median(values), 'max':max(values)} if values else None

def main():
    OUT.mkdir(exist_ok=True)
    summary={'archives':[], 'windows':[], 'interpretation_limits':[
        'Counts use request timestamp_start in half-open measured windows; settling and menu time are excluded.',
        'Response statuses may arrive after the request window; HTTP 202 is acceptance, not a recognition result.',
        'Client timestamps are self-reported and clock offset is not calibrated; timestamp freshness does not prove capture freshness.',
        'The Off2 follow-up has an observation gap and a restarted proxy session; it is not a continuous fourth phase.',
        'One rooted TV, one live channel and one selected IPv4 destination/port; no universal claim about every LG service.'
    ]}
    request_rows=[]
    on1_payloads=set()
    for name in ARCHIVES:
        folder, flows, windows, events=read_evidence(name)
        uploads=[]
        for f in flows:
            req=f.get('request') or {}
            if text(req.get('path','')).split('?')[0]=='/v5/audio/fingerprint':
                j, metrics=decode_upload(f);uploads.append((f,j,metrics))
        summary['archives'].append({'archive':name,'sha256':digest_file(ARCHIVE_PATHS[name]),
            'flows_sha256':digest_file(folder/'flows.mitm'), 'total_http_flows':len(flows),
            'total_fingerprint_posts':len(uploads),
            'capture_log':(folder/'capture.log').read_text().strip(),
            'incomplete_prompt_phases':[r['phase'] for r in events if r['event']=='transition_prompt'
                 and not any(w['phase']==r['phase'] for w in windows)]})
        group_numbers={}
        for window in windows:
            lo,hi=window['start_epoch'],window['end_epoch']
            rows=[(f,j,m) for f,j,m in uploads if lo<=f['request']['timestamp_start']<hi]
            ages=[]; client_ends=[]
            for f,j,m in rows:
                key=j['token']; group_numbers.setdefault(key,len(group_numbers)+1)
                end=j.get('ts_end')
                if isinstance(end,(int,float)) and 1e12<end<1e13:
                    end=end/1000; ages.append(f['request']['timestamp_start']-end);client_ends.append(end)
                else: end=None
                request_rows.append({'archive':name,'phase':window['phase'],
                    'utc':iso(f['request']['timestamp_start']), 'epoch':f['request']['timestamp_start'],
                    'group':group_numbers[key], 'type':j.get('type'),
                    'http_status':(f.get('response') or {}).get('status_code'),
                    'body_bytes':m['body_bytes'],'legacy_records':m['legacy_records'],
                    'v3_frames':m['v3_frames'],'client_end_utc':iso(end) if end else '',
                    'request_minus_client_end_seconds':f['request']['timestamp_start']-end if end else ''})
            all_window_flows=[f for f in flows if lo<=(f.get('request') or {}).get('timestamp_start',-1)<hi]
            statuses=collections.Counter(str((f.get('response') or {}).get('status_code')) for f,j,m in rows)
            row={**window,'archive':name,'start_utc':iso(lo),'end_utc':iso(hi),'duration_seconds':hi-lo,
                'http_flows':len(all_window_flows), 'fingerprint_posts':len(rows),
                'fingerprint_posts_per_minute':len(rows)*60/(hi-lo), 'http_statuses':dict(statuses),
                'distinct_capture_groups_overlapping_window':len({j['token'] for f,j,m in rows}),
                'message_types':dict(collections.Counter(j.get('type') for f,j,m in rows)),
                'body_bytes':sum(m['body_bytes'] for f,j,m in rows),
                'legacy_records':sum(m['legacy_records'] for f,j,m in rows),
                'v3_frames':sum(m['v3_frames'] for f,j,m in rows),
                'record_failure_values':dict(collections.Counter(str(j.get('record_failure')) for f,j,m in rows)),
                'app_names':dict(collections.Counter(j.get('app_name') for f,j,m in rows)),
                'channel_names':dict(collections.Counter(j.get('channel_name') for f,j,m in rows)),
                'request_minus_client_end_seconds':summary_stats(ages),
                'client_end_before_setting_confirmation':sum(t<window['confirmed_epoch'] for t in client_ends),
                'client_end_before_measure_start':sum(t<lo for t in client_ends),
                'flow_errors':sum(bool(f.get('error')) for f,j,m in rows)}
            if window['phase']=='on1': on1_payloads.update(m['payload_digest'] for f,j,m in rows)
            if window['phase']=='on2': row['legacy_payloads_identical_to_measured_on1']=sum(m['payload_digest'] in on1_payloads for f,j,m in rows)
            summary['windows'].append(row)
        transition=[]
        for e in events:
            if e['event']!='setting_confirmed':continue
            t=float(e['epoch_utc'])
            before=[f['request']['timestamp_start'] for f,j,m in uploads if f['request']['timestamp_start']<t]
            after=[f['request']['timestamp_start'] for f,j,m in uploads if f['request']['timestamp_start']>=t]
            transition.append({'phase':e['phase'],'confirmed_utc':iso(t),
                'last_prior_upload_utc':iso(max(before)) if before else None,
                'first_subsequent_upload_utc':iso(min(after)) if after else None})
        summary['archives'][-1]['transitions']=transition
    (OUT/'study-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    with (OUT/'measured-requests.csv').open('w',newline='') as f:
        fields=['archive','phase','utc','epoch','group','type','http_status','body_bytes','legacy_records','v3_frames','client_end_utc','request_minus_client_end_seconds']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(request_rows)
    for w in summary['windows']:
        print(w['phase'],w['start_utc'],w['end_utc'],'fingerprint_posts',w['fingerprint_posts'],'HTTP',w['http_statuses'])

if __name__=='__main__': main()
