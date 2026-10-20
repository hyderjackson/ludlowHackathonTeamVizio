"""Decode the SDK SessionV1 record boundary; never export request identifiers."""
import base64,collections,hashlib,json,struct,sys,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'common'))
from inspect_flows import read_all,content,text

def decode_payload(encoded,declared_length):
 raw=base64.b64decode(encoded,validate=True)
 if len(raw)!=declared_length or len(raw)%76: raise ValueError('legacy length/stride')
 return [(struct.unpack_from('<I',raw,i)[0],raw[i+4:i+76]) for i in range(0,len(raw),76)]

def main():
 out=Path(os.environ['ACR_OUTPUT_DIR']);out.mkdir(parents=True,exist_ok=True)
 rows=[];groups=collections.defaultdict(list);all_indices=[];hashes=[];v3_subset=[];first_indices=None;v3steps=collections.Counter();v3parities=collections.Counter();legacy_steps=collections.Counter()
 for f in read_all():
  r=f.get('request') or {}
  if text(r.get('path','')).split('?')[0]!='/v5/audio/fingerprint': continue
  j=json.loads(content(r)[0]);records=decode_payload(j['payload'],j['length'])
  ix=[v[0] for v in records];all_indices+=ix;hashes.extend(v[1] for v in records)
  legacy_steps.update(b-a for a,b in zip(ix,ix[1:]))
  if first_indices is None:first_indices=ix[:3]
  v3raw=base64.b64decode(j.get('v3_frames_payload',''),validate=True)
  v3=list(struct.unpack('<'+'I'*(len(v3raw)//4),v3raw))
  v3steps.update(b-a for a,b in zip(v3,v3[1:]));v3parities.update(i%2 for i in v3)
  v3_subset.append(set(v3).issubset(ix))
  groups[j['token']].extend(ix)
  rows.append({'request_ordinal':len(rows)+1,'message_type':j['type'],
    'legacy_bytes':j['length'],'record_count':len(records),
    'first_audio_frame_index':ix[0] if ix else None,'last_audio_frame_index':ix[-1] if ix else None,
    'strictly_increasing_indices':all(a<b for a,b in zip(ix,ix[1:])),
    'v3_index_count':len(v3),'v3_indices_subset_of_legacy':v3_subset[-1]})
 c=collections.Counter(b for h in hashes for b in h)
 summary={'source_flow_sha256':hashlib.sha256(Path(os.environ['ACR_BASELINE_FLOWS']).read_bytes()).hexdigest(),
  'requests':len(rows),'legacy_records':len(hashes),'legacy_decoded_bytes':sum(x['legacy_bytes'] for x in rows),
  'record_layout':{'stride':76,'offset_0':'uint32 little endian audio frame index (input frame number minus one)',
   'offset_4':'72 one-byte MinHash rank values; lower 8 bits of first-active-bit permutation rank'},
  'index_min':min(all_indices),'index_max':max(all_indices),
  'all_requests_strictly_increasing':all(r['strictly_increasing_indices'] for r in rows),
  'within_group_index_step_counts':dict(collections.Counter(b-a for g in groups.values() for a,b in zip(g,g[1:]))),
  'within_request_index_step_counts':dict(legacy_steps),
  'v3_subset_requests':sum(v3_subset),'nonempty_v3_requests':sum(r['v3_index_count']>0 for r in rows),
  'signature_byte_min':min(c),'signature_byte_max':max(c),'distinct_signature_bytes':len(c),
  'unique_signature_vectors':len(set(hashes)),
  'groups':len(groups),'group_record_counts':dict(collections.Counter(len(g) for g in groups.values())),
  'v3_within_request_index_step_counts':dict(v3steps),'v3_index_parities':dict(v3parities),
  'first_request_safe_sample':{'audio_frame_indices':first_indices}}
 (out/'legacy-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 (out/'legacy-request-measurements.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(json.dumps(summary,indent=2))
if __name__=='__main__':main()
