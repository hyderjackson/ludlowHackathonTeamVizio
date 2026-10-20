from pathlib import Path
import collections,gzip,json,zlib,os

def parse(b,pos=0,depth=0):
 if depth>64:raise ValueError('nesting limit')
 colon=b.index(b':',pos,pos+24)
 size=int(b[pos:colon]);start=colon+1;end=start+size
 if size<0 or end>=len(b):raise ValueError('truncated value')
 tag=b[end:end+1];raw=b[start:end]
 if tag==b',':val=raw
 elif tag==b';':val=raw.decode('utf8')
 elif tag==b'#':val=int(raw)
 elif tag==b'^':val=float(raw)
 elif tag==b'!':val=(raw==b'true')
 elif tag==b'~':val=None
 elif tag in (b']',b'}'):
  vals=[];cur=start
  while cur<end:
   v,cur=parse(b,cur,depth+1);vals.append(v)
  if cur!=end:raise ValueError('container length')
  val=vals if tag==b']' else dict(zip(vals[0::2],vals[1::2]))
 else:raise ValueError(('tag',tag,pos))
 return val,end+1

def text(v):return v.decode('utf8','replace') if isinstance(v,bytes) else str(v)
def headers(v):return {text(k).lower():text(x) for k,x in v}
def content(msg):
 b=msg.get('content',b'') or b''
 if isinstance(b,str):b=b.encode()
 h=headers(msg.get('headers',[]));encoding=h.get('content-encoding','')
 if encoding=='gzip':b=gzip.decompress(b)
 elif encoding=='deflate':b=zlib.decompress(b)
 return b,h

def read_all():
 b=Path(os.environ['ACR_BASELINE_FLOWS']).read_bytes();flows=[];pos=0
 while pos<len(b):
  f,pos=parse(b,pos);flows.append(f)
 return flows
