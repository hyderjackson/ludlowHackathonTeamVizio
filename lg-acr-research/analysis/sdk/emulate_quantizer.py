"""Execute actual V1 quantizer instructions on synthetic matrices offline."""
import hashlib,json,math,random,struct,sys
from pathlib import Path
from unicorn import *
from unicorn.arm_const import *
BASE=0x1000000;DATA=0x5000000;STACK=0x4000000;RETURN=0x3000000
raw=Path(sys.argv[1]).read_bytes();sha=hashlib.sha256(raw).hexdigest()
assert sha=='87adb105fddca9f7a704676d12426ebee9ac59202567924c0df184057e5315ad'
h=struct.unpack_from('<HHIIIIIHHHHHH',raw,16)
segments=[struct.unpack_from('<IIIIIIII',raw,h[4]+i*h[8]) for i in range(h[9])]
segments=[p for p in segments if p[0]==1]
def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]
def fb(v):return struct.unpack('<I',struct.pack('<f',v))[0]
def bf(v):return struct.unpack('<f',struct.pack('<I',v))[0]

class Lab:
 def __init__(self):
  self.mu=Uc(UC_ARCH_ARM,UC_MODE_ARM);mu=self.mu
  image=(max(p[2]+p[5] for p in segments)+4095)&~4095
  mu.mem_map(BASE,image,UC_PROT_READ|UC_PROT_EXEC)
  for p in segments:mu.mem_write(BASE+p[2],raw[p[1]:p[1]+p[4]])
  mu.mem_map(DATA,0x200000,UC_PROT_READ|UC_PROT_WRITE);mu.mem_map(STACK,0x20000,UC_PROT_READ|UC_PROT_WRITE)
  mu.mem_map(RETURN,4096,UC_PROT_READ|UC_PROT_EXEC)
  self.heap=DATA+0x10000;self.stat={'instructions':0,'guest_syscalls':0,'modeled_helpers':{}}
  mu.hook_add(UC_HOOK_CODE,self.code);mu.hook_add(UC_HOOK_INTR,self.intr)
 def alloc(self,n):
  assert 0<=n<0x10000
  p=self.heap;self.heap+=(n+15)&~15
  assert self.heap<DATA+0x200000
  return p
 def r32(self,p):return struct.unpack('<I',self.mu.mem_read(p,4))[0]
 def w32(self,p,v):self.mu.mem_write(p,struct.pack('<I',v&0xffffffff))
 def finish(self,v=None):
  if v is not None:self.mu.reg_write(UC_ARM_REG_R0,v)
  self.mu.reg_write(UC_ARM_REG_PC,self.mu.reg_read(UC_ARM_REG_LR))
 def code(self,uc,addr,size,ud):
  self.stat['instructions']+=1
  assert self.stat['instructions']<=3000000
  r=addr-BASE;mu=self.mu
  redirects={0x4d008:0xe69c4,0x4d25c:0xe6758,0x4b13c:0xe6744,
   0x4e598:0x110fb8,0x4a468:0x1110bc,0x4e5b0:0x111070,0x4abd8:0x11113c}
  if r in redirects:mu.reg_write(UC_ARM_REG_PC,BASE+redirects[r]);return
  helper={0x4c408:'allocate',0x4bc8c:'delete',0x4dbc4:'memset',0x4c174:'memcpy',0x4c1f4:'memmove',
   0x4d678:'float_gt',0x4d3c8:'float_lt',0x4b97c:'float_add',0x4b1a8:'float_sub',0x4c4a8:'float_mul'}
  if r in helper:
   name=helper[r];self.stat['modeled_helpers'][name]=self.stat['modeled_helpers'].get(name,0)+1
   a,b,c=[mu.reg_read(v) for v in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
   if name=='allocate':self.finish(self.alloc(a))
   elif name=='delete':self.finish()
   elif name=='memset':assert c<0x10000;mu.mem_write(a,bytes([b&255])*c);self.finish(a)
   elif name in ('memcpy','memmove'):assert c<0x10000;mu.mem_write(a,bytes(mu.mem_read(b,c)));self.finish(a)
   elif name=='float_gt':self.finish(int(bf(a)>bf(b)))
   elif name=='float_lt':self.finish(int(bf(a)<bf(b)))
   elif name=='float_add':self.finish(fb(bf(a)+bf(b)))
   elif name=='float_sub':self.finish(fb(bf(a)-bf(b)))
   elif name=='float_mul':self.finish(fb(bf(a)*bf(b)))
   return
  if not (0xe6744<=r<0xe6ce0 or 0x110e80<=r<0x111814):raise RuntimeError('outside allowed code '+hex(r))
 def intr(self,*args):self.stat['guest_syscalls']+=1;raise RuntimeError('guest syscall forbidden')
 def run(self,address,args,stackargs=()):
  mu=self.mu
  for reg,val in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):mu.reg_write(reg,val)
  sp=STACK+0x1ff00
  for i,val in enumerate(stackargs):self.w32(sp+i*4,val)
  mu.reg_write(UC_ARM_REG_SP,sp);mu.reg_write(UC_ARM_REG_LR,RETURN)
  mu.emu_start(BASE+address,RETURN,timeout=3000000,count=3000000)
  assert mu.reg_read(UC_ARM_REG_PC)==RETURN
  assert mu.reg_read(UC_ARM_REG_R0)==0
 def matrix(self,values,byte=False):
  p=self.alloc(12);rows=self.alloc(12*len(values));self.mu.mem_write(p,struct.pack('<III',rows,rows+len(values)*12,rows+len(values)*12))
  for i,row in enumerate(values):
   raw=bytes(row) if byte else struct.pack('<'+'f'*len(row),*row);r=self.alloc(len(raw));self.mu.mem_write(r,raw)
   self.mu.mem_write(rows+i*12,struct.pack('<III',r,r+len(raw),r+len(raw)))
  return p
 def quant(self,name,values,n):
  m=len(values);assert all(len(row)==m for row in values)
  values=[[f32(v) for v in row] for row in values]
  src=self.matrix(values);dst=self.matrix([[0xa5]*m for _ in range(m)],True)
  p=DATA+0x100;self.w32(p,n);self.w32(p+4,m);self.w32(p+8,m)
  self.run(0xe6b74,[dst,src,p,p+4],[p+8])
  threshold=sorted((abs(v) for row in values for v in row),reverse=True)[n] if n<m*m else 0
  expected=[[((1 if v>0 else 2) if abs(v)>threshold else 0) for v in row] for row in values]
  actual=[];rows=self.r32(dst)
  for i in range(m):actual.append(list(self.mu.mem_read(self.r32(rows+i*12),m)))
  assert actual==expected,(name,threshold,actual,expected)
  return {'name':name,'matrix_shape':[m,m],'n':n,'expected_threshold':threshold,'nonzero_quantized_symbols':sum(v!=0 for row in actual for v in row),
   'independent_reference_match':True,'quantized_sha256':hashlib.sha256(bytes(v for row in actual for v in row)).hexdigest(),
   'quantized_matrix':actual if m<=4 else '[omitted synthetic large fixture]',**self.stat}
 def wavelet(self,name,values):
  m=len(values);assert m>0 and m&(m-1)==0 and all(len(row)==m for row in values)
  values=[[f32(v) for v in row] for row in values]
  src=self.matrix(values);dst=self.matrix([[0]*m for _ in range(m)])
  self.run(0x111174,[dst,src,m,m])
  expected=[row[:] for row in values];active=m;c=bf(0x3f3504f3)
  while active>1:
   temp=[row[:] for row in expected];half=active//2
   for col in range(active):
    for i in range(half):
     a,b=expected[2*i][col],expected[2*i+1][col]
     temp[i][col]=f32(f32(a+b)*c);temp[i+half][col]=f32(f32(a-b)*c)
   for row in range(active):
    for i in range(half):
     a,b=temp[row][2*i],temp[row][2*i+1]
     expected[row][i]=f32(f32(a+b)*c);expected[row][i+half]=f32(f32(a-b)*c)
   active//=2
  actual=[];rows=self.r32(dst)
  for i in range(m):actual.append(list(struct.unpack('<'+'f'*m,self.mu.mem_read(self.r32(rows+i*12),m*4))))
  assert actual==expected,(name,actual,expected)
  return {'name':name,'matrix_shape':[m,m],'independent_reference_match':True,
   'output_matrix':actual if m<=4 else '[omitted synthetic large fixture]',**self.stat}

def haar_case(name,values):
 # Verify elementary col stage, where adjacent pairs become low/high halves.
 lab=Lab();a=lab.matrix([values]);b=lab.matrix([[0]*len(values)]);src=lab.r32(a);dst=lab.r32(b)
 lab.run(0x1110bc,[dst,src,len(values)])
 actual=list(struct.unpack('<'+'f'*len(values),lab.mu.mem_read(lab.r32(dst),len(values)*4)))
 c=bf(0x3f3504f3)
 expected=[f32(f32(values[i]+values[i+1])*c) for i in range(0,len(values),2)]+[f32(f32(values[i]-values[i+1])*c) for i in range(0,len(values),2)]
 assert actual==expected,(actual,expected)
 return {'name':name,'input':values,'output':actual,'constant':c,'independent_reference_match':True,**lab.stat}

rng=random.Random(20261020)
distinct=[[(-1 if i%2 else 1)*(i+1) for i in range(r*4,(r+1)*4)] for r in range(4)]
fixtures=[('distinct-signed',distinct,4),('distinct-signed-scaled-2',[[v*2 for v in row] for row in distinct],4),
 ('cutoff-ties',[[4,-4,3,-3],[2,-2,2,-2],[1,-1,0,0],[0,0,0,0]],5),
 ('all-tied',[[7,-7,7,-7]]*4,4),('all-zero',[[0]*4]*4,4),
 ('n-zero',[[i+1 for i in range(r*4,(r+1)*4)] for r in range(4)],0),
 ('n-total',[[(-1 if i%2 else 1)*(i+1) for i in range(r*4,(r+1)*4)] for r in range(4)],16),
 ('random-8x8',[[rng.uniform(-100,100) for _ in range(8)] for _ in range(8)],10),
 ('default-shaped-32x32',[[rng.uniform(-100,100) for _ in range(32)] for _ in range(32)],150)]
results={'sdk_sha256':sha,'scope':'actual quantizer/quickselect/swap, full square-power-of-two Haar transform and elementary Haar stage; finite synthetic inputs; modeled allocator, memory helpers and ARM soft-float operations',
 'quantizer_cases':[Lab().quant(*fixture) for fixture in fixtures],
 'haar_cases':[haar_case('alternating-sign',[1.,-2.,3.,-4.,5.,-6.,7.,-8.]),haar_case('constant',[2.]*8)],
 'haar_matrix_cases':[Lab().wavelet('distinct-4x4',distinct),Lab().wavelet('constant-4x4',[[2.]*4]*4),
   Lab().wavelet('random-8x8',[[rng.uniform(-100,100) for _ in range(8)] for _ in range(8)]),
   Lab().wavelet('default-shaped-32x32',[[rng.uniform(-100,100) for _ in range(32)] for _ in range(32)])]}
assert results['quantizer_cases'][0]['quantized_sha256']==results['quantizer_cases'][1]['quantized_sha256']
results['two_different_coefficient_matrices_same_quantization_verified']=True
print(json.dumps(results,indent=2))
