"""Bounded offline SDK V1 signature+record experiment. Only synthetic data."""
import hashlib,json,struct,sys
from pathlib import Path
from unicorn import *
from unicorn.arm_const import *

BASE=0x1000000;DATA=0x5000000;STACK=0x4000000;RETURN=0x3000000
RANGES=[(0xf5a40,0xf5ca0),(0xf5ca4,0xf5cc0),(0xf74b8,0xf7620),(0xe44bc,0xe4518)]
REDIRECT={0x4dcb0:0xf74b8,0x4a73c:0xf7560,0x4cf50:0xe44bc}
raw=Path(sys.argv[1]).read_bytes()
sha=hashlib.sha256(raw).hexdigest()
assert sha=='87adb105fddca9f7a704676d12426ebee9ac59202567924c0df184057e5315ad'
h=struct.unpack_from('<HHIIIIIHHHHHH',raw,16)
segments=[struct.unpack_from('<IIIIIIII',raw,h[4]+i*h[8]) for i in range(h[9])]
segments=[p for p in segments if p[0]==1]
def virtual(addr,n):
 p=next(p for p in segments if p[2]<=addr and addr+n<=p[2]+p[4]);return raw[p[1]+addr-p[2]:p[1]+addr-p[2]+n]
table=0xe4510+struct.unpack('<I',virtual(0xe4518,4))[0]
perms=[struct.unpack('<2048H',virtual(table+i*4096,4096)) for i in range(72)]

def case(frame,enabled=True):
 mu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
 image=(max(p[2]+p[5] for p in segments)+4095)&~4095
 mu.mem_map(BASE,image,UC_PROT_READ|UC_PROT_EXEC)
 for p in segments:mu.mem_write(BASE+p[2],raw[p[1]:p[1]+p[4]])
 mu.mem_map(DATA,0x20000,UC_PROT_READ|UC_PROT_WRITE);mu.mem_map(STACK,0x20000,UC_PROT_READ|UC_PROT_WRITE)
 mu.mem_map(RETURN,4096,UC_PROT_READ|UC_PROT_EXEC)
 stat={'instructions':0,'guest_syscalls':0,'modeled_memcpy':0,'modeled_realloc':0}
 def w32(p,v):mu.mem_write(p,struct.pack('<I',v&0xffffffff))
 def r32(p):return struct.unpack('<I',mu.mem_read(p,4))[0]
 def code(uc,addr,size,ud):
  stat['instructions']+=1
  if stat['instructions']>1000000:raise RuntimeError('instruction cap')
  rel=addr-BASE
  if rel in REDIRECT:mu.reg_write(UC_ARM_REG_PC,BASE+REDIRECT[rel]);return
  if rel in (0x4c174,0x4e78c):
   a,b,c=[mu.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2)]
   if rel==0x4c174:
    if c>10000:raise RuntimeError('copy cap')
    mu.mem_write(a,bytes(mu.mem_read(b,c)));stat['modeled_memcpy']+=1
   else:
    if b>10000 or a not in (0,DATA+0x10000):raise RuntimeError('realloc cap')
    a=DATA+0x10000;stat['modeled_realloc']+=1
   mu.reg_write(UC_ARM_REG_R0,a);mu.reg_write(UC_ARM_REG_PC,mu.reg_read(UC_ARM_REG_LR));return
  if not any(a<=rel<b for a,b in RANGES):raise RuntimeError('outside allowed code '+hex(rel))
 def intr(*args):stat['guest_syscalls']+=1;raise RuntimeError('guest syscall forbidden')
 mu.hook_add(UC_HOOK_CODE,code);mu.hook_add(UC_HOOK_INTR,intr)
 obj=DATA+0x100;config=DATA+0x200;nested=DATA+0x1000;packed=DATA+0x2000;sig=DATA+0x3000
 w32(obj,config);w32(config+0xc,8);w32(config+0x1c,128);w32(config+0x30,72)
 mu.mem_write(config+0x38,struct.pack('<IIII',72,2048,0,0))
 w32(obj+0x20,nested);mu.mem_write(obj+0x38,struct.pack('<III',packed,packed+256,packed+256))
 mu.mem_write(obj+0x44,struct.pack('<III',sig,sig+72,sig+72))
 mu.mem_write(obj+0x50,bytes([enabled,1]));mu.mem_write(sig,bytes([0xa5]*72))
 vals=[[(i*17+j*7+(j>>3))%4 for j in range(128)] for i in range(8)]
 for i,row in enumerate(vals):
  ptr=DATA+0x4000+i*256;mu.mem_write(ptr,bytes(row));mu.mem_write(nested+i*12,struct.pack('<III',ptr,ptr+128,ptr+128))
 source=[]
 for row in vals:source.extend(row)
 expected_packed=bytes(sum(source[i+j]<<(6-2*j) for j in range(4)) for i in range(0,len(source),4))
 expected_sig=bytes(next((rank&255 for rank,bit in enumerate(row) if expected_packed[bit//8]&(128>>(bit%8))),0xa5) for row in perms)
 mu.reg_write(UC_ARM_REG_R0,obj);mu.reg_write(UC_ARM_REG_R1,frame);mu.reg_write(UC_ARM_REG_SP,STACK+0x1ff00);mu.reg_write(UC_ARM_REG_LR,RETURN)
 mu.emu_start(BASE+0xf5a40,RETURN,timeout=2000000,count=1000000)
 assert mu.reg_read(UC_ARM_REG_PC)==RETURN
 length=r32(obj+0x58);actual=bytes(mu.mem_read(r32(obj+0x54),length)) if length else b''
 expected=struct.pack('<I',(frame-1)&0xffffffff)+expected_sig if enabled else b''
 assert actual==expected
 if enabled:assert bytes(mu.mem_read(packed,256))==expected_packed
 # Execute actual populateFingerprint to verify emitted pointer/length.
 out=DATA+0x8000;mu.reg_write(UC_ARM_REG_R0,obj);mu.reg_write(UC_ARM_REG_R1,out);mu.reg_write(UC_ARM_REG_LR,RETURN)
 mu.emu_start(BASE+0xf5ca4,RETURN,timeout=200000,count=100)
 assert r32(out)==length and r32(out+4)==r32(obj+0x54)
 return {'input_frame':frame,'enabled':enabled,'output_length':length,'decoded_output_index':struct.unpack_from('<I',actual)[0] if actual else None,
   'independent_signature_and_record_match':True,**stat}

result={'sdk_sha256':sha,'scope':'actual generateSignature, generateMinHash, Permute::getOrderValue, SessionV1::generateFingerprint and populateFingerprint; modeled memcpy/realloc; synthetic 8x128 two-bit input symbols; no audio pipeline or networking',
 'cases':[case(v) for v in (0,1,74,0x12345679)]+[case(74,False)]}
print(json.dumps(result,indent=2))
