#!/usr/bin/env python3
"""RawrXD REAP GGUF expert/router remapper. Python 3 standard library only.

Rebuild from ORIGINAL GGUF and an explicit JSON selection manifest. Does not
invent or reconstruct missing weights. Supports block-quantized expert tensors
only when expert is the outermost (last GGUF dimension) axis.

Manifest example:
{"experts":{"0":[3,7,10],"1":[2,5,9]},"default":[3,7,10]}
All MoE layers must use the same retained expert count. Use --audit first.
"""
import argparse, json, os, re, struct, sys, tempfile
from pathlib import Path

U8,U16,U32,U64,I8,I16,I32,I64,F32,F64,BOOL,STRING,ARRAY=range(13)
SIZES={U8:1,U16:2,U32:4,U64:8,I8:1,I16:2,I32:4,I64:8,F32:4,F64:8,BOOL:1}
# GGML types: (elements per block, bytes per block). Reject unknown types.
TYPES={0:(1,4),1:(1,2),2:(32,18),3:(32,20),6:(32,22),7:(32,24),8:(32,34),9:(32,40),10:(256,84),11:(256,110),12:(256,144),13:(256,176),14:(256,210),15:(256,292),16:(256,66),17:(256,74),18:(256,98),19:(256,50),20:(256,82),21:(256,136),22:(256,164),23:(256,210),24:(256,292),25:(256,64),26:(256,128),27:(256,256),28:(256,512)}
# Exact GGML type codes vary by ggml version. Only default-enable well-known types.
SAFE_TYPES={0:(1,4),1:(1,2),2:(32,18),3:(32,20),6:(32,22),7:(32,24),8:(32,34),9:(32,40),10:(256,84),11:(256,110),12:(256,144),13:(256,176),14:(256,210),15:(256,292)}

def rd(f,n):
 b=f.read(n)
 if len(b)!=n: raise ValueError('Unexpected EOF')
 return b
def u32(f): return struct.unpack('<I',rd(f,4))[0]
def u64(f): return struct.unpack('<Q',rd(f,8))[0]
def string(f):
 n=u64(f)
 if n>1<<25: raise ValueError('Unreasonable string size')
 return rd(f,n).decode('utf-8')
def encstr(s):
 b=s.encode('utf-8');return struct.pack('<Q',len(b))+b
def readval(f,t):
 if t==STRING:return string(f)
 if t==ARRAY:
  sub=u32(f); n=u64(f)
  if n>100_000_000:raise ValueError('Unreasonable array')
  return (sub,[readval(f,sub) for _ in range(n)])
 if t in SIZES:
  raw=rd(f,SIZES[t]); return struct.unpack({U8:'<B',U16:'<H',U32:'<I',U64:'<Q',I8:'<b',I16:'<h',I32:'<i',I64:'<q',F32:'<f',F64:'<d',BOOL:'<?'}[t],raw)[0]
 raise ValueError('Unsupported metadata type '+str(t))
def writeval(t,v):
 if t==STRING:return encstr(v)
 if t==ARRAY:
  sub,items=v;return struct.pack('<IQ',sub,len(items))+b''.join(writeval(sub,x) for x in items)
 return struct.pack({U8:'<B',U16:'<H',U32:'<I',U64:'<Q',I8:'<b',I16:'<h',I32:'<i',I64:'<q',F32:'<f',F64:'<d',BOOL:'<?'}[t],v)
def prod(xs):
 v=1
 for x in xs:v*=x
 return v
def size(dims,typ):
 if typ not in SAFE_TYPES:raise ValueError(f'Unsupported GGML type {typ}; refusing to corrupt tensor')
 block,bs=SAFE_TYPES[typ]; n=prod(dims)
 if n%block:raise ValueError(f'Tensor shape {dims} not divisible by quant block {block}')
 return n//block*bs

def parse(path):
 with open(path,'rb') as f:
  if rd(f,4)!=b'GGUF':raise ValueError('Not GGUF')
  ver=u32(f)
  if ver!=3:raise ValueError('Only GGUF v3 supported')
  nt=u64(f);nk=u64(f)
  if nt>2_000_000 or nk>1_000_000:raise ValueError('Unreasonable counts')
  kv=[]
  for _ in range(nk):
   key=string(f); typ=u32(f); kv.append([key,typ,readval(f,typ)])
  tensors=[]
  for _ in range(nt):
   name=string(f);nd=u32(f)
   if nd>8:raise ValueError('Unreasonable tensor rank')
   dims=[u64(f) for _ in range(nd)];typ=u32(f);off=u64(f)
   tensors.append({'name':name,'dims':dims,'typ':typ,'off':off})
  pos=f.tell(); align=next((int(v) for k,t,v in kv if k=='general.alignment'),32)
  if align<1 or align>4096 or align&(align-1):raise ValueError('Invalid alignment')
  data=(pos+align-1)//align*align
  filelen=os.fstat(f.fileno()).st_size
  for t in tensors:
   sz=size(t['dims'],t['typ'])
   if data+t['off']+sz>filelen:raise ValueError('Tensor outside file: '+t['name'])
  return kv,tensors,data,align

def layer(name):
 m=re.match(r'blk\.(\d+)\.',name)
 return m.group(1) if m else None

def classify(t,old):
 name=t['name'];dims=t['dims']; n=layer(name)
 if n is None:return None
 # Conservative naming: GGUF llama.cpp common MoE names.
 if re.search(r'ffn_gate_inp\.weight$',name):
  axes=[i for i,d in enumerate(dims) if d==old]
  if len(axes)!=1:raise ValueError('Ambiguous router expert axis: '+name)
  return ('router',axes[0])
 if re.search(r'ffn_(?:gate|up|down)_exps\.weight$',name):
  if len(dims)<3 or dims[-1]!=old:raise ValueError('Expected outermost expert axis: '+name)
  return ('experts',len(dims)-1)
 return None

def select_for(manifest,layer_id):
 ex=manifest.get('experts',{})
 return ex.get(layer_id,manifest.get('default'))

def transform(f,src,old,selected,kind,axis):
 dims=src['dims'];typ=src['typ']; block,bs=SAFE_TYPES[typ]
 newdims=list(dims);newdims[axis]=len(selected)
 if axis==len(dims)-1:
  # Each expert is one contiguous slab; block alignment must hold per slab.
  slab=prod(dims[:-1]);
  if slab%block:raise ValueError('Expert slab not quant block aligned: '+src['name'])
  chunk=slab//block*bs
  for idx in selected:
   f.seek(old+src['off']+idx*chunk)
   yield rd(f,chunk)
 elif axis==0:
  # Expert entries are interleaved along fastest dimension. Only unquantized.
  if block!=1:raise ValueError('Quantized fastest-axis router cannot be safely remapped: '+src['name'])
  width=dims[0];outer=prod(dims[1:]);unit=bs
  for j in range(outer):
   f.seek(old+src['off']+j*width*unit)
   row=rd(f,width*unit)
   yield b''.join(row[i*unit:(i+1)*unit] for i in selected)
 else:raise ValueError('Expert axis not safely supported: '+src['name'])

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--original',required=True)
 ap.add_argument('--manifest')
 ap.add_argument('--output')
 ap.add_argument('--audit',action='store_true')
 a=ap.parse_args()
 if not a.audit and (not a.manifest or not a.output):ap.error('Repair requires --manifest and --output')
 if a.output and Path(a.original).resolve()==Path(a.output).resolve():ap.error('Never overwrite original')
 kv,ts,data,align=parse(a.original)
 counts=[(k,int(v)) for k,t,v in kv if k.endswith('.expert_count') and t in (U32,U64,I32,I64)]
 if len(counts)!=1:raise ValueError('Expected exactly one *.expert_count metadata key: '+str(counts))
 key,old=counts[0]
 targets=[]
 for t in ts:
  c=classify(t,old)
  if c:targets.append((t,c[0],c[1]))
 print(json.dumps({'original':a.original,'expert_count':old,'expert_tensors':len(targets),'tensor_names':[x[0]['name'] for x in targets[:20]]},indent=2))
 if a.audit:return
 manifest=json.loads(Path(a.manifest).read_text(encoding='utf-8'))
 layers=sorted({layer(t['name']) for t,_,_ in targets})
 if not layers:raise ValueError('No recognized expert tensors; cannot repair')
 picks={}
 for lid in layers:
  ids=select_for(manifest,lid)
  if not isinstance(ids,list) or not ids:raise ValueError('Missing selected experts for layer '+lid)
  if any(type(i)!=int or i<0 or i>=old for i in ids) or len(set(ids))!=len(ids):raise ValueError('Invalid/duplicate expert IDs at layer '+lid)
  picks[lid]=ids
 if len({len(v) for v in picks.values()})!=1:raise ValueError('Different retained counts per layer unsupported')
 newcount=len(next(iter(picks.values())))
 for t,kind,axis in targets:
  if kind=='router' and t['typ'] not in (0,1):raise ValueError('Router must be F32/F16: '+t['name'])
 # Fail closed: require both router and expert tensor families for every layer.
 for lid in layers:
  kinds={kind for t,kind,_ in targets if layer(t['name'])==lid}
  if kinds!={'router','experts'}:raise ValueError('Missing router/expert tensors at layer '+lid)
 # Also refuse suspicious unrecognized expert-named tensors, which may need remapping.
 known={t['name'] for t,_,_ in targets}
 suspicious=[t['name'] for t in ts if layer(t['name']) in picks and re.search(r'(?:exps|expert|ffn_gate_inp)',t['name']) and t['name'] not in known]
 if suspicious:raise ValueError('Unrecognized expert-related tensors: '+repr(suspicious[:15]))
 for item in kv:
  if item[0]==key:item[2]=newcount
 # We must write new tensor offsets. Metadata/tensor header is generated first.
 targetmap={t['name']:(kind,axis) for t,kind,axis in targets}
 newts=[]; offset=0
 for t in ts:
  d=list(t['dims']); c=targetmap.get(t['name'])
  if c:d[c[1]]=newcount
  offset=(offset+align-1)//align*align
  newts.append((t,d,offset))
  offset+=size(d,t['typ'])
 header=b'GGUF'+struct.pack('<IQQ',3,len(ts),len(kv))
 for k,typ,v in kv:header+=encstr(k)+struct.pack('<I',typ)+writeval(typ,v)
 for t,d,off in newts:
  header+=encstr(t['name'])+struct.pack('<I',len(d))+b''.join(struct.pack('<Q',x) for x in d)+struct.pack('<IQ',t['typ'],off)
 header+=b'\0'*((-len(header))%align)
 out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
 if out.exists():raise ValueError('Output already exists; refusing overwrite')
 temp=None
 try:
  with tempfile.NamedTemporaryFile(dir=out.parent,prefix='.reap-repair-',suffix='.tmp',delete=False) as dst,open(a.original,'rb') as src:
   temp=dst.name;dst.write(header);cur=0
   for t,d,off in newts:
    dst.write(b'\0'*(off-cur));cur=off
    c=targetmap.get(t['name'])
    if c:
     chunks=transform(src,t,data,picks[layer(t['name'])],*c)
    else:
     src.seek(data+t['off']); remaining=size(t['dims'],t['typ'])
     def copychunks():
      nonlocal remaining
      while remaining:
       b=rd(src,min(4*1024*1024,remaining));remaining-=len(b);yield b
     chunks=copychunks()
    for chunk in chunks:dst.write(chunk);cur+=len(chunk)
   dst.flush();os.fsync(dst.fileno())
  os.replace(temp,out)
 except BaseException:
  if temp and os.path.exists(temp):os.unlink(temp)
  raise
 print('REPAIRED_GGUF:',out,'EXPERT_COUNT:',newcount,'BYTES:',out.stat().st_size)
 print('IMPORTANT: Router/weights are selected from ORIGINAL; test quality and routing before promotion.')
if __name__=='__main__':
 try:main()
 except Exception as e:print('REPAIR_FAILED:',e,file=sys.stderr);sys.exit(2)
