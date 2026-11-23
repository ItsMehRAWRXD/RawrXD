#!/usr/bin/env python3
"""Independent synthetic GGUF v3 writer/reader for native F32->F16 regression."""
import pathlib
import struct
import subprocess
import sys
import tempfile

U32=lambda x:struct.pack("<I",x)
U64=lambda x:struct.pack("<Q",x)
S=lambda s:U64(len(s.encode()))+s.encode()
ALIGN=32
def pad(b):
    return b+b"\0"*((-len(b))%ALIGN)

def fixture(path):
    values=[1.0,-2.0,0.5,65504.0]*16
    raw=struct.pack("<"+"f"*len(values),*values)
    quant=bytes(range(32))
    kv=S("general.architecture")+U32(8)+S("llama")
    kv+=S("general.alignment")+U32(4)+U32(ALIGN)
    names=[("blk.0.attn_q.weight",0,len(values),0),
           ("blk.0.attn_k.weight",6,32,len(raw))]
    hdr=b"GGUF"+U32(3)+U64(2)+U64(2)+kv
    for name,typ,n,offset in names:
        hdr+=S(name)+U32(1)+U64(n)+U32(typ)+U64(offset)
    path.write_bytes(pad(hdr)+raw+quant)
    return values,quant

def parse(path):
    b=path.read_bytes()
    assert b[:4]==b"GGUF"
    version,count,kv=struct.unpack_from("<IQQ",b,4)
    assert version==3 and count==2 and kv==2
    p=24
    def string():
        nonlocal p
        n=struct.unpack_from("<Q",b,p)[0];p+=8
        s=b[p:p+n].decode();p+=n
        return s
    metadata={}
    for _ in range(kv):
        key=string();t=struct.unpack_from("<I",b,p)[0];p+=4
        if t==8:metadata[key]=string()
        elif t==4:metadata[key]=struct.unpack_from("<I",b,p)[0];p+=4
        else:raise AssertionError("unexpected metadata")
    tensors={}
    for _ in range(count):
        name=string()
        rank=struct.unpack_from("<I",b,p)[0];p+=4
        dims=struct.unpack_from("<"+"Q"*rank,b,p);p+=rank*8
        typ,off=struct.unpack_from("<IQ",b,p);p+=12
        tensors[name]=(typ,dims,off)
    start=(p+31)&~31
    return b,start,metadata,tensors

def run(binary):
    with tempfile.TemporaryDirectory() as d:
        root=pathlib.Path(d)
        source=root/"input.gguf";target=root/"output.gguf"
        values,quant=fixture(source)
        subprocess.run([binary,str(source),str(target),"0"],check=True)
        original,orig_start,metadata,old=parse(source)
        b,start,metadata2,tensors=parse(target)
        assert metadata==metadata2
        assert tensors["blk.0.attn_q.weight"][:2]==(1,(len(values),))
        assert tensors["blk.0.attn_k.weight"][:2]==(6,(32,))
        off=tensors["blk.0.attn_q.weight"][2]
        f16=b[start+off:start+off+len(values)*2]
        assert list(struct.unpack("<"+"e"*len(values),f16))==values
        off=tensors["blk.0.attn_k.weight"][2]
        assert b[start+off:start+off+32]==quant
        assert len(b)<len(original)
        q8path=root/"q8.gguf"
        subprocess.run([binary,str(source),str(q8path),"0.01","q8_0"],check=True)
        qb,qs,qmeta,qt=parse(q8path)
        assert qmeta==metadata
        assert qt["blk.0.attn_q.weight"][:2]==(8,(len(values),))
        qoff=qt["blk.0.attn_q.weight"][2]
        for block in range(len(values)//32):
            start_block=qs+qoff+block*34
            scale=struct.unpack_from("<e",qb,start_block)[0]
            qsamples=struct.unpack_from("<32b",qb,start_block+2)
            for j,q in enumerate(qsamples):
                assert abs(scale*q-values[block*32+j])<=0.01
        assert qt["blk.0.attn_k.weight"][0]==6
        assert qb[qs+qt["blk.0.attn_k.weight"][2]:qs+qt["blk.0.attn_k.weight"][2]+32]==quant
        bad=root/"bad.gguf";bad.write_bytes(original[:24])
        failed=subprocess.run([binary,str(bad),str(root/"bad-out.gguf"),"0"],capture_output=True)
        assert failed.returncode!=0
        assert not (root/"bad-out.gguf").exists()
        print("GGUF synthetic conversion, metadata, quantized preservation and truncated-input tests PASS")

if __name__=="__main__":
    run(sys.argv[1])
