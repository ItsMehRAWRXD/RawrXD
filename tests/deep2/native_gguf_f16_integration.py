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
        subprocess.run([binary,str(source),str(q8path),"300","q8_0"],check=True)
        qb,qs,qmeta,qt=parse(q8path)
        assert qmeta==metadata
        assert qt["blk.0.attn_q.weight"][:2]==(8,(len(values),))
        qoff=qt["blk.0.attn_q.weight"][2]
        for block in range(len(values)//32):
            start_block=qs+qoff+block*34
            scale=struct.unpack_from("<e",qb,start_block)[0]
            qsamples=struct.unpack_from("<32b",qb,start_block+2)
            for j,q in enumerate(qsamples):
                assert abs(scale*q-values[block*32+j])<=300
        # FP16 input must also quantize correctly, with the same GGUF Q8_0 layout.
        f16q=root/"f16-to-q8.gguf"
        subprocess.run([binary,str(target),str(f16q),"300","q8_0"],check=True)
        fb,fs,fmeta,ft=parse(f16q)
        assert fmeta==metadata
        assert ft["blk.0.attn_q.weight"][0]==8
        foff=ft["blk.0.attn_q.weight"][2]
        for block in range(len(values)//32):
            scale=struct.unpack_from("<e",fb,fs+foff+block*34)[0]
            qsamples=struct.unpack_from("<32b",fb,fs+foff+block*34+2)
            assert all(abs(scale*q-values[block*32+j])<=300 for j,q in enumerate(qsamples))
        assert qt["blk.0.attn_k.weight"][0]==6
        assert qb[qs+qt["blk.0.attn_k.weight"][2]:qs+qt["blk.0.attn_k.weight"][2]+32]==quant
        # Independent GGML Q4_0 block decoding: low nibble j, high nibble j+16.
        for qsource in (source,target):
            q4path=root/("f32-q4.gguf" if qsource==source else "f16-q4.gguf")
            subprocess.run([binary,str(qsource),str(q4path),"10000","q4_0"],check=True)
            bb,bs,mm,tt=parse(q4path)
            assert mm==metadata
            assert tt["blk.0.attn_q.weight"][:2]==(2,(len(values),))
            off4=tt["blk.0.attn_q.weight"][2]
            for block in range(len(values)//32):
                start4=bs+off4+block*18
                scale=struct.unpack_from("<e",bb,start4)[0]
                # Largest absolute value in this fixture is positive;
                # GGML Q4_0 represents it with a negative scale and code -8.
                assert scale<0
                packed=bb[start4+2:start4+18]
                assert len(packed)==16
                for j in range(32):
                    nib=(packed[j] & 15) if j<16 else (packed[j-16]>>4)
                    assert abs(scale*(nib-8)-values[block*32+j])<=10000
            qoff4=tt["blk.0.attn_k.weight"][2]
            assert bb[bs+qoff4:bs+qoff4+32]==quant
        # BF16 (GGML type 30) source: independent BF16 payload construction.
        bf=root/"bf16.gguf"
        bfraw=b"".join(struct.pack("<H",struct.unpack("<I",struct.pack("<f",v))[0]>>16) for v in values)
        kv=S("general.architecture")+U32(8)+S("llama")
        kv+=S("general.alignment")+U32(4)+U32(ALIGN)
        header=b"GGUF"+U32(3)+U64(2)+U64(2)+kv
        header+=S("blk.0.attn_q.weight")+U32(1)+U64(len(values))+U32(30)+U64(0)
        header+=S("blk.0.attn_k.weight")+U32(1)+U64(32)+U32(6)+U64(len(bfraw))
        bf.write_bytes(pad(header)+bfraw+quant)
        for fmt,typ,block_bytes,limit in (("q8_0",8,34,300),("q4_0",2,18,10000)):
            dest=root/("bf16-"+fmt+".gguf")
            subprocess.run([binary,str(bf),str(dest),str(limit),fmt],check=True)
            cb,cs,cm,ct=parse(dest)
            assert cm==metadata
            assert ct["blk.0.attn_q.weight"][0]==typ
            assert ct["blk.0.attn_k.weight"][0]==6
            off=ct["blk.0.attn_q.weight"][2]
            for block in range(len(values)//32):
                p=cs+off+block*block_bytes
                scale=struct.unpack_from("<e",cb,p)[0]
                if fmt=="q8_0":
                    decoded=struct.unpack_from("<32b",cb,p+2)
                else:
                    packed=cb[p+2:p+18]
                    decoded=tuple((packed[j]&15)-8 if j<16 else (packed[j-16]>>4)-8 for j in range(32))
                assert all(abs(scale*q-values[block*32+j])<=limit for j,q in enumerate(decoded))
        # GGML Q5_0 independent reconstruction (16 low and 16 high nibbles
        # plus one high bit per element, little-endian 32-bit high-bit mask).
        for qsource in (source,target,bf):
            dest=root/(qsource.stem+"-q5.gguf")
            subprocess.run([binary,str(qsource),str(dest),"500","q5_0"],check=True)
            bb,bs,mm,tt=parse(dest)
            assert mm==metadata
            assert tt["blk.0.attn_q.weight"][0]==6
            off=tt["blk.0.attn_q.weight"][2]
            for block in range(len(values)//32):
                p=bs+off+block*22
                scale=struct.unpack_from("<e",bb,p)[0]
                high=struct.unpack_from("<I",bb,p+2)[0]
                packed=bb[p+6:p+22]
                assert len(packed)==16
                for j in range(32):
                    lo=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                    code=lo|(((high>>j)&1)<<4)
                    assert abs(scale*(code-16)-values[block*32+j])<=500
            offq=tt["blk.0.attn_k.weight"][2]
            assert bb[bs+offq:bs+offq+32]==quant
        # Independently decode Q4_1: half delta, half minimum, packed nibbles.
        for qsource in (source,target,bf):
            dest=root/(qsource.stem+"-q41.gguf")
            subprocess.run([binary,str(qsource),str(dest),"10000","q4_1"],check=True)
            bb,bs,mm,tt=parse(dest)
            assert mm==metadata
            assert tt["blk.0.attn_q.weight"][0]==3
            off=tt["blk.0.attn_q.weight"][2]
            for block in range(len(values)//32):
                p=bs+off+block*20
                delta,minimum=struct.unpack_from("<ee",bb,p)
                packed=bb[p+4:p+20]
                assert len(packed)==16
                for j in range(32):
                    code=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                    assert abs(minimum+delta*code-values[block*32+j])<=10000
            offq=tt["blk.0.attn_k.weight"][2]
            assert bb[bs+offq:bs+offq+32]==quant
        bad=root/"bad.gguf";bad.write_bytes(original[:24])
        failed=subprocess.run([binary,str(bad),str(root/"bad-out.gguf"),"0"],capture_output=True)
        assert failed.returncode!=0
        assert not (root/"bad-out.gguf").exists()
        print("GGUF synthetic conversion, metadata, quantized preservation and truncated-input tests PASS")

if __name__=="__main__":
    run(sys.argv[1])
