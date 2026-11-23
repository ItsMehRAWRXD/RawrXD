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
    assert version==3 and 1<=count<=2 and kv==2
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
        # The unified streaming F16 path must reject a tensor with even
        # one non-representable F32 value under a zero-error budget.
        inexact=root/"inexact-f32.gguf"
        altered=bytearray(original)
        struct.pack_into("<f",altered,orig_start,1.0001)
        inexact.write_bytes(altered)
        unchanged=root/"inexact-f32-output.gguf"
        subprocess.run([binary,str(inexact),str(unchanged),"0","f16"],check=True)
        ub,us,um,ut=parse(unchanged)
        assert ut["blk.0.attn_q.weight"][0]==0
        assert ub[us+ut["blk.0.attn_q.weight"][2]:us+ut["blk.0.attn_q.weight"][2]+4]==struct.pack("<f",1.0001)
        assert ut["blk.0.attn_k.weight"][0]==6
        # Nonfinite source weights must never be silently quantized.  Every
        # format must retain the original tensor type and exact F32 payload.
        nonfinite=root/"nonfinite.gguf"
        broken=bytearray(original)
        struct.pack_into("<I",broken,orig_start,0x7fc00001)
        nonfinite.write_bytes(broken)
        for fmt in ("f16","q8_0","q5_1","q5_0","q4_1","q4_0"):
            dest=root/("nonfinite-"+fmt+".gguf")
            subprocess.run([binary,str(nonfinite),str(dest),"10000",fmt],check=True)
            nb,ns,nm,nt=parse(dest)
            assert nt["blk.0.attn_q.weight"][0]==0
            off=nt["blk.0.attn_q.weight"][2]
            assert nb[ns+off:ns+off+len(values)*4]==broken[orig_start:orig_start+len(values)*4]
            assert nt["blk.0.attn_k.weight"][0]==6
        # BF16 uses round-to-nearest-even and preserves the GGML type 30.
        bfout=root/"f32-to-bf16.gguf"
        subprocess.run([binary,str(source),str(bfout),"300","bf16"],check=True)
        bfb,bfs,bfm,bft=parse(bfout)
        assert bfm==metadata
        assert bft["blk.0.attn_q.weight"][0]==30
        for j,value in enumerate(values):
            stored=struct.unpack_from("<H",bfb,bfs+bft["blk.0.attn_q.weight"][2]+2*j)[0]
            restored=struct.unpack("<f",struct.pack("<I",stored<<16))[0]
            assert abs(restored-value)<=300
        assert bft["blk.0.attn_k.weight"][0]==6
        bfstrict=root/"strict-bf16.gguf"
        subprocess.run([binary,str(inexact),str(bfstrict),"0","bf16"],check=True)
        sb,ss,sm,st=parse(bfstrict)
        assert st["blk.0.attn_q.weight"][0]==0
        assert sb[ss+st["blk.0.attn_q.weight"][2]:ss+st["blk.0.attn_q.weight"][2]+4]==struct.pack("<f",1.0001)
        # BF16 midpoint ties round to even, including an odd upper half.
        ties=root/"bf16-ties.gguf"
        tie_bits=[0x3f808000,0x3f818000,0xbf808000,0xbf818000]*8
        tie_raw=b"".join(struct.pack("<I",x) for x in tie_bits)
        kv=S("general.architecture")+U32(8)+S("llama")
        kv+=S("general.alignment")+U32(4)+U32(ALIGN)
        tie_header=b"GGUF"+U32(3)+U64(1)+U64(2)+kv
        tie_header+=S("blk.0.attn_q.weight")+U32(1)+U64(32)+U32(0)+U64(0)
        ties.write_bytes(pad(tie_header)+tie_raw)
        ties_out=root/"bf16-ties-output.gguf"
        subprocess.run([binary,str(ties),str(ties_out),"1","bf16"],check=True)
        tb,ts,tm,tt=parse(ties_out)
        assert tt["blk.0.attn_q.weight"][0]==30
        actual=struct.unpack_from("<32H",tb,ts+tt["blk.0.attn_q.weight"][2])
        assert actual==(0x3f80,0x3f82,0xbf80,0xbf82)*8
        # Auto chooses the smallest precision-valid format per tensor, while
        # preserving existing quantized payloads and GGUF metadata.
        auto_loose=root/"auto-loose.gguf"
        subprocess.run([binary,str(source),str(auto_loose),"300","auto"],check=True)
        ab,ast,am,at=parse(auto_loose)
        assert am==metadata
        assert at["blk.0.attn_q.weight"][0]==2  # Q4_0 is the smallest candidate
        # Decode the emitted GGML Q4_0 blocks independently and check the
        # requested error bound, not merely the advertised tensor type.
        qoff=ast+at["blk.0.attn_q.weight"][2]
        for block_index in range(len(values)//32):
            p=qoff+18*block_index
            scale=struct.unpack_from("<e",ab,p)[0]
            for j in range(32):
                packed=ab[p+2+(j%16)]
                code=((packed>>4) if j>=16 else (packed&15))-8
                assert abs(scale*code-values[32*block_index+j])<=300

        assert at["blk.0.attn_k.weight"][0]==6
        # Both tensor offsets must describe bytes inside the final GGUF.
        assert ast+at["blk.0.attn_q.weight"][2]+(len(values)//32)*18<=len(ab)
        assert ast+at["blk.0.attn_k.weight"][2]+len(quant)==len(ab)

        assert ab[ast+at["blk.0.attn_k.weight"][2]:ast+at["blk.0.attn_k.weight"][2]+32]==quant
        auto_strict=root/"auto-strict.gguf"
        subprocess.run([binary,str(source),str(auto_strict),"0","auto"],check=True)
        sb,ss,sm,st=parse(auto_strict)
        assert sm==metadata
        assert st["blk.0.attn_q.weight"][0]==1  # lossless F16 fallback
        assert st["blk.0.attn_k.weight"][0]==6
        auto_inexact=root/"auto-inexact.gguf"
        subprocess.run([binary,str(inexact),str(auto_inexact),"0","auto"],check=True)
        ib,ins,im,it=parse(auto_inexact)
        assert it["blk.0.attn_q.weight"][0]==0  # no lossy encoding permitted
        assert struct.unpack_from("<f",ib,ins+it["blk.0.attn_q.weight"][2])[0]==struct.unpack("<f",struct.pack("<f",1.0001))[0]
        # F16 cannot represent 65536, but BF16 can represent it exactly.
        # Auto must choose BF16 for this tensor under zero absolute error.
        wide=root/"auto-bf16-source.gguf"
        wide_bytes=bytearray(original)
        for j in range(3,len(values),4):
            struct.pack_into("<f",wide_bytes,orig_start+4*j,65536.0)
        wide.write_bytes(wide_bytes)
        wide_out=root/"auto-bf16-output.gguf"
        subprocess.run([binary,str(wide),str(wide_out),"0","auto"],check=True)
        wb,ws,wm,wt=parse(wide_out)
        assert wt["blk.0.attn_q.weight"][0]==30
        assert wt["blk.0.attn_k.weight"][0]==6
        woff=ws+wt["blk.0.attn_q.weight"][2]
        assert struct.unpack_from("<H",wb,woff+3*2)[0]==0x4780
        assert wb[ws+wt["blk.0.attn_k.weight"][2]:ws+wt["blk.0.attn_k.weight"][2]+32]==quant
        # Invalid precision budgets must fail before publishing any model.
        for bad in ("0.1oops","nan","inf","-0.01",""):
            bad_output=root/("bad-tolerance-"+str(len(bad))+("-neg" if bad.startswith("-") else "")+".gguf")
            result=subprocess.run([binary,str(source),str(bad_output),bad,"auto"],
                                  capture_output=True)
            assert result.returncode!=0, ("accepted invalid tolerance",bad)
            assert not bad_output.exists(), ("published invalid conversion",bad)
        # GGML type 28 F64: auto narrows to F32 only when the entire tensor
        # meets the requested absolute-error bound, with exact GGUF offsets.
        f64=root/"f64-source.gguf"
        doubles=[1.0,-2.0,0.5,65504.0]*16
        f64raw=struct.pack("<"+"d"*len(doubles),*doubles)
        kv=S("general.architecture")+U32(8)+S("llama")
        kv+=S("general.alignment")+U32(4)+U32(ALIGN)
        header=b"GGUF"+U32(3)+U64(1)+U64(2)+kv
        header+=S("blk.0.attn_q.weight")+U32(1)+U64(len(doubles))+U32(28)+U64(0)
        f64.write_bytes(pad(header)+f64raw)
        f64_out=root/"f64-auto.gguf"
        subprocess.run([binary,str(f64),str(f64_out),"0","auto"],check=True)
        fd,fs,fm,ft=parse(f64_out)
        assert ft["blk.0.attn_q.weight"][:2]==(0,(len(doubles),))
        assert len(fd)-fs==len(doubles)*4
        assert struct.unpack_from("<"+"f"*len(doubles),fd,fs)==tuple(doubles)
        # Explicit F32 mode only narrows F64 and leaves existing F32 intact.
        f64_explicit=root/"f64-explicit-f32.gguf"
        subprocess.run([binary,str(f64),str(f64_explicit),"0","f32"],check=True)
        ed,es,em,et=parse(f64_explicit)
        assert et["blk.0.attn_q.weight"][0]==0
        assert ed[es:]==fd[fs:]
        f32_unchanged=root/"explicit-f32-preserves-f32.gguf"
        subprocess.run([binary,str(source),str(f32_unchanged),"300","f32"],check=True)
        assert f32_unchanged.read_bytes()==source.read_bytes()
        # A single F64 value not exactly representable in F32 must prevent
        # conversion under a strict zero-error budget.
        f64_inexact=root/"f64-inexact.gguf"
        altered=bytearray(f64.read_bytes())
        _,f64start,_,_=parse(f64)
        struct.pack_into("<d",altered,f64start,1.0+2**-40)
        f64_inexact.write_bytes(altered)
        f64_preserved=root/"f64-preserved.gguf"
        subprocess.run([binary,str(f64_inexact),str(f64_preserved),"0","auto"],check=True)
        pd,ps,pm,pt=parse(f64_preserved)
        assert pt["blk.0.attn_q.weight"][0]==28
        assert pd[ps:ps+len(f64raw)]==altered[f64start:f64start+len(f64raw)]
        # Strict Q8_0 error budget must retain F32, including all payload bytes.
        strictq=root/"strict-q8.gguf"
        subprocess.run([binary,str(source),str(strictq),"0","q8_0"],check=True)
        sq,ss,sm,st=parse(strictq)
        assert sm==metadata
        assert st["blk.0.attn_q.weight"][0]==0
        original_raw=struct.pack("<"+"f"*len(values),*values)
        assert sq[ss+st["blk.0.attn_q.weight"][2]:ss+st["blk.0.attn_q.weight"][2]+len(original_raw)]==original_raw
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
        # Descriptor order intentionally differs from physical tensor order.
        # GGUF permits this; rewriting must keep offsets and payloads consistent.
        swapped=root/"reordered.gguf"
        kv=S("general.architecture")+U32(8)+S("llama")
        kv+=S("general.alignment")+U32(4)+U32(ALIGN)
        raw=struct.pack("<"+"f"*len(values),*values)
        header=b"GGUF"+U32(3)+U64(2)+U64(2)+kv
        header+=S("blk.0.attn_k.weight")+U32(1)+U64(32)+U32(6)+U64(len(raw))
        header+=S("blk.0.attn_q.weight")+U32(1)+U64(len(values))+U32(0)+U64(0)
        swapped.write_bytes(pad(header)+raw+quant)
        for fmt,typ,tolerance in (("f16",1,"0"),("q8_0",8,"300"),("q5_0",6,"500"),("q5_1",7,"10000"),("q4_1",3,"10000"),("q4_0",2,"10000")):
            dest=root/("reordered-"+fmt+".gguf")
            subprocess.run([binary,str(swapped),str(dest),tolerance,fmt],check=True)
            data,ds,meta,desc=parse(dest)
            assert meta==metadata
            assert desc["blk.0.attn_q.weight"][0]==typ
            assert desc["blk.0.attn_q.weight"][2]==0
            assert desc["blk.0.attn_k.weight"][2]>0
            offset=desc["blk.0.attn_k.weight"][2]
            assert data[ds+offset:ds+offset+32]==quant
        # Independent Q5_1 decoding for F32, FP16 and BF16 inputs.
        for qsource in (source,target,bf):
            dest=root/(qsource.stem+"-q51.gguf")
            subprocess.run([binary,str(qsource),str(dest),"10000","q5_1"],check=True)
            bb,bs,mm,tt=parse(dest)
            assert mm==metadata
            assert tt["blk.0.attn_q.weight"][0]==7
            off=tt["blk.0.attn_q.weight"][2]
            for block in range(len(values)//32):
                p=bs+off+block*24
                delta,minimum=struct.unpack_from("<ee",bb,p)
                high=struct.unpack_from("<I",bb,p+4)[0]
                packed=bb[p+8:p+24]
                assert len(packed)==16
                for j in range(32):
                    low=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                    code=low|(((high>>j)&1)<<4)
                    assert abs(minimum+delta*code-values[block*32+j])<=10000
            offq=tt["blk.0.attn_k.weight"][2]
            assert bb[bs+offq:bs+offq+32]==quant
        # A strict zero-error budget must never silently fall back to FP16
        # while the caller requested a quantized format.
        for fmt in ("q4_1","q5_1"):
            dest=root/("strict-"+fmt+".gguf")
            subprocess.run([binary,str(source),str(dest),"0",fmt],check=True)
            data,ds,meta,desc=parse(dest)
            assert meta==metadata
            assert desc["blk.0.attn_q.weight"][0]==0
            off=desc["blk.0.attn_q.weight"][2]
            assert data[ds+off:ds+off+len(values)*4]==struct.pack("<"+"f"*len(values),*values)
            offq=desc["blk.0.attn_k.weight"][2]
            assert data[ds+offq:ds+offq+32]==quant
        # 2D tensor with 16-wide rows must not be quantized by flattening
        # across row boundaries, even though the total element count is 64.
        narrow=root/"narrow-rows.gguf"
        kv=S("general.architecture")+U32(8)+S("llama")
        kv+=S("general.alignment")+U32(4)+U32(ALIGN)
        raw=struct.pack("<"+"f"*len(values),*values)
        header=b"GGUF"+U32(3)+U64(1)+U64(2)+kv
        header+=S("blk.0.attn_q.weight")+U32(2)+U64(16)+U64(4)+U32(0)+U64(0)
        narrow.write_bytes(pad(header)+raw)
        for fmt in ("q8_0","q5_0","q5_1","q4_0","q4_1","auto"):
            dest=root/("narrow-"+fmt+".gguf")
            subprocess.run([binary,str(narrow),str(dest),"10000",fmt],check=True)
            if fmt=="auto":
                # Auto can still reduce F32 to F16, but must not flatten
                # 16-element rows into an invalid GGML 32-element block.
                narrowed,ns,nm,nt=parse(dest)
                assert nt["blk.0.attn_q.weight"][0]==1
                assert len(narrowed)-ns==len(values)*2
            else:
                assert dest.read_bytes()==narrow.read_bytes()
        # Reject a destination alias to the source without modifying the model.
        alias=root/"input-alias.gguf"
        try:
            alias.symlink_to(source)
        except (OSError, NotImplementedError):
            alias=None  # Symlink creation can require privileges on Windows.
        if alias is not None:
            before=source.read_bytes()
            result=subprocess.run([binary,str(source),str(alias),"0","f16"],
                                  capture_output=True)
            assert result.returncode!=0
            assert source.read_bytes()==before
            # Also guard against a pre-existing .partial symlink to input.
            partial=root/"alias-dest.gguf.partial"
            partial.symlink_to(source)
            result=subprocess.run([binary,str(source),str(root/"alias-dest.gguf"),"0","f16"],
                                  capture_output=True)
            assert result.returncode!=0
            assert source.read_bytes()==before
            assert partial.is_symlink()
        # Dangling staging symlinks are directory entries even though
        # Path.exists() reports false. Never follow or replace them.
        dangling=root/"dangling-output.gguf.partial"
        try:
            dangling.symlink_to(root/"not-created.gguf")
        except (OSError, NotImplementedError):
            dangling=None
        if dangling is not None:
            assert dangling.is_symlink()
            result=subprocess.run([binary,str(source),str(root/"dangling-output.gguf"),"0","f16"],
                                  capture_output=True)
            assert result.returncode!=0
            assert dangling.is_symlink()
            assert not (root/"not-created.gguf").exists()
            assert not (root/"dangling-output.gguf").exists()
        # Exercise the >64 MiB F32 streaming path without allocating a
        # Python list of millions of floats.
        huge=root/"huge.gguf"
        n=(64*1024*1024)//4+32
        kv=S("general.architecture")+U32(8)+S("llama")
        kv+=S("general.alignment")+U32(4)+U32(ALIGN)
        header=b"GGUF"+U32(3)+U64(1)+U64(2)+kv
        header+=S("blk.0.attn_q.weight")+U32(1)+U64(n)+U32(0)+U64(0)
        with huge.open("wb") as f:
            f.write(pad(header))
            chunk=struct.pack("<f",1.0)*16384
            for _ in range(n//16384):f.write(chunk)
            f.write(struct.pack("<f",1.0)*(n%16384))
        compact=root/"huge-f16.gguf"
        subprocess.run([binary,str(huge),str(compact),"0","f16"],check=True)
        data,ds,meta,desc=parse(compact)
        assert desc["blk.0.attn_q.weight"][:2]==(1,(n,))
        assert len(data)<huge.stat().st_size
        assert data[ds:ds+16]==struct.pack("<e",1.0)*8
        # Verify values straddling each 64 KiB chunk boundary.
        for i in (0, 16383, 16384, 16385, n-1):
            assert struct.unpack_from("<e",data,ds+2*i)[0]==1.0
        assert len(data)-ds==n*2
        # Auto must also quantize tensors beyond 64 MiB without loading the
        # full tensor into memory; Q4_0 is the smallest accepted encoding.
        huge_auto=root/"huge-auto.gguf"
        subprocess.run([binary,str(huge),str(huge_auto),"1","auto"],check=True)
        ha,hs,hm,ht=parse(huge_auto)
        assert ht["blk.0.attn_q.weight"][:2]==(2,(n,))
        assert len(ha)-hs==(n//32)*18
        for block in (0,2047,2048,n//32-1):
            p=hs+block*18
            scale=struct.unpack_from("<e",ha,p)[0]
            packed=ha[p+2:p+18]
            for j in range(32):
                code=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                assert abs(scale*(code-8)-1.0)<=1
        # BF16 streaming must also handle tensors beyond the old 64 MiB cap
        # without retaining the entire source or destination in the converter.
        huge_bf=root/"huge-bf16.gguf"
        subprocess.run([binary,str(huge),str(huge_bf),"0","bf16"],check=True)
        hb,hbs,hbm,hbt=parse(huge_bf)
        assert hbt["blk.0.attn_q.weight"][:2]==(30,(n,))
        assert len(hb)-hbs==n*2
        for j in (0,16383,16384,16385,n-1):
            assert struct.unpack_from("<H",hb,hbs+2*j)[0]==0x3f80
        # Publishing must not overwrite an existing model artifact.
        existing=root/"existing-output.gguf"
        existing.write_bytes(b"EXISTING MODEL ARTIFACT")
        result=subprocess.run([binary,str(source),str(existing),"0","f16"],
                              capture_output=True)
        assert result.returncode!=0
        assert existing.read_bytes()==b"EXISTING MODEL ARTIFACT"
        assert not (root/"existing-output.gguf.partial").exists()
        # A destination symlink must not be followed or replaced.
        destination_link=root/"existing-link.gguf"
        try:
            destination_link.symlink_to(existing)
        except (OSError, NotImplementedError):
            destination_link=None
        if destination_link is not None:
            result=subprocess.run([binary,str(source),str(destination_link),"0","f16"],
                                  capture_output=True)
            assert result.returncode!=0
            assert destination_link.is_symlink()
            assert existing.read_bytes()==b"EXISTING MODEL ARTIFACT"
        # An occupied output path must be rejected before creating staging.
        # This applies even when the input contains a large tensor.
        huge_existing=root/"huge-existing.gguf"
        huge_existing.write_bytes(b"KEEP ORIGINAL")
        result=subprocess.run([binary,str(huge),str(huge_existing),"0","bf16"],
                              capture_output=True)
        assert result.returncode!=0
        assert huge_existing.read_bytes()==b"KEEP ORIGINAL"
        assert not (root/"huge-existing.gguf.partial").exists()
        # A pre-existing staging file belongs to another invocation.
        # A rejected conversion must leave it byte-for-byte unchanged.
        staged=root/"already-staged.gguf.partial"
        sentinel=b"PREEXISTING STAGING DATA"
        staged.write_bytes(sentinel)
        dest=root/"already-staged.gguf"
        result=subprocess.run([binary,str(source),str(dest),"0","f16"],
                              capture_output=True)
        assert result.returncode!=0
        assert staged.read_bytes()==sentinel
        assert not dest.exists()
        # Q8_0 streaming must work beyond the former 64 MiB allocation cap.
        largeq=root/"huge-q8.gguf"
        subprocess.run([binary,str(huge),str(largeq),"0.01","q8_0"],check=True)
        qdata,qstart,qmeta,qdesc=parse(largeq)
        assert qdesc["blk.0.attn_q.weight"][:2]==(8,(n,))
        assert len(qdata)-qstart==(n//32)*34
        for block in (0, 2047, 2048, n//32-1):
            p=qstart+block*34
            assert struct.unpack_from("<e",qdata,p)[0]>0
            scale=struct.unpack_from("<e",qdata,p)[0]
            assert all(abs(scale*v-1.0)<=0.01 for v in struct.unpack_from("<32b",qdata,p+2))
        # Large Q4_0 output uses the streaming path and preserves GGML
        # signed-scale nibble layout across tensor block boundaries.
        large4=root/"huge-q4.gguf"
        subprocess.run([binary,str(huge),str(large4),"1","q4_0"],check=True)
        q4data,q4start,q4meta,q4desc=parse(large4)
        assert q4desc["blk.0.attn_q.weight"][:2]==(2,(n,))
        assert len(q4data)-q4start==(n//32)*18
        for block in (0,2047,2048,n//32-1):
            p=q4start+block*18
            scale=struct.unpack_from("<e",q4data,p)[0]
            packed=q4data[p+2:p+18]
            assert len(packed)==16
            for j in range(32):
                nib=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                assert abs(scale*(nib-8)-1.0)<=1
        large5=root/"huge-q5.gguf"
        subprocess.run([binary,str(huge),str(large5),"1","q5_0"],check=True)
        q5data,q5start,q5meta,q5desc=parse(large5)
        assert q5desc["blk.0.attn_q.weight"][:2]==(6,(n,))
        assert len(q5data)-q5start==(n//32)*22
        for block in (0,2047,2048,n//32-1):
            p=q5start+block*22
            scale=struct.unpack_from("<e",q5data,p)[0]
            high=struct.unpack_from("<I",q5data,p+2)[0]
            packed=q5data[p+6:p+22]
            for j in range(32):
                low=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                code=low|(((high>>j)&1)<<4)
                assert abs(scale*(code-16)-1.0)<=1
        large41=root/"huge-q41.gguf"
        subprocess.run([binary,str(huge),str(large41),"1","q4_1"],check=True)
        q41data,q41start,q41meta,q41desc=parse(large41)
        assert q41desc["blk.0.attn_q.weight"][:2]==(3,(n,))
        assert len(q41data)-q41start==(n//32)*20
        for block in (0,2047,2048,n//32-1):
            p=q41start+block*20
            scale,minimum=struct.unpack_from("<ee",q41data,p)
            packed=q41data[p+4:p+20]
            for j in range(32):
                code=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                assert abs(minimum+scale*code-1.0)<=1
        large51=root/"huge-q51.gguf"
        subprocess.run([binary,str(huge),str(large51),"1","q5_1"],check=True)
        q51data,q51start,q51meta,q51desc=parse(large51)
        assert q51desc["blk.0.attn_q.weight"][:2]==(7,(n,))
        assert len(q51data)-q51start==(n//32)*24
        for block in (0,2047,2048,n//32-1):
            p=q51start+block*24
            scale,minimum=struct.unpack_from("<ee",q51data,p)
            high=struct.unpack_from("<I",q51data,p+4)[0]
            packed=q51data[p+8:p+24]
            for j in range(32):
                low=(packed[j]&15) if j<16 else (packed[j-16]>>4)
                code=low|(((high>>j)&1)<<4)
                assert abs(minimum+scale*code-1.0)<=1
        bad=root/"bad.gguf";bad.write_bytes(original[:24])
        failed=subprocess.run([binary,str(bad),str(root/"bad-out.gguf"),"0"],capture_output=True)
        assert failed.returncode!=0
        assert not (root/"bad-out.gguf").exists()
        print("GGUF synthetic conversion, metadata, quantized preservation and truncated-input tests PASS")

if __name__=="__main__":
    run(sys.argv[1])
