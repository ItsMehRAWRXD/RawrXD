#!/usr/bin/env python3
"""Independent GGML Q2_K-Q6_K/Q8_K wire decoder and loss-gated GGUF integration."""
import pathlib
import struct
import subprocess
import sys
import tempfile
from native_gguf_f16_integration import U32,U64,S,pad,parse,ALIGN

def make_source(path,typ,values):
    kv=S("general.architecture")+U32(8)+S("llama")
    kv+=S("general.alignment")+U32(4)+U32(ALIGN)
    hdr=b"GGUF"+U32(3)+U64(1)+U64(2)+kv
    hdr+=S("blk.0.attn_q.weight")+U32(1)+U64(len(values))+U32(typ)+U64(0)
    if typ==28: raw=struct.pack("<256d",*values)
    elif typ==0: raw=struct.pack("<256f",*values)
    elif typ==1: raw=struct.pack("<256e",*values)
    else:
        raw=b"".join(struct.pack("<H",struct.unpack("<I",struct.pack("<f",v))[0]>>16) for v in values)
    path.write_bytes(pad(hdr)+raw)
    return raw

def independent_decode(typ, block):
    sizes={10:84,11:110,12:144,13:176,14:210,15:292}
    assert len(block)==sizes[typ]
    out=[]
    if typ==10:
        d,dm=struct.unpack_from("<ee",block,80)
        for j in range(256):
            g=j//16;chunk=g//8;within=g%8;lane=within//2;half=within%2
            q=(block[16+chunk*32+half*16+(j%16)]>>(2*lane))&3
            out.append(d*(block[g]&15)*q-dm*(block[g]>>4))
    elif typ==11:
        d=struct.unpack_from("<e",block,108)[0]
        for j in range(256):
            g=j//16;chunk=g//8;within=g%8
            lowcode=(block[96+(g if g<8 else g-8)]>>(0 if g<8 else 4))&15
            highcode=(block[104+g%4]>>(2*(g//4)))&3
            scale=(lowcode|(highcode<<4))-32
            qbyte=block[32+chunk*32+(g%2)*16+(j%16)]
            q=(qbyte>>(2*(within//2)))&3
            hbyte=block[(g%2)*16+(j%16)]
            high=bool(hbyte&(1<<(g//2)))
            out.append(d*scale*(q-(0 if high else 4)))
    elif typ==12:
        d,m=struct.unpack_from("<ee",block)
        scales=block[4:16];qs=block[16:144]
        for j in range(256):
            g=j//32
            if g<4: sc=scales[g]&63;mn=scales[g+4]&63
            else:
                sc=(scales[g+4]&15)|((scales[g-4]>>6)<<4)
                mn=(scales[g+4]>>4)|((scales[g]>>6)<<4)
            byte=qs[(g//2)*32+j%32]
            q=(byte>>(4*(g%2)))&15
            out.append(d*sc*q-m*mn)
    elif typ==13:
        d,m=struct.unpack_from("<ee",block)
        scales=block[4:16];hi=block[16:48];qs=block[48:176]
        for j in range(256):
            g=j//32
            if g<4: sc=scales[g]&63;mn=scales[g+4]&63
            else:
                sc=(scales[g+4]&15)|((scales[g-4]>>6)<<4)
                mn=(scales[g+4]>>4)|((scales[g]>>6)<<4)
            nib=(qs[(g//2)*32+j%32]>>(4*(g%2)))&15
            top=(hi[j%32]>>(2*(g//2)+g%2))&1
            out.append(d*sc*(nib|(top<<4))-m*mn)
    elif typ==14:
        d=struct.unpack_from("<e",block,208)[0]
        scales=struct.unpack_from("<16b",block,192)
        for j in range(256):
            chunk=j//128;lane=(j%128)//32;col=j%32
            lo=(block[chunk*64+(lane//2)*32+col]>>(4*(lane%2)))&15
            high=(block[128+chunk*32+col]>>(2*lane))&3
            out.append(d*scales[j//16]*((lo|(high<<4))-32))
    else:
        d=struct.unpack_from("<f",block,0)[0]
        qs=struct.unpack_from("<256b",block,4)
        sums=struct.unpack_from("<16h",block,260)
        for group in range(16):
            assert sums[group]==sum(qs[group*16:(group+1)*16])
        out.extend(d*q for q in qs)
    return out

def run(binary):
    values=[]
    for g in range(16):
        for k in range(16):
            if g%4==0: values.append(0.125+k*0.03125)
            elif g%4==1: values.append(-0.125-k*0.03125)
            elif g%4==2: values.append(-0.25+k*0.03125)
            else: values.append(0.0)
    with tempfile.TemporaryDirectory() as d:
        root=pathlib.Path(d)
        for source_type in (28,0,1,30):
            inp=root/("source-%d.gguf"%source_type)
            raw=make_source(inp,source_type,values)
            for out_type,name,tol,size in ((10,"q2_k",2.0,84),(11,"q3_k",1.0,110),(12,"q4_k",0.8,144),(13,"q5_k",0.5,176),(14,"q6_k",0.15,210),(15,"q8_k",0.05,292)):
                dst=root/("%d-%s.gguf"%(source_type,name))
                subprocess.run([binary,str(inp),str(dst),str(tol),name],check=True)
                data,start,meta,tensors=parse(dst)
                kind,dims,offset=tensors["blk.0.attn_q.weight"]
                assert kind==out_type and dims==(256,), (name,source_type,kind)
                assert len(data)-start==size
                decoded=independent_decode(out_type,data[start+offset:start+offset+size])
                assert max(abs(x-y) for x,y in zip(values,decoded))<=tol
                assert len(data)<len(inp.read_bytes())
            # Auto must choose a GGML K type per whole tensor and satisfy
            # the same independent decoder/error budget, for every source dtype.
            auto_dst=root/("auto-%d.gguf"%source_type)
            subprocess.run([binary,str(inp),str(auto_dst),"0.02","auto"],check=True)
            auto_data,auto_start,auto_meta,auto_tensors=parse(auto_dst)
            auto_type,auto_dims,auto_offset=auto_tensors["blk.0.attn_q.weight"]
            assert auto_type in (10,11,12,13,14,15), (source_type,auto_type)
            auto_size={10:84,11:110,12:144,13:176,14:210,15:292}[auto_type]
            auto_decoded=independent_decode(auto_type,auto_data[auto_start+auto_offset:auto_start+auto_offset+auto_size])
            assert max(abs(x-y) for x,y in zip(values,auto_decoded))<=0.02
            assert len(auto_data)<len(inp.read_bytes())
            if source_type==28:
                strict_values=values.copy()
                strict_values[0]=1.0+2**-40
                strict=root/"strict-source.gguf"
                raw_strict=make_source(strict,28,strict_values)
                for fmt in ("q2_k","q3_k","q4_k","q5_k","q6_k","q8_k"):
                    dst=root/("strict-"+fmt+".gguf")
                    subprocess.run([binary,str(strict),str(dst),"0",fmt],check=True)
                    data,start,meta,tensors=parse(dst)
                    kind,dims,offset=tensors["blk.0.attn_q.weight"]
                    assert kind==28 and data[start+offset:start+offset+len(raw_strict)]==raw_strict
                nonfinite=strict_values.copy();nonfinite[0]=float("nan")
                bad=root/"nonfinite-source.gguf"
                badbytes=make_source(bad,28,nonfinite)
                for fmt in ("q5_k","q6_k"):
                    dst=root/("nonfinite-"+fmt+".gguf")
                    subprocess.run([binary,str(bad),str(dst),"1",fmt],check=True)
                    data,start,_,tensors=parse(dst)
                    kind,_,offset=tensors["blk.0.attn_q.weight"]
                    assert kind==28 and data[start+offset:start+offset+len(badbytes)]==badbytes
    print("GGUF Q2_K-Q6_K/Q8_K F64 F32 F16 BF16 + independent decode + strict fallback tests PASS")

if __name__=="__main__":
    run(sys.argv[1])
