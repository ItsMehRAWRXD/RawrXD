import struct
path = r'F:\~dev\rawrxd\src\core\test_tiny_with_vocab.gguf'
with open(path, 'rb') as f:
    data = f.read()
off=0
magic=struct.unpack('<I',data[off:off+4])[0]; off+=4
ver=struct.unpack('<I',data[off:off+4])[0]; off+=4
tc=struct.unpack('<Q',data[off:off+8])[0]; off+=8
mc=struct.unpack('<Q',data[off:off+8])[0]; off+=8
print(f'ver={ver} tc={tc} mc={mc}')
for i in range(mc):
    nlen=struct.unpack('<Q',data[off:off+8])[0]; off+=8
    key=data[off:off+nlen].decode(); off+=nlen
    vtype=struct.unpack('<I',data[off:off+4])[0]; off+=4
    print(f'KV {i}: {key} type={vtype}', end='')
    if vtype==0:
        v=data[off]; off+=1; print(f' uint8={v}')
    elif vtype==1:
        v=struct.unpack('<b',data[off:off+1])[0]; off+=1; print(f' int8={v}')
    elif vtype==2:
        v=struct.unpack('<H',data[off:off+2])[0]; off+=2; print(f' uint16={v}')
    elif vtype==3:
        v=struct.unpack('<h',data[off:off+2])[0]; off+=2; print(f' int16={v}')
    elif vtype==4:
        v=struct.unpack('<I',data[off:off+4])[0]; off+=4; print(f' uint32={v}')
    elif vtype==5:
        v=struct.unpack('<i',data[off:off+4])[0]; off+=4; print(f' int32={v}')
    elif vtype==6:
        v=struct.unpack('<f',data[off:off+4])[0]; off+=4; print(f' float32={v}')
    elif vtype==7:
        v=data[off]; off+=1; print(f' bool={v}')
    elif vtype==8:
        slen=struct.unpack('<Q',data[off:off+8])[0]; off+=8
        s=data[off:off+slen].decode(); off+=slen
        print(f' str="{s}"')
    elif vtype==9:
        at=struct.unpack('<I',data[off:off+4])[0]; off+=4
        al=struct.unpack('<Q',data[off:off+8])[0]; off+=8
        print(f' arr type={at} len={al}')
        for _ in range(al):
            if at==8:
                slen=struct.unpack('<Q',data[off:off+8])[0]; off+=8; off+=slen
            elif at in (0,1,7):
                off+=1
            elif at in (2,3):
                off+=2
            elif at in (4,5,6):
                off+=4
            elif at in (10,11,12):
                off+=8
    elif vtype==10:
        v=struct.unpack('<Q',data[off:off+8])[0]; off+=8; print(f' uint64={v}')
    elif vtype==11:
        v=struct.unpack('<q',data[off:off+8])[0]; off+=8; print(f' int64={v}')
    elif vtype==12:
        v=struct.unpack('<d',data[off:off+8])[0]; off+=8; print(f' float64={v}')
    else:
        print(f' unknown type {vtype}'); off+=4
print(f'metadata end={off}')
