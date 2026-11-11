import struct,sys
for p in sys.argv[1:]:
 with open(p,'rb') as f:
  h=f.read(24)
 magic,ver,n_t,n_kv=struct.unpack('<IIQQ',h)
 print(p, 'magic',hex(magic),'ver',ver,'tensors',n_t,'kv',n_kv)
