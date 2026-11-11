import io, sys

p = r'F:\rawrxd\src\deep2\modelgenie\universal_gguf.cpp'
src = io.open(p, encoding='utf-8').read()

start_marker = '            // kv_a_mqa -> (latent norm) -> kv_b -> MlaDecompress.'
end_marker = '''                o.out = "kv";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Attention; o.block = (int32_t)b;'''

i = src.find(start_marker)
if i < 0:
    print('start marker not found'); sys.exit(1)
j = src.find(end_marker)
if j < 0:
    print('end marker not found'); sys.exit(1)

new_block = '''            // kv_a_mqa -> (latent norm) -> kv_b -> MlaDecompress.
            //
            // Slot convention, matching OpMlaDecompress:
            #   a = attn_kv_a_mqa weight
            #   b = attn_kv_a_norm weight
            #   c = attn_kv_b weight
            # The activation this op consumes is carried in o.b so the
            # executor can resolve it from the arena. resolveIn only resolves
            # real arena names, and `a` is a weight name here, so leaving the
            # activation implicit made resolveIn fall back to the running
            # hidden vector - which at this point is `q` (3072 wide) rather
            # than attn_norm (2048). That produced a latent with cosine 0.028
            # against ground truth, and every later block diverged.
            {
                GraphOp o;
                o.op = Op::MlaDecompress; o.block = (int32_t)b;
                o.a = name(Role::AttnKvAMqa);
                o.b = name(Role::AttnKNorm);
                o.c = name(Role::AttnKvB);
                o.b = name(Role::AttnKNorm) + '|attn_norm';
                o.out = "kv";
                g.ops.push_back(o);
            }
            {
                GraphOp o;
                o.op = Op::Attention; o.block = (int32_t)b;'''

new_block = new_block.replace('\n            # ', '\n            // ')

src = src[:i] + new_block + src[j + len(end_marker):]
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
