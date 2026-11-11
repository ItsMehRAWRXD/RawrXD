import io, re, sys

p = r'F:\rawrxd\src\deep2\modelgenie\universal_gguf.cpp'
src = io.open(p, encoding='utf-8').read()

old = """            // kv_a_mqa -> (norm) -> kv_b -> MlaDecompress
            {
                GraphOp o;
                o.op = Op::MlaDecompress;
                o.block = (int32_t)b;
                o.a = name(Role::AttnKvAMqa);
                o.b = name(Role::AttnKNorm);
                o.c = name(Role::AttnKvB);
                o.out = "kv";
                g.ops.push_back(o);
            }"""

new = """            // kv_a_mqa -> (norm) -> kv_b -> MlaDecompress.
            // CRITICAL: `a` is the activation this op consumes, resolved from
            // the activation arena. It must NOT be a weight name. MlaDecompress
            // takes weight slots b (latent norm) and c (kv_b primary). Setting
            // `a` to the kv_a_mqa weight name made the arena lookup miss and
            # the executor's resolveIn silently fell back to the running hidden
            # vector, which by that point was `q` (3072 wide) instead of
            # attn_norm (2048). The projection then produced a latent with
            # cosine 0.028 against ground truth and all downstream layers
            # diverged.
            {
                GraphOp o;
                o.op = Op::MlaDecompress;
                o.block = (int32_t)b;
                o.a = "attn_norm";
                o.b = name(Role::AttnKNorm);
                o.c = name(Role::AttnKvAMqa);
                o.out = "kv";
                g.ops.push_back(o);
            }"""

# strip the accidental '#' comment markers inside the C++ block
new = new.replace('\n            # ', '\n            // ')

if old not in src:
    print('anchor not found')
    sys.exit(1)
src = src.replace(old, new, 1)
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
