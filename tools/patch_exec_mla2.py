import io

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

old = "                if (!OpMlaDecompress(in, xi, k, v, position, e)) { last_error_ = e; return false; }"
new = """                {
                    // The three weight slots are a (kv_a_mqa), b (latent norm),
                    # c (kv_b). The activation this op consumes rides in `detail`
                    # so resolveIn can find it in the arena rather than falling
                    # back to hidden_, which is `q` by the time this op runs.
                    const std::vector<float>& mlaIn =
                        act.count(in.detail) ? act[in.detail] : xi;
                    if (!OpMlaDecompress(in, mlaIn, k, v, position, e)) { last_error_ = e; return false; }
                }"""
new = new.replace('\n                    # ', '\n                    // ')
if old not in src:
    print('anchor missing')
    raise SystemExit(1)
src = src.replace(old, new, 1)
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('executor patched')
