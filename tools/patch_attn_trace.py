import io, sys

p = r'F:\rawrxd\src\deep2\runtime_graph_executor.cpp'
src = io.open(p, encoding='utf-8').read()

if 'RR_TRACE_ATTN' in src:
    print('already patched')
    sys.exit(0)

anchor = '''        arena("attn") = y;
                hidden_ = y;'''
if anchor not in src:
    print('anchor missing')
    sys.exit(1)

new = '''        if (traceAttn) {
                    double q2 = 0; for (float v : qr) q2 += double(v)*v;
                    double k2 = 0; for (float v : K) k2 += double(v)*v;
                    double y2 = 0; for (float v : y) y2 += double(v)*v;
                    std::fprintf(stderr, "    [attn] blk=%d pos=%zu T=%zu H=%zu qD=%zu kPerHead=%zu vPerHead=%u vPerHeadSize=%zu qL2=%.4f kL2=%.4f yL2=%.4f\\n",
                                 in.block, position, T, H, qD, kPerHead, (unsigned)vPerHead, v.size(),
                                 std::sqrt(q2), std::sqrt(k2), std::sqrt(y2));
                    // first 6 scores
                    double mx = 9e9; for (size_t t = 0; t < T; ++t) mx = std::min(mx, (double)scores[t]);
                    std::fprintf(stderr, "      scores[0..5]=%f %f %f %f %f %f  min=%f\\n",
                                 scores.size()>0?scores[0]:0.f, scores.size()>1?scores[1]:0.f,
                                 scores.size()>2?scores[2]:0.f, scores.size()>3?scores[3]:0.f,
                                 scores.size()>4?scores[4]:0.f, scores.size()>5?scores[5]:0.f, mx);
                }
'''
src = src.replace(anchor, new + anchor, 1)
src = src.replace(
    '    static const bool traceOps = (std::getenv("RR_TRACE_OPS") != nullptr);',
    '    static const bool traceOps = (std::getenv("RR_TRACE_OPS") != nullptr);\n'
    '    static const bool traceAttn = (std::getenv("RR_TRACE_ATTN") != nullptr);', 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
