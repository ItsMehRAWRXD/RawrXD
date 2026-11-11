import io, re, sys

p = r'F:\rawrxd\tools\deep2_runtime_dispatch.cpp'
src = io.open(p, encoding='utf-8').read()

if 'logit stats' in src:
    print('already patched')
    sys.exit(0)

anchor = '            // ---- [5] generated text'
if anchor not in src:
    print('anchor not found')
    sys.exit(1)

block = (
'            // ---- logit stats (diagnostic) --------------------------------\n'
'            {\n'
'                const size_t ns = std::min<size_t>(gpuL.size(), 4);\n'
'                for (size_t s = 0; s < ns; ++s) {\n'
'                    const std::vector<float>& v = gpuL[s];\n'
'                    if (v.empty()) continue;\n'
'                    size_t best = 0; double sum = 0.0, sq = 0.0; float mn = v[0], mx = v[0];\n'
'                    for (size_t i = 0; i < v.size(); ++i) {\n'
'                        if (v[i] > v[best]) best = i;\n'
'                        sum += v[i]; sq += double(v[i]) * v[i];\n'
'                        if (v[i] < mn) mn = v[i];\n'
'                        if (v[i] > mx) mx = v[i];\n'
'                    }\n'
'                    const double mean = sum / double(v.size());\n'
'                    const double var = sq / double(v.size()) - mean * mean;\n'
'                    std::printf("  [logit stats] pos=%zu argmax=%zu min=%.4f max=%.4f mean=%.4f std=%.4f\\n",\n'
'                                s, best, mn, mx, mean, std::sqrt(var > 0 ? var : 0.0));\n'
'                    std::vector<size_t> idx(v.size());\n'
'                    for (size_t i = 0; i < v.size(); ++i) idx[i] = i;\n'
'                    std::partial_sort(idx.begin(), idx.begin() + 5, idx.end(),\n'
'                                      [&](size_t a, size_t b) { return v[a] > v[b]; });\n'
'                    std::printf("    top5:");\n'
'                    for (int k = 0; k < 5; ++k) std::printf(" [%zu]=%.4f", idx[k], v[idx[k]]);\n'
'                    std::printf("\\n");\n'
'                }\n'
'            }\n'
'\n'
)

src = src.replace(anchor, block + anchor, 1)
io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
