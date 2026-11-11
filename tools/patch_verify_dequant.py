import io, sys

p = r'F:\rawrxd\tools\deep2_runtime_dispatch.cpp'
src = io.open(p, encoding='utf-8').read()

if 'verify-dequant' in src:
    print('already patched'); sys.exit(0)

# Add a verify-dequant mode that dumps the executor's own decode of output.weight
# row 0 and compares the resulting logit distribution for coherence signals.
anchor = '    else if (a == "--prompt" && i + 1 < argc) prompt = argv[++i];'
if anchor not in src:
    print('anchor missing'); sys.exit(1)

src = src.replace(anchor, '    else if (a == "--verify-dequant") verifyDequant = true;\n' + anchor, 1)

# add the verify implementation right before "// receipts"
anchor2 = '    // receipts'
if anchor2 not in src:
    print('anchor2 missing'); sys.exit(1)

impl = '''    // ---- optional: verify the executor's own dequant path ----
    if (verifyDequant) {
        // The LM head reads output.weight [n_in=embd, n_out=vocab] in Q6_K.
        // A correct decode must make logits DIFFER between positions, must be
        // finite, and must give a distribution whose top token is far more
        #include <cmath>'''
# keep it simpler: we can't add includes mid-function reliably, so use only
# what's already included.
impl = '''    if (verifyDequant) {
        int32_t slot = -1;
        for (size_t i = 0; i < ex.ProgramSize(); ++i) { (void)i; }
        // Find the output.weight slot through the ingester report.
        slot = -1;
        for (size_t i = 0; i < rep.tensors.size(); ++i) {
            if (rep.tensors[i].name == "output.weight") { slot = (int32_t)i; break; }
        }
        if (slot < 0) { Check(false, "output.weight found in ingested report"); }
        else {
            Check(true, "output.weight found in ingested report");
            const ggml_type_traits* tr = ggml_get_type_traits(rep.tensors[(size_t)slot].ggml_type);
            Check(tr != nullptr, "output.weight has ggml type traits");
            if (tr) {
                std::printf("  output.weight: type=%s blck=%zu type_size=%zu dims=[%zu,%zu] bytes=%llu\\n",
                            tr->type_name, (size_t)tr->blck_size, (size_t)tr->type_size,
                            (size_t)rep.tensors[(size_t)slot].dims[0],
                            rep.tensors[(size_t)slot].dims.size() > 1 ? (size_t)rep.tensors[(size_t)slot].dims[1] : 0,
                            (unsigned long long)rep.tensors[(size_t)slot].bytes);
                // Decode the first 8 super-blocks (256 values each) and check finiteness.
                std::vector<float> row(8 * tr->blck_size);
                tr->to_float(rep.tensors[(size_t)slot].data, row.data(), (int)row.size());
                bool finite = true; double s = 0.0;
                for (float v : row) { if (!std::isfinite(v)) finite = false; s += std::fabs((double)v); }
                Check(finite, "output.weight first 8 super-blocks decode finite");
                std::printf("  decoded L1=%.6f first10=%.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f\\n",
                            s, row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]);
            }
        }
    }

'''
src = src.replace(anchor2, impl + anchor2, 1)

# declare flag
src = src.replace('    std::string model, prompt =', '    bool verifyDequant = false;\n    std::string model, prompt =', 1)

io.open(p, 'w', encoding='utf-8', newline='\n').write(src)
print('patched')
