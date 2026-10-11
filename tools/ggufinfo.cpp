// ggufinfo.cpp - universal GGUF inspector backed by RawrXDGgufReader.
// RAWRXD_GGUF_UNIVERSAL_READER_001
#include "RawrXDGgufReader.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>

using namespace rawrxd;

static const char* Usage =
"Usage: ggufinfo <file.gguf> [--summary | --tensors | --meta <key> | --check]\n"
"  --summary   architecture, shape counts, block inventory, capability flags\n"
"  --tensors   full tensor directory\n"
"  --meta KEY  print one metadata value\n"
"  --check     validate every tensor offset and nbytes stay inside the file\n";

int main(int argc, char** argv) {
    if (argc < 2) { printf("%s", Usage); return 2; }
    const std::string path = argv[1];
    setvbuf(stdout, nullptr, _IONBF, 0);
    const std::string mode = argc > 2 ? argv[2] : "--summary";

    GgufReader r;
    if (!r.Open(path.c_str())) {
        printf("OPEN_FAIL %s : %s\n", path.c_str(), r.why().c_str());
        return 1;
    }

    if (mode == "--meta") {
        if (argc < 3) { printf("need key\n"); return 2; }
        uint64_t u; float f; bool b; std::string s;
        const char* k = argv[3];
        if (r.getU64(k, u))      printf("%llu\n", (unsigned long long)u);
        else if (r.getF32(k, f)) printf("%.9g\n", f);
        else if (r.getBool(k, b))printf("%s\n", b ? "true" : "false");
        else if (r.getString(k, s)) printf("%s\n", s.c_str());
        else { printf("ABSENT\n"); return 1; }
        return 0;
    }

    if (mode == "--tensors") {
        for (const auto& kv : r.tensors()) {
            const GgufTensor& t = kv.second;
            printf("%-52s %-9s ne=[%lld,%lld,%lld,%lld] off=%llu bytes=%llu\n",
                   t.name.c_str(), GgmlTypeName(t.type),
                   (long long)t.ne0(), (long long)t.ne1(),
                   (long long)t.ne2(), (long long)t.ne3(),
                   (unsigned long long)t.abs_offset,
                   (unsigned long long)t.nbytes);
        }
        return 0;
    }

    if (mode == "--check") {
        // Every tensor's byte range must lie inside the file. Tensors with an
        // unknown block size are skipped and reported as unknowns.
        int bad = 0, unknown = 0, checked = 0;
        for (const auto& kv : r.tensors()) {
            const GgufTensor& t = kv.second;
            if (t.nbytes == 0) { ++unknown; continue; }
            ++checked;
            if (t.abs_offset + t.nbytes > r.fileSize()) { ++bad;
                printf("OUT_OF_RANGE %s type=%s ne=[%lld,%lld,%lld,%lld] abs=%llu bytes=%llu file=%llu\n",
                       t.name.c_str(), rawrxd::GgmlTypeName(t.type),
                       (long long)t.ne0(), (long long)t.ne1(),
                       (long long)t.ne2(), (long long)t.ne3(),
                       (unsigned long long)t.abs_offset,
                       (unsigned long long)t.nbytes,
                       (unsigned long long)r.fileSize()); }
        }
        printf("checked=%d out_of_range=%d unknown_size=%d\n", checked, bad, unknown);
        printf("VERDICT=%s\n", bad == 0 ? "PASS" : "FAIL");

        // Reading the token embedding back must return plausible values.
        const GgufTensor* emb = r.find("token_embd.weight");
        if (emb) {
            std::vector<float> v;
            if (r.readF32(*emb, v) && !v.empty()) {
                double mn = v[0], mx = v[0], sum = 0; bool fin = true;
                for (float x : v) { if (!std::isfinite(x)) fin = false; mn = std::min(mn,(double)x); mx = std::max(mx,(double)x); sum += x; }
                printf("token_embd n=%zu finite=%s min=%.6f max=%.6f mean=%.8f\n",
                       v.size(), fin ? "yes" : "NO", mn, mx, sum / double(v.size()));
            } else {
                printf("EMB_READ_FAIL %s\n", r.why().c_str());
            }
        } else {
            printf("token_embd.weight ABSENT (architecture may name it differently)\n");
        }
        return bad == 0 ? 0 : 1;
    }

    // default: --summary
    printf("file            %s\n", path.c_str());
    printf("gguf version    %u\n", r.version());
    printf("architecture    %s\n", r.architecture().empty() ? "(absent)" : r.architecture().c_str());
    printf("file size       %llu bytes\n", (unsigned long long)r.fileSize());
    printf("tensors         %llu\n", (unsigned long long)r.tensorCount());
    printf("data start      %llu\n", (unsigned long long)r.dataStart());

    uint64_t bc = 0, emb = 0, vocab = 0, ctx = 0, hc = 0, kvh = 0, eks = 0;
    float rdim = 0;
    r.getArchU64("block_count", bc);
    r.getArchU64("embedding_length", emb);
    r.getArchU64("context_length", ctx);
    r.getArchU64("attention.head_count", hc);
    r.getArchU64("attention.head_count_kv", kvh);
    r.getArchU64("expert_count", eks);
    r.getArchF32("rope.dimension_count", rdim);
    if (r.getArchU64("vocab_size", vocab)) {}
    else r.getU64("tokenizer.ggml.vocab_size", vocab);

    std::vector<int> blocks;
    r.blockIndices(blocks);

    printf("block_count     %llu\n", (unsigned long long)bc);
    printf("embedding       %llu\n", (unsigned long long)emb);
    printf("vocab           %llu\n", (unsigned long long)vocab);
    printf("context         %llu\n", (unsigned long long)ctx);
    printf("attn heads      %llu (kv %llu)\n", (unsigned long long)hc, (unsigned long long)kvh);
    printf("rope dim        %.0f\n", rdim);
    printf("expert count    %llu\n", (unsigned long long)eks);
    printf("blocks in dir   %zu", blocks.size());
    if (!blocks.empty()) printf(" (range %d..%d)", blocks.front(), blocks.back());
    printf("\n");
    printf("capabilities    ssm=%s attention=%s moe=%s\n",
           r.hasSsm() ? "yes" : "no",
           r.hasAttention() ? "yes" : "no",
           r.hasMoe() ? "yes" : "no");

    // Any metadata key naming an expert or ssm parameter is worth surfacing.
    printf("VERDICT=OPEN_OK\n");
    return 0;
}
