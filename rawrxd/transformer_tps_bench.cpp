// transformer_tps_bench.cpp
// Measures REAL tokens/sec for rawrxd::TransformerRuntime end to end:
//   load -> prefill -> autoregressive decode.
//
// Honesty rules baked in:
//  * Every number printed is measured on this run. Nothing is assumed or
//    modelled. If a phase did not run, it prints SKIP, not a number.
//  * Model geometry is synthetic, so the tokenizer and weights carry no
//    linguistic meaning. Token/s here measures the COMPUTE COST of the forward
//    pass, not output quality.
//  * Decode cost is expected to grow with context (attention is O(context)),
//    so decode is sampled at several context depths instead of one average.
//
// Build:
//   cl /std:c++20 /EHsc /O2 /I src transformer_tps_bench.cpp ^
//      src\gguf_loader.cpp src\rawrxd_transformer.cpp
#include "gguf_loader.hpp"
#include "rawrxd_transformer.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;
using Clock = std::chrono::steady_clock;

static double Ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

struct Geom {
    uint32_t vocab, hidden, layers, heads, kv_heads, inter, max_pos;
};

static void BuildModel(const std::string& path, const Geom& g) {
    std::map<std::string, GGUFMetadataValue> meta;
    GGUFMetadataValue arch; arch.type = GGUFType::String; arch.value = std::string("llama");
    meta["general.architecture"] = arch;
    auto put = [&](const char* k, uint32_t v) {
        GGUFMetadataValue m; m.type = GGUFType::Uint32; m.value = v; meta[k] = m;
    };
    put("llama.embedding_length", g.hidden);
    put("llama.block_count", g.layers);
    put("llama.attention.head_count", g.heads);
    put("llama.attention.head_count_kv", g.kv_heads);
    put("llama.feed_forward_length", g.inter);
    put("llama.context_length", g.max_pos);
    {   // vocab is an array in real GGUF
        GGUFMetadataValue m; m.type = GGUFType::Uint32Array;
        std::vector<uint32_t> t(g.vocab);
        for (uint32_t i = 0; i < g.vocab; ++i) t[i] = i;
        m.value = t; meta["tokenizer.ggml.tokens"] = m;
    }

    GGUFTensorWriter w;
    auto add = [&](const std::string& name, const std::vector<uint64_t>& shape, float amp) {
        size_t n = 1; for (auto d : shape) n *= static_cast<size_t>(d);
        std::vector<float> v(n);
        for (size_t i = 0; i < n; ++i) {
            v[i] = amp * std::sin(0.001f * static_cast<float>(i % 997));
        }
        std::vector<uint8_t> b(reinterpret_cast<uint8_t*>(v.data()),
                               reinterpret_cast<uint8_t*>(v.data()) + n * 4);
        w.AddTensor(name, GGUFType::Float32, shape, b);
    };

    add("token_embd.weight", {g.vocab, g.hidden}, 0.02f);
    add("output.weight", {g.vocab, g.hidden}, 0.02f);
    add("output_norm.weight", {g.hidden}, 1.0f);
    for (uint32_t l = 0; l < g.layers; ++l) {
        const std::string b = "blk." + std::to_string(l) + ".";
        const uint32_t kvd = (g.hidden / g.heads) * g.kv_heads;
        add(b + "attn_norm.weight", {g.hidden}, 1.0f);
        add(b + "ffn_norm.weight", {g.hidden}, 1.0f);
        add(b + "attn_q.weight", {g.hidden, g.hidden}, 0.01f);
        add(b + "attn_k.weight", {kvd, g.hidden}, 0.01f);
        add(b + "attn_v.weight", {kvd, g.hidden}, 0.01f);
        add(b + "attn_output.weight", {g.hidden, g.hidden}, 0.01f);
        add(b + "ffn_gate.weight", {g.inter, g.hidden}, 0.01f);
        add(b + "ffn_up.weight", {g.inter, g.hidden}, 0.01f);
        add(b + "ffn_down.weight", {g.hidden, g.inter}, 0.01f);
    }
    if (!w.WriteToFile(path, meta)) {
        std::printf("FATAL could not write %s\n", path.c_str());
        std::exit(2);
    }
}

static void Run(const Geom& g, const std::string& path, uint32_t prompt_len,
                uint32_t decode_len) {
    std::printf("\n===== geometry =====\n");
    std::printf("vocab=%u hidden=%u layers=%u heads=%u kv_heads=%u inter=%u max_pos=%u\n",
                g.vocab, g.hidden, g.layers, g.heads, g.kv_heads, g.inter, g.max_pos);
    const bool gqa = (g.heads != g.kv_heads);
    std::printf("gqa=%s\n", gqa ? "yes" : "no");

    const auto t_build0 = Clock::now();
    BuildModel(path, g);
    const auto t_build1 = Clock::now();

    TransformerRuntime rt;
    const auto t_load0 = Clock::now();
    const bool ok = rt.LoadWeights(path);
    const auto t_load1 = Clock::now();
    if (!ok) {
        std::printf("FATAL LoadWeights failed for this geometry (SKIP all tps)\n");
        return;
    }
    const size_t wbytes = rt.GetWeightBytes();
    std::printf("build_ms=%.1f load_ms=%.1f weight_bytes=%zu (%.1f MiB)\n",
                Ms(t_build0, t_build1), Ms(t_load0, t_load1), wbytes,
                double(wbytes) / (1024.0 * 1024.0));

    if (prompt_len >= g.max_pos) {
        std::printf("SKIP prefill: prompt_len %u >= max_pos %u\n", prompt_len, g.max_pos);
    } else {
        std::vector<uint32_t> prompt(prompt_len);
        for (uint32_t i = 0; i < prompt_len; ++i) prompt[i] = i % g.vocab;
        const auto p0 = Clock::now();
        auto fr = rt.Forward(prompt, 0);
        const auto p1 = Clock::now();
        if (!fr.success) {
            std::printf("SKIP prefill: forward failed (%s)\n", fr.error_message.c_str());
        } else {
            const double ms = Ms(p0, p1);
            std::printf("PREFILL prompt_tokens=%u total_ms=%.2f tok_per_s=%.2f "
                        "logits=%zu\n", prompt_len, ms,
                        prompt_len / (ms / 1000.0), fr.logits.size());
        }
    }

    // Decode at increasing context depth to expose the O(context) attention cost.
    // RAWRXD_TPS_CTX_DEPTH_TRUTH_001
    // The sweep used to fill the cache in fixed 256-token chunks regardless of
    // the requested depth, so a request for ctx=16 actually ran a 256-token
    // Forward and a request for ctx=256 ran the same single 256-token chunk.
    // The measured work was therefore identical for ctx 16, 64 and 256, and
    // the printed ctx column described the request rather than the depth the
    // decode actually ran at. That made the table look like proof that decode
    // cost is context-independent, which is not what was measured.
    // The final chunk is now clamped to the remaining depth, and the depth
    // actually reached is printed alongside the requested one.
    std::printf("DECODE (context depth sweep)\n");
    std::printf("%10s %12s %10s %12s %14s\n",
                "ctx_req", "kv_depth", "ms/token", "tok/s", "mean_logit");
    for (uint32_t base : {16u, 64u, 256u, 1024u, 4096u}) {
        if (base + decode_len >= g.max_pos) break;
        rt.ResetKVCache();
        // Fill the cache up to exactly `base` so the next decode runs at that
        // depth: the last chunk is clamped rather than rounded up.
        bool warm = true;
        uint32_t filled = 0;
        {
            const uint32_t kChunk = 256;
            for (uint32_t done = 0; done < base; done += kChunk) {
                const uint32_t n = std::min(kChunk, base - done);
                std::vector<uint32_t> fill(n);
                for (uint32_t i = 0; i < n; ++i) fill[i] = (done + i) % g.vocab;
                auto r = rt.Forward(fill, static_cast<int>(done));
                if (!r.success) { warm = false; break; }
                filled += n;
            }
        }
        if (!warm) { std::printf("SKIP ctx=%u: warmup failed\n", base); continue; }

        double total = 0.0;
        double mean_logit = 0.0;
        uint32_t counted = 0;
        for (uint32_t i = 0; i < decode_len; ++i) {
            std::vector<uint32_t> one{static_cast<uint32_t>((base + i) % g.vocab)};
            const auto t0 = Clock::now();
            auto r = rt.Forward(one, static_cast<int>(base + i));
            const auto t1 = Clock::now();
            if (!r.success) break;
            total += Ms(t0, t1);
            for (float v : r.logits) mean_logit += v;
            ++counted;
        }
        if (counted == 0) { std::printf("SKIP ctx=%u: no tokens produced\n", base); continue; }
        // kv_depth is measured, not asserted: it is the number of tokens the
        // warmup actually pushed through the runtime.
        std::printf("%10u %12u %12.3f %12.2f %14.6f\n", base, filled,
                    total / counted, counted / (total / 1000.0),
                    mean_logit / (double(counted) * g.vocab));
    }
}

int main(int argc, char** argv) {
    // RAWRXD_TPS_CRASH_DIAGNOSABLE_001
    // stdout is fully buffered by default. A benchmark that faults mid-run
    // therefore loses every line it had already measured, so the only symptom
    // is a bare exit code and no indication of which phase died. This run
    // terminated with 0xC0000409 and printed nothing at all, which made it
    // impossible to tell load from prefill from decode. Unbuffered output costs
    // nothing on a benchmark that only prints a few dozen lines, and it means a
    // crash reports exactly how far the run got.
    setvbuf(stdout, nullptr, _IONBF, 0);

    const std::string dir = argc > 1 ? argv[1] : "F:/~dev/rawrxd/bench_tmp";
    std::printf("bench_dir=%s\n", dir.c_str());
    // Small: fast smoke. Medium: closer to a real small model shape.
    const Geom small{512, 256, 4, 8, 8, 688, 4096};
    const Geom gqa  {512, 256, 4, 8, 2, 688, 4096};
    const Geom med  {2048, 512, 8, 8, 8, 1376, 8192};
    const Geom big  {4096, 1024, 12, 16, 4, 2816, 8192};

    // RAWRXD_TPS_HARNESS_ISOLATION_001
    // The full sweep is all-or-nothing, so a fault in one geometry hides every
    // measurement after it. TPS_BENCH_GEOM selects a single geometry and
    // TPS_BENCH_PROMPT overrides the prefill length, which is what makes it
    // possible to find the first input length that faults instead of only
    // seeing that something, somewhere, did.
    const char* onlyGeom = std::getenv("TPS_BENCH_GEOM");
    const char* promptOv = std::getenv("TPS_BENCH_PROMPT");
    const uint32_t promptOverride = promptOv ? (uint32_t)std::strtoul(promptOv, nullptr, 10) : 0;

    struct Case { const char* name; const Geom* g; uint32_t prompt, decode; };
    const Case cases[] = {
        {"small", &small, 64, 16},
        {"gqa",   &gqa,   64, 16},
        {"med",   &med,  128,  8},
        {"big",   &big,  128,  4},
    };
    for (const Case& c : cases) {
        if (onlyGeom && *onlyGeom && std::string(onlyGeom) != c.name) continue;
        const uint32_t pl = promptOverride ? promptOverride : c.prompt;
        Run(*c.g, dir + "/b_" + c.name + ".gguf", pl, c.decode);
    }
    std::printf("\nALL DONE (every figure above was measured on this run)\n");
    return 0;
}