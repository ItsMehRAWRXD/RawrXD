// stage_profile.cpp
// Splits one decode step into compute phases so the bottleneck is measured,
// not guessed. Every number printed is wall-clock measured on this run.
//
// Also isolates vector width: the same source is built with /arch:AVX2 and
// /arch:AVX512, both single-threaded, so width is the only variable.
#include "gguf_loader.hpp"
#include "rawrxd_transformer.hpp"
#include "rawrxd_cpu_math.hpp"

#include <chrono>
#include <cmath>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

using namespace rawrxd;
using Clock = std::chrono::steady_clock;

static void Build(const std::string& path, uint32_t V, uint32_t H, uint32_t L,
                  uint32_t NH, uint32_t NKV, uint32_t I, uint32_t MAXP) {
    std::map<std::string, GGUFMetadataValue> meta;
    GGUFMetadataValue a; a.type = GGUFType::String; a.value = std::string("llama");
    meta["general.architecture"] = a;
    auto put = [&](const char* k, uint32_t v) {
        GGUFMetadataValue m; m.type = GGUFType::Uint32; m.value = v; meta[k] = m;
    };
    put("llama.embedding_length", H);
    put("llama.block_count", L);
    put("llama.attention.head_count", NH);
    put("llama.attention.head_count_kv", NKV);
    put("llama.feed_forward_length", I);
    put("llama.context_length", MAXP);
    { GGUFMetadataValue m; m.type = GGUFType::Uint32Array;
      std::vector<uint32_t> t(V); for (uint32_t i = 0; i < V; ++i) t[i] = i;
      m.value = t; meta["tokenizer.ggml.tokens"] = m; }

    GGUFTensorWriter w;
    auto add = [&](const std::string& n, const std::vector<uint64_t>& sh, float amp) {
        size_t c = 1; for (auto d : sh) c *= size_t(d);
        std::vector<float> v(c);
        for (size_t i = 0; i < c; ++i) v[i] = amp * std::sin(0.013f * float(i % 991));
        std::vector<uint8_t> b((uint8_t*)v.data(), (uint8_t*)v.data() + c * 4);
        w.AddTensor(n, GGUFType::Float32, sh, b);
    };
    add("token_embd.weight", {V, H}, 0.05f);
    add("output.weight", {V, H}, 0.02f);
    add("output_norm.weight", {H}, 1.0f);
    const uint32_t kvd = (H / NH) * NKV;
    for (uint32_t l = 0; l < L; ++l) {
        const std::string b = "blk." + std::to_string(l) + ".";
        add(b + "attn_norm.weight", {H}, 1.0f);
        add(b + "ffn_norm.weight", {H}, 1.0f);
        add(b + "attn_q.weight", {H, H}, 0.01f);
        add(b + "attn_k.weight", {kvd, H}, 0.01f);
        add(b + "attn_v.weight", {kvd, H}, 0.01f);
        add(b + "attn_output.weight", {H, H}, 0.01f);
        add(b + "ffn_gate.weight", {I, H}, 0.01f);
        add(b + "ffn_up.weight", {I, H}, 0.01f);
        add(b + "ffn_down.weight", {H, I}, 0.01f);
    }
    if (!w.WriteToFile(path, meta)) { std::printf("FATAL write failed\n"); std::exit(2); }
}

struct Row { const char* name; double ms; };

static void Dump(const char* title, const StageTimes& s, double measured_ms) {
    std::printf("\n--- %s ---\n", title);
    std::printf("%-22s %10s %8s\n", "phase", "ms", "share");
    const Row rows[] = {
        {"proj_qkv",   s.proj_qkv_ms},
        {"qk_score",   s.qk_score_ms},
        {"softmax",    s.softmax_ms},
        {"vsum(V)",    s.vsum_ms},
        {"out_proj",   s.out_proj_ms},
        {"mlp",        s.mlp_ms},
        {"rope",       s.rope_ms},
        {"norm",       s.norm_ms},
        {"kv_write",   s.kv_write_ms},
        {"embed",      s.embed_ms},
        {"lm_head",    s.lm_head_ms},
    };
    const double base = measured_ms > 0.0 ? measured_ms : s.total_ms;
    for (const auto& r : rows) {
        if (r.ms <= 0.0) continue;
        std::printf("%-22s %10.4f %7.1f%%\n", r.name, r.ms, 100.0 * r.ms / base);
    }
    const double attributed = s.Sum();
    std::printf("%-22s %10.4f %7.1f%%\n", "ATTRIBUTED", attributed,
                base > 0 ? 100.0 * attributed / base : 0.0);
    std::printf("%-22s %10.4f (wall, incl. unattributed)\n", "TOTAL", base);
    const double attn = s.qk_score_ms + s.softmax_ms + s.vsum_ms;
    if (base > 0) {
        std::printf("\nattention_total=%.4f ms (%.1f%%)  projections+mlp=%.4f ms (%.1f%%)\n",
                    attn, 100.0 * attn / base,
                    s.proj_qkv_ms + s.out_proj_ms + s.mlp_ms + s.lm_head_ms,
                    100.0 * (s.proj_qkv_ms + s.out_proj_ms + s.mlp_ms + s.lm_head_ms) / base);
        std::printf("PARALLELIZATION_TARGET=%s\n",
                    attn > (s.proj_qkv_ms + s.out_proj_ms + s.mlp_ms) ? "ATTENTION"
                                                                       : "PROJECTIONS");
    }
}

int main(int argc, char** argv) {
    const std::string dir = argc > 1 ? argv[1] : "F:/~dev/rawrxd/bench_tmp";
    std::printf("backend=%s\n", cpu::BackendName());

    const uint32_t V = 2048, H = 512, L = 8, NH = 8, NKV = 8, I = 1376, MAXP = 8192;
    const std::string path = dir + "/prof.gguf";
    Build(path, V, H, L, NH, NKV, I, MAXP);

    TransformerRuntime rt;
    if (!rt.LoadWeights(path)) { std::printf("FATAL load failed\n"); return 2; }
    std::printf("model: vocab=%u hidden=%u layers=%u heads=%u kv_heads=%u inter=%u\n",
                V, H, L, NH, NKV, I);

    for (uint32_t depth : {16u, 1024u, 4096u}) {
        auto warm = [&](bool report) {
            for (uint32_t done = 0; done < depth; done += 256) {
                const uint32_t n = (depth - done) < 256 ? (depth - done) : 256;
                std::vector<uint32_t> fill(n);
                for (uint32_t i = 0; i < n; ++i) fill[i] = (done + i) % V;
                auto r = rt.Forward(fill, (int)done);
                if (!r.success) {
                    if (report) std::printf("SKIP depth=%u warmup failed\n", depth);
                    return false;
                }
            }
            return true;
        };
        if (!warm(true)) continue;

        // Profiled decode steps at this depth.
        rt.SetProfiling(true);
        const int kSteps = 12;
        StageTimes acc;
        double wall = 0.0;
        bool ok = true;
        for (int i = 0; i < kSteps; ++i) {
            std::vector<uint32_t> one{uint32_t((depth + uint32_t(i)) % V)};
            const auto t0 = Clock::now();
            auto r = rt.Forward(one, (int)(depth + uint32_t(i)));
            wall += std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
            if (!r.success) { ok = false; break; }
            const StageTimes s = rt.StageTimesResult();
            acc.proj_qkv_ms += s.proj_qkv_ms;  acc.qk_score_ms += s.qk_score_ms;
            acc.softmax_ms += s.softmax_ms;      acc.vsum_ms += s.vsum_ms;
            acc.out_proj_ms += s.out_proj_ms;  acc.mlp_ms += s.mlp_ms;
            acc.rope_ms += s.rope_ms;          acc.norm_ms += s.norm_ms;
            acc.kv_write_ms += s.kv_write_ms;  acc.embed_ms += s.embed_ms;
            acc.lm_head_ms += s.lm_head_ms;    acc.total_ms += s.total_ms;
            acc.layers += s.layers;            acc.heads += s.heads;
        }
        rt.SetProfiling(false);
        if (ok) {
            // acc accumulated across steps; report the mean so it is directly
            // comparable with the mean wall time.
            const double inv = 1.0 / double(kSteps);
            acc.proj_qkv_ms *= inv; acc.qk_score_ms *= inv; acc.softmax_ms *= inv;
            acc.vsum_ms *= inv;     acc.out_proj_ms *= inv; acc.mlp_ms *= inv;
            acc.rope_ms *= inv;     acc.norm_ms *= inv;    acc.kv_write_ms *= inv;
            acc.embed_ms *= inv;    acc.lm_head_ms *= inv; acc.total_ms *= inv;
            acc.layers /= uint64_t(kSteps); acc.heads /= uint64_t(kSteps);
            char buf[64];
            std::snprintf(buf, sizeof(buf), "depth=%u (mean of %d steps)", depth, kSteps);
            Dump(buf, acc, wall / kSteps);
            std::printf("throughput=%.2f tok/s (profiling ON, so this is a floor)\n",
                        kSteps / (wall / 1000.0));
        }
    }
    return 0;
}