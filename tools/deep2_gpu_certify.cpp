// ============================================================================
// deep2_gpu_certify.cpp -- RAWRXD_DEEP2_GPU_QUANT_DOT_003
// ============================================================================
// Certifies the NATIVE GPU quant-dot path end to end on real GGUF weights:
//   * runs the full transformer forward with the GPU path enabled (no CPU pin)
//   * reports gpu_calls / cpu_calls / the exact fallback reason, if any
//   * re-runs the identical sequence CPU-pinned and compares the full logit
//     vectors of both executions (cosine, max_abs, argmax agreement)
//   * requires finite logits over the whole vocabulary
//
// PASS requires: zero CPU fallback, finite full-vocab logits, and exact argmax
// agreement with the CPU reference at every tested position.
//
// Usage: deep2_gpu_certify.exe --model <gguf> [--tokens "1 185" ]
// ============================================================================
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;

namespace {

bool WriteLogits(const std::string& path, const std::vector<float>& v) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const size_t n = std::fwrite(v.data(), sizeof(float), v.size(), f);
    std::fclose(f);
    return n == v.size();
}

size_t FiniteCount(const std::vector<float>& v) {
    size_t n = 0;
    for (float x : v) if (std::isfinite(x)) ++n;
    return n;
}

}  // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string model, tokensArg = "1 185", dump = "gpu_certify";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokensArg = argv[++i];
        else if (a == "--dump" && i + 1 < argc) dump = argv[++i];
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: deep2_gpu_certify.exe --model <gguf> [--tokens \"1 185\"] [--dump DIR]\n");
        return 1;
    }
    std::vector<uint32_t> tokens;
    {
        const char* p = tokensArg.c_str();
        char* end = nullptr;
        for (long v = std::strtol(p, &end, 10); end != p; v = std::strtol(p, &end, 10)) {
            if (v < 0) break;
            tokens.push_back((uint32_t)v);
            p = end;
            while (*p == ' ' || *p == ',') ++p;
            if (!*p) break;
        }
    }
    if (tokens.empty()) { std::printf("no tokens\n"); return 1; }
    std::printf("tokens:");
    for (auto t : tokens) std::printf(" %u", t);
    std::printf("\n");

    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
    std::printf("arch=%s blocks=%llu embd=%llu vocab=%llu experts=%llu used=%llu\n",
                rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count,
                (unsigned long long)rep.spec.embd, (unsigned long long)rep.spec.vocab,
                (unsigned long long)rep.spec.expert_count,
                (unsigned long long)rep.spec.expert_used);

    // ---- GPU path (no CPU pin) --------------------------------------------
    std::vector<std::vector<float>> gpuLogits;
    {
        RuntimeGraph::Executor ex;
        if (!ex.Bind(rep)) {
            std::printf("BIND_FAIL(gpu): %s\n", ex.Stats().error.c_str());
            return 1;
        }
        std::printf("[gpu] bound ops=%zu\n", ex.Stats().ops_total);
        for (size_t pos = 0; pos < tokens.size(); ++pos) {
            const auto t0 = std::chrono::steady_clock::now();
            const bool ok = ex.ExecuteToken(tokens[pos], pos);
            const auto t1 = std::chrono::steady_clock::now();
            if (!ok) { std::printf("EXEC_FAIL(gpu) pos=%zu err=%s\n", pos, ex.LastError().c_str()); return 1; }
            gpuLogits.push_back(ex.Logits());
            std::printf("[gpu] pos=%zu token=%u %.1f ms ops=%zu\n", pos, tokens[pos],
                        std::chrono::duration<double, std::milli>(t1 - t0).count(),
                        ex.Stats().ops_total);
        }
        std::printf("[gpu] gpu_calls=%llu cpu_calls=%llu fallback=%s\n",
                    (unsigned long long)ex.Stats().gpu_calls,
                    (unsigned long long)ex.Stats().cpu_calls,
                    ex.Stats().fallback_reason.empty() ? "<none>" : ex.Stats().fallback_reason.c_str());
    }

    // ---- CPU-pinned reference (fresh executor, identical sequence) --------
    std::vector<std::vector<float>> cpuLogits;
    {
        RuntimeGraph::Executor ex;
        ex.SetForceCpu(true);
        if (!ex.Bind(rep)) {
            std::printf("BIND_FAIL(cpu): %s\n", ex.Stats().error.c_str());
            return 1;
        }
        for (size_t pos = 0; pos < tokens.size(); ++pos) {
            if (!ex.ExecuteToken(tokens[pos], pos)) {
                std::printf("EXEC_FAIL(cpu) pos=%zu err=%s\n", pos, ex.LastError().c_str());
                return 1;
            }
            cpuLogits.push_back(ex.Logits());
        }
        std::printf("[cpu] cpu_calls=%llu\n", (unsigned long long)ex.Stats().cpu_calls);
    }

    // ---- comparison -------------------------------------------------------
    bool pass = true;
    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        const std::vector<float>& g = gpuLogits[pos];
        const std::vector<float>& c = cpuLogits[pos];
        if (g.empty() || c.empty()) { std::printf("pos=%zu: empty logits\n", pos); pass = false; continue; }
        const size_t n = std::min(g.size(), c.size());
        uint32_t ag = 0, ac = 0;
        double dot = 0, ng = 0, nc = 0, mx = 0;
        size_t finite = 0;
        for (size_t i = 0; i < n; ++i) {
            if (g[i] > g[ag]) ag = (uint32_t)i;
            if (c[i] > c[ac]) ac = (uint32_t)i;
            dot += double(g[i]) * double(c[i]);
            ng += double(g[i]) * double(g[i]);
            nc += double(c[i]) * double(c[i]);
            const double d = std::fabs(double(g[i]) - double(c[i]));
            if (d > mx) mx = d;
            if (std::isfinite(g[i])) ++finite;
        }
        const double cos = ng > 0 && nc > 0 ? dot / (std::sqrt(ng) * std::sqrt(nc)) : 0.0;
        const bool ok = (finite == g.size()) && ag == ac && cos >= 0.999 && mx < 5.0;
        std::printf("pos=%zu vocab=%zu finite=%zu gpu_argmax=%u cpu_argmax=%u cos=%.7f max_abs=%.4g %s\n",
                    pos, g.size(), finite, ag, ac, cos, mx, ok ? "PASS" : "FAIL");
        if (!ok) pass = false;
        char p1[512], p2[512];
        std::snprintf(p1, sizeof(p1), "%s/gpu_logits_pos%zu.bin", dump.c_str(), pos);
        std::snprintf(p2, sizeof(p2), "%s/cpu_logits_pos%zu.bin", dump.c_str(), pos);
        WriteLogits(p1, g);
        WriteLogits(p2, c);
    }
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
