// deep2_lifecycle_probe.cpp -- RAWRXD_STRATA_LIFECYCLE_001
//
// Same-process model lifecycle probe: A -> B -> A over one Vulkan cache.
//
// Answers the question the budget sweeps cannot: is a cache hit *valid* after a
// model replacement? Two oracles are used:
//
//   1. Determinism  - loading A twice in the same process must reproduce the
//                     same logits signature (warm cache reuse is correct).
//   2. Separation   - loading B must produce a different signature from A for
//                     the same token. Identical signatures would prove the cache
//                     keyed on a reused allocation address rather than model
//                     identity, i.e. a false hit.
//
// Usage:
//   deep2_lifecycle_probe.exe --model-a <gguf> --model-b <gguf>
//       [--tokens 1 450] [--gpu|--cpu] [--outdir D] [--tag T]

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "StrataExpertResidency.hpp"
#include "quant_dot_dispatch.hpp"
#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include <windows.h>

using namespace RawrXD::Deep2;  // Universal / RuntimeGraph / QuantDot

namespace {

struct PhaseResult {
    std::string model;
    bool ok = false;
    size_t ops = 0;
    uint64_t gpuCalls = 0, cpuCalls = 0;
    uint64_t hits = 0, misses = 0, evictions = 0, evictionsBudget = 0, evictionsTrim = 0;
    uint64_t deviceBytes = 0;
    double signature = 0.0;
    std::string error;
};

// Cheap order-sensitive signature over a few logits; enough to tell two models
// apart and to prove determinism, without hashing the whole vocabulary.
double Signature(const std::vector<float>& logits, size_t n = 64)
{
    double acc = 0.0;
    const size_t count = logits.size() < n ? logits.size() : n;
    for (size_t i = 0; i < count; ++i)
        acc += (double)logits[i] * (double)(i + 1);
    return acc;
}

bool RunPhase(const std::string& model, const std::vector<uint32_t>& tokens, bool gpu,
              bool strata, PhaseResult& out)
{
    const RawrXD::Deep2::Universal::IngestReport& rep = RawrXD::Deep2::Universal::Ingest(model, false);
    if (!rep.ok) {
        out.error = "ingest: " + rep.error;
        return false;
    }
    RuntimeGraph::Executor ex;
    ex.SetForceCpu(!gpu);
    if (strata) {
        ex.SetStrataExpertTracking(true);
        ex.SetStrataCachePolicy(0);
    }
    if (!ex.Bind(rep)) {
        out.error = "bind: " + ex.Stats().error;
        return false;
    }
    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        if (!ex.ExecuteToken(tokens[pos], pos)) {
            out.error = "execute at pos " + std::to_string(pos);
            return false;
        }
    }
    const auto& stats = ex.Stats();
    const QuantDot::CacheStats cs = QuantDot::GetCacheStats();
    out.ok = true;
    out.ops = stats.ops_total;
    out.gpuCalls = stats.gpu_calls;
    out.cpuCalls = stats.cpu_calls;
    out.hits = cs.hits;
    out.misses = cs.misses;
    out.evictions = cs.evictions;
    out.evictionsBudget = cs.evictions_budget;
    out.evictionsTrim = cs.evictions_trim;
    out.deviceBytes = cs.device_bytes_live;
    out.signature = Signature(ex.Logits());
    out.model = model;
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    std::string modelA, modelB, outdir = "strata_lifecycle_out", tag = "lifecycle";
    bool gpu = true, strata = true;
    std::vector<uint32_t> tokens = {1u, 450u};

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model-a" && i + 1 < argc) modelA = argv[++i];
        else if (a == "--model-b" && i + 1 < argc) modelB = argv[++i];
        else if (a == "--outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "--tag" && i + 1 < argc) tag = argv[++i];
        else if (a == "--cpu") gpu = false;
        else if (a == "--gpu") gpu = true;
        else if (a == "--no-strata") strata = false;
    }
    if (modelA.empty() || modelB.empty()) {
        std::printf("usage: deep2_lifecycle_probe.exe --model-a <gguf> --model-b <gguf> "
                    "[--gpu|--cpu] [--no-strata] [--outdir D] [--tag T]\n");
        return 2;
    }

    const std::vector<std::string> order = {modelA, modelB, modelA};
    const char* labels[3] = {"A1", "B", "A2"};
    std::vector<PhaseResult> phases(3);

    for (int i = 0; i < 3; ++i) {
        std::printf("[%s] loading %s ...\n", labels[i], order[i].c_str());
        std::fflush(stdout);
        if (!RunPhase(order[i], tokens, gpu, strata, phases[i])) {
            std::printf("[%s] FAIL %s\n", labels[i], phases[i].error.c_str());
            return 1;
        }
        const PhaseResult& p = phases[i];
        std::printf("[%s] gpu=%llu cpu=%llu hits=%llu misses=%llu evictions=%llu "
                    "(budget=%llu trim=%llu) live=%llu signature=%.9g\n",
                    labels[i], (unsigned long long)p.gpuCalls, (unsigned long long)p.cpuCalls,
                    (unsigned long long)p.hits, (unsigned long long)p.misses,
                    (unsigned long long)p.evictions, (unsigned long long)p.evictionsBudget,
                    (unsigned long long)p.evictionsTrim, (unsigned long long)p.deviceBytes,
                    p.signature);
        std::fflush(stdout);
    }

    const double relA = std::fabs(phases[0].signature - phases[2].signature) /
                        (std::fabs(phases[0].signature) + 1e-12);
    const double relB = std::fabs(phases[0].signature - phases[1].signature) /
                        (std::fabs(phases[0].signature) + 1e-12);

    std::printf("DETERMINISM A1_vs_A2 rel=%.6g %s\n", relA,
                relA < 1e-3 ? "PASS" : "FAIL");
    std::printf("SEPARATION  A1_vs_B  rel=%.6g %s\n", relB,
                relB > 1e-3 ? "PASS (models differ)" : "FAIL (possible cache aliasing)");

    const bool pass = relA < 1e-3 && relB > 1e-3 &&
                      phases[0].cpuCalls == 0 && phases[1].cpuCalls == 0 &&
                      phases[2].cpuCalls == 0;
    std::printf("LIFECYCLE_STATUS %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}