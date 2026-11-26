// Unit + real-model tests for the corrected Strata residency readiness probe.
// Build: g++ -std=c++17 -I../.. strata_readiness_test.cpp -o strata_readiness_test
// Usage: strata_readiness_test <dense.gguf> <moe.gguf>
// Exit 0 = all checks passed.
//
// Proves the critical correction: GGUF presence alone does NOT establish
// residency readiness. A dense model is NOT ready; a genuine MoE model is.

#include "src/agentic/StrataReadiness.hpp"

#include <cstdio>
#include <string>

using namespace rawrxd;

static int g_failures = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);     \
            ++g_failures;                                                  \
        }                                                                  \
    } while (0)

int main(int argc, char** argv) {
    const std::string dense = argc > 1 ? argv[1] : "models/tinyllama.gguf";
    const std::string moe   = argc > 2 ? argv[2] : "models/deepseek-coder-v2_16b.gguf";

    // 1. Missing / empty path is never ready.
    {
        const auto rr = ProbeStrataReadiness("");
        CHECK(!rr.ready);
        CHECK(rr.detail.find("no model") != std::string::npos);
        const auto missing = ProbeStrataReadiness("does/not/exist.gguf");
        CHECK(!missing.ready);
    }

    // 2. Dense model: present on disk but NOT residency-ready.
    {
        const GgufResidencyProbe p = ProbeGgufMoE(dense);
        std::printf("dense probe: parseOk=%d moe=%d experts=%u arch='%s' err='%s'\n",
                    p.parseOk, p.moe, p.numExperts, p.architecture.c_str(), p.error.c_str());
        CHECK(p.parseOk);
        CHECK(!p.moe);
        const auto rr = ProbeStrataReadiness(dense);
        CHECK(!rr.ready);
        CHECK(rr.detail.find("dense") != std::string::npos);
    }

    // 3. Genuine MoE model: ready with expert count > 0.
    {
        const GgufResidencyProbe p = ProbeGgufMoE(moe);
        std::printf("moe probe:    parseOk=%d moe=%d experts=%u arch='%s' err='%s'\n",
                    p.parseOk, p.moe, p.numExperts, p.architecture.c_str(), p.error.c_str());
        CHECK(p.parseOk);
        CHECK(p.moe);
        CHECK(p.numExperts > 0);
        const auto rr = ProbeStrataReadiness(moe);
        CHECK(rr.ready);
        CHECK(rr.detail.find("experts") != std::string::npos);
    }

    // 4. The router consumes the probe: MoE -> Strata routable, dense -> blocked.
    {
        std::array<BackendInfo, 3> reg{};
        reg[0] = BackendInfo{BackendId::Deep2, "deep2", EngineKind::Deep2, Health::Available,
                             Capabilities{Support::Verified, Support::Verified, Support::Unverified,
                                          Support::Unverified}, ""};
        reg[1] = BackendInfo{BackendId::Strata, "strata", EngineKind::Deep2, Health::Available,
                             Capabilities{Support::Unverified, Support::Unverified,
                                          Support::Unsupported, Support::Unsupported}, ""};
        reg[2] = BackendInfo{BackendId::Ollama, "ollama", EngineKind::Ollama, Health::Available,
                             Capabilities{Support::Verified, Support::Verified, Support::Verified,
                                          Support::Verified}, ""};

        const auto moeReady = ProbeStrataReadiness(moe);
        const auto rMoe = RouteBackend(BackendId::Strata, reg, moeReady, false);
        CHECK(rMoe.decision.has_value());
        CHECK(rMoe.decision->strata.expertTracking);

        const auto denseReady = ProbeStrataReadiness(dense);
        const auto rDense = RouteBackend(BackendId::Strata, reg, denseReady, false);
        CHECK(!rDense.decision.has_value());
        CHECK(rDense.error.has_value());
        CHECK(rDense.error->find("STRATA_NOT_ROUTABLE") != std::string::npos);
    }

    if (g_failures == 0) { std::printf("STRATA_READINESS_TESTS=PASS\n"); return 0; }
    std::printf("STRATA_READINESS_TESTS=FAIL count=%d\n", g_failures);
    return 1;
}