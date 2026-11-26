// Unit tests for the authoritative backend-independent inference router.
// Build: g++ -std=c++17 -I../.. inference_router_test.cpp -o inference_router_test
// Exit code 0 = all checks passed.
//
// These tests encode the end-to-end acceptance matrix at the routing layer:
// every backend resolves to exactly one engine family, Strata is routable only
// when expert residency can be activated, and no backend is ever silently
// substituted. The agentic controller consumes only RouteDecision, so the same
// matrix is what the IDE/CLI dispatch on.

#include "src/agentic/InferenceRouter.hpp"

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

static std::array<BackendInfo, 3> MakeRegistry(Health deep2Health,
                                               Health strataHealth,
                                               Health ollamaHealth) {
    std::array<BackendInfo, 3> r{};
    r[0] = BackendInfo{BackendId::Deep2, "deep2", EngineKind::Deep2, deep2Health,
                       Capabilities{Support::Verified, Support::Verified,
                                    Support::Unverified, Support::Unverified},
                       deep2Health == Health::Available ? "" : "default GGUF missing"};
    r[1] = BackendInfo{BackendId::Strata, "strata", EngineKind::Deep2, strataHealth,
                       Capabilities{Support::Unverified, Support::Unverified,
                                    Support::Unsupported, Support::Unsupported},
                       strataHealth == Health::Available ? "" : "residency not activated"};
    r[2] = BackendInfo{BackendId::Ollama, "ollama", EngineKind::Ollama, ollamaHealth,
                       Capabilities{Support::Verified, Support::Verified,
                                    Support::Verified, Support::Verified},
                       ""};
    return r;
}

int main() {
    const auto reg = MakeRegistry(Health::Available, Health::Available, Health::Available);
    const ResidencyReadiness ready{true, ""};
    const ResidencyReadiness notReady{false, "no Deep2 GGUF / Strata mode unavailable"};

    // 1. Streaming-chat baseline: Ollama routes to its own engine family.
    {
        const auto r = RouteBackend(BackendId::Ollama, reg, notReady, false);
        CHECK(r.decision.has_value());
        CHECK(!r.error.has_value());
        CHECK(r.decision->selection.engine == EngineKind::Ollama);
        CHECK(r.decision->selection.selected == BackendId::Ollama);
        CHECK(!r.decision->strata.expertTracking);
        CHECK(r.decision->summary.find("engine=ollama") != std::string::npos);
    }

    // 2. Plain Deep2 (native Vulkan) routes to Deep2 with no Strata knobs.
    {
        const auto r = RouteBackend(BackendId::Deep2, reg, notReady, false);
        CHECK(r.decision.has_value());
        CHECK(r.decision->selection.engine == EngineKind::Deep2);
        CHECK(!r.decision->selection.strataExpertResidency);
        CHECK(!r.decision->strata.expertTracking);
        CHECK(!r.decision->strata.int8KV);
    }

    // 3. Strata WITH residency ready -> Deep2 engine + expert residency knobs.
    {
        const auto r = RouteBackend(BackendId::Strata, reg, ready, false);
        CHECK(r.decision.has_value());
        CHECK(!r.error.has_value());
        CHECK(r.decision->selection.engine == EngineKind::Deep2);
        CHECK(r.decision->selection.selected == BackendId::Strata);
        CHECK(r.decision->selection.strataExpertResidency);
        CHECK(r.decision->strata.expertTracking);
        CHECK(r.decision->strata.cachePolicy == 0);
        CHECK(!r.decision->strata.int8KV);
        CHECK(r.decision->summary.find("strata=expert-residency") != std::string::npos);
    }

    // 4. THE BLOCKER: Strata WITHOUT residency is STRATA_NOT_ROUTABLE, never Deep2.
    {
        const auto r = RouteBackend(BackendId::Strata, reg, notReady, false);
        CHECK(!r.decision.has_value());
        CHECK(r.error.has_value());
        CHECK(r.error->find("STRATA_NOT_ROUTABLE") != std::string::npos);
    }

    // 5. Unavailable backend errors instead of substituting a healthy one,
    //    even when fallback is permitted (fail-closed).
    {
        const auto broken = MakeRegistry(Health::Failed, Health::Available, Health::Available);
        const auto r = RouteBackend(BackendId::Deep2, broken, ready, /*allowFallback=*/true);
        CHECK(!r.decision.has_value());
        CHECK(r.error.has_value());
        CHECK(r.error->find("deep2") != std::string::npos);
    }

    // 6. String overload matches the enum overload and rejects unknown text.
    {
        const auto a = RouteBackend(std::string_view("strata"), reg, ready, false);
        const auto b = RouteBackend(BackendId::Strata, reg, ready, false);
        CHECK(a.decision.has_value());
        CHECK(b.decision.has_value());
        CHECK(a.decision->selection.engine == b.decision->selection.engine);
        CHECK(a.decision->strata.expertTracking == b.decision->strata.expertTracking);

        const auto bad = RouteBackend(std::string_view("bogus"), reg, ready, false);
        CHECK(!bad.decision.has_value());
        CHECK(bad.error.has_value());
        CHECK(bad.error->find("unknown backend") != std::string::npos);
    }

    // 7. int8 KV tier is carried through when the persisted selection sets it.
    {
        BackendSelection s{};
        s.selected = BackendId::Strata;
        s.engine = EngineKind::Deep2;
        s.strataExpertResidency = true;
        s.strataInt8KVCache = true;
        const auto wire = SerializeSelection(s);
        const auto back = DeserializeSelection(wire);
        CHECK(back.has_value());
        const StrataOptions o = StrataOptionsFor(*back);
        CHECK(o.expertTracking);
        CHECK(o.int8KV);
    }

    // 8. Backend-independence invariant: every routable backend yields a
    //    decision of identical shape; only selection.engine + strata knobs
    //    differ. This is what lets one agent controller drive all three.
    {
        const auto o = RouteBackend(BackendId::Ollama, reg, ready, false);
        const auto d = RouteBackend(BackendId::Deep2, reg, ready, false);
        const auto s = RouteBackend(BackendId::Strata, reg, ready, false);
        CHECK(o.decision.has_value() && d.decision.has_value() && s.decision.has_value());
        // Exactly one engine family per selection, and Strata reuses Deep2.
        CHECK(o.decision->selection.engine == EngineKind::Ollama);
        CHECK(d.decision->selection.engine == EngineKind::Deep2);
        CHECK(s.decision->selection.engine == EngineKind::Deep2);
    }

    if (g_failures == 0) {
        std::printf("INFERENCE_ROUTER_TESTS=PASS\n");
        return 0;
    }
    std::printf("INFERENCE_ROUTER_TESTS=FAIL count=%d\n", g_failures);
    return 1;
}