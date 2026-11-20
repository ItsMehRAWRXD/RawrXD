// Unit tests for the shared backend selection contract.
// Build: cl /std:c++17 /EHsc /I../.. backend_registry_test.cpp
// Exit code 0 = all checks passed.

#include "src/agentic/BackendRegistry.hpp"

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
                       ""};
    r[1] = BackendInfo{BackendId::Strata, "strata", EngineKind::Deep2, strataHealth,
                       Capabilities{Support::Unverified, Support::Unverified,
                                    Support::Unsupported, Support::Unsupported},
                       ""};
    r[2] = BackendInfo{BackendId::Ollama, "ollama", EngineKind::Ollama, ollamaHealth,
                       Capabilities{Support::Verified, Support::Verified,
                                    Support::Verified, Support::Verified},
                       ""};
    return r;
}

int main() {
    const auto reg = MakeRegistry(Health::Available, Health::Available, Health::Available);

    // 1. Strata resolves to the Deep2 engine family, never to a third runtime.
    {
        const auto r = ResolveSelection(BackendId::Strata, reg, /*residencyReady=*/true,
                                        /*allowFallback=*/false);
        CHECK(r.selection.has_value());
        CHECK(!r.error.has_value());
        CHECK(r.selection->engine == EngineKind::Deep2);
        CHECK(r.selection->selected == BackendId::Strata);
        CHECK(r.selection->strataExpertResidency);
        CHECK(!r.selection->strataInt8KVCache);
    }

    // 2. Explicit selection survives serialisation round-trip.
    {
        BackendSelection s{};
        s.selected = BackendId::Strata;
        s.engine = EngineKind::Deep2;
        s.strataExpertResidency = true;
        s.strataInt8KVCache = true;
        s.allowFallback = true;

        const std::string wire = SerializeSelection(s);
        CHECK(wire == "strata,strata=1,int8kv=1,fallback=1");
        const auto back = DeserializeSelection(wire);
        CHECK(back.has_value());
        CHECK(back->selected == s.selected);
        CHECK(back->engine == s.engine);
        CHECK(back->strataExpertResidency == s.strataExpertResidency);
        CHECK(back->strataInt8KVCache == s.strataInt8KVCache);
        CHECK(back->allowFallback == s.allowFallback);
    }

    // 3. Unavailable Strata returns an error instead of substituting Deep2.
    {
        const auto bad = MakeRegistry(Health::Available, Health::Unavailable, Health::Available);
        const auto r = ResolveSelection(BackendId::Strata, bad, true, false);
        CHECK(!r.selection.has_value());
        CHECK(r.error.has_value());
        CHECK(r.error->find("strata") != std::string::npos);
    }

    // 3b. Strata that is healthy but cannot activate residency is STRATA_NOT_ROUTABLE.
    {
        const auto r = ResolveSelection(BackendId::Strata, reg, /*residencyReady=*/false, false);
        CHECK(!r.selection.has_value());
        CHECK(r.error.has_value());
        CHECK(r.error->find("STRATA_NOT_ROUTABLE") != std::string::npos);
    }

    // 4. Fallback stays disabled unless explicitly approved.
    {
        const auto no = ResolveSelection(BackendId::Deep2, reg, true, /*allowFallback=*/false);
        CHECK(no.selection.has_value());
        CHECK(!no.selection->allowFallback);

        const auto yes = ResolveSelection(BackendId::Deep2, reg, true, /*allowFallback=*/true);
        CHECK(yes.selection.has_value());
        CHECK(yes.selection->allowFallback);

        // A failed backend must not silently fall back to a healthy one.
        const auto broken = MakeRegistry(Health::Failed, Health::Available, Health::Available);
        const auto r = ResolveSelection(BackendId::Deep2, broken, true, /*allowFallback=*/true);
        CHECK(!r.selection.has_value());
        CHECK(r.error.has_value());
    }

    // 5. Capabilities distinguish verified from unsupported features.
    {
        const BackendInfo& strata = reg[1];
        CHECK(strata.capabilities.chat == Support::Unverified);
        CHECK(strata.capabilities.toolCalls == Support::Unsupported);
        CHECK(ToString(strata.capabilities.toolCalls) == std::string_view("unsupported"));

        const BackendInfo& ollama = reg[2];
        CHECK(ollama.capabilities.toolCalls == Support::Verified);
        CHECK(ollama.capabilities.autonomousRepair == Support::Verified);
    }

    // 6. Ollama keeps its own engine family.
    {
        const auto r = ResolveSelection(BackendId::Ollama, reg, false, false);
        CHECK(r.selection.has_value());
        CHECK(r.selection->engine == EngineKind::Ollama);
        CHECK(!r.selection->strataExpertResidency);
    }

    // 7. Malformed persistence is rejected rather than guessed at.
    {
        CHECK(!DeserializeSelection("bogus").has_value());
        CHECK(!DeserializeSelection("deep2,int8kv=1").has_value());  // int8kv on a non-Strata backend
        CHECK(!DeserializeSelection("ollama,strata=1").has_value()); // residency on Ollama
        CHECK(DeserializeSelection("deep2").has_value());
        CHECK(DeserializeSelection("strata,int8kv=1").has_value());  // Strata with int8 KV
        CHECK(DeserializeSelection("").has_value() == false);
    }

    if (g_failures == 0) {
        std::printf("BACKEND_REGISTRY_TESTS=PASS\n");
        return 0;
    }
    std::printf("BACKEND_REGISTRY_TESTS=FAIL count=%d\n", g_failures);
    return 1;
}