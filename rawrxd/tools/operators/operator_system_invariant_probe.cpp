// Compile/instantiation probe for RawrOperatorSystem.hpp.
// This is a TYPE-CHECK probe only. It asserts nothing about product adoption.
#include "operators/RawrOperatorSystem.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace rawrxd::operators;

// Force instantiation of every non-template member so the compiler cannot
// skip an ill-formed body. A header that merely parses is not a contract.
static void probeInstantiation()
{
    StaticMap map;
    OperatorSystem ops(map);

    Root r;
    r.id = "probe.root";
    r.execute = []() -> Evidence {
        return Evidence{ .executed = true, .outputCount = 1 };
    };
    (void)map.addRoot(r);
    (void)map.addAlias(Alias{ .mapKey = "probe.key", .rootId = "probe.root" });

    (void)ops.drow(Word{ "probe" });
    (void)OperatorSystem::nuDrowReverseScrape(std::vector<std::string>{ "a -> b" });
    (void)OperatorSystem::unbindOneLine("x -> y");
    (void)ops.loot("probe.key");
    (void)ops.resolve("probe.key");
    (void)ops.bypass("probe.missing");
    (void)ops.skip("probe.missing");
    (void)ops.bowRainStar();

    if (Root* root = ops.resolve("probe.key")) {
        (void)ops.bind("probe.key");
        (void)ops.hotpatch("probe.key");
        const Evidence e = ops.on(*root);
        (void)ops.verify(*root, e);
    }

    (void)ops.executeWord(Word{ "probe" });
}

int main()
{
    probeInstantiation();

    // --- falsification probe: does the invariant actually reject? ---------
    // A contract that cannot disagree is not a contract.
    int failures = 0;

    // Zero output count must NOT prove execution, even if every other flag is
    // set. This is the exact shape of the retracted false-PASS receipts.
    const Evidence zeroCount{
        .executed = true,
        .producedOutput = true,
        .measurementPresent = true,
        .callbacksObserved = true,
        .outputCount = 0,
        .detail = "claims_success_produced_nothing"
    };
    if (zeroCount.provesExecution()) {
        std::printf("FAIL: zero-output Evidence proved execution\n");
        ++failures;
    }

    // No measurement present must NOT prove execution.
    const Evidence unmeasured{
        .executed = true,
        .producedOutput = true,
        .measurementPresent = false,
        .callbacksObserved = true,
        .outputCount = 7
    };
    if (unmeasured.provesExecution()) {
        std::printf("FAIL: unmeasured Evidence proved execution\n");
        ++failures;
    }

    // The positive control: all four conjuncts satisfied.
    const Evidence real{
        .executed = true,
        .producedOutput = true,
        .measurementPresent = true,
        .callbacksObserved = true,
        .outputCount = 7
    };
    if (!real.provesExecution()) {
        std::printf("FAIL: genuine Evidence did not prove execution\n");
        ++failures;
    }

    // CREATE must not verify before execution. A created root is COLD.
    {
        StaticMap m;
        OperatorSystem o(m);
        o.setRootFactory([](std::string_view k) -> std::optional<Root> {
            Root nr;
            nr.id = std::string(k);
            nr.execute = []() -> Evidence {
                return Evidence{
                    .executed = true,
                    .producedOutput = true,
                    .measurementPresent = true,
                    .callbacksObserved = true,
                    .outputCount = 1
                };
            };
            return nr;
        });

        Root* created = o.create("cold.key");
        if (created == nullptr) {
            std::printf("FAIL: CRE produced no root\n");
            ++failures;
        } else if (created->proof != ProofState::Cold) {
            std::printf("FAIL: created root was not COLD\n");
            ++failures;
        } else if (created->executable()) {
            std::printf("FAIL: created root was executable before BIND\n");
            ++failures;
        }

        if (m.alias("cold.key") != nullptr && !m.alias("cold.key")->cold) {
            std::printf("FAIL: alias was promoted out of cold by creation\n");
            ++failures;
        }
    }

    // UN-BIND must ignore plain prose and accept a structural line.
    if (OperatorSystem::unbindOneLine("the model becomes pass and the engine on")
            .has_value()) {
        std::printf("FAIL: UN-BIND scraped plain prose as structure\n");
        ++failures;
    }
    if (!OperatorSystem::unbindOneLine("compute::requestRoute(x)").has_value()) {
        std::printf("FAIL: UN-BIND rejected a structural line\n");
        ++failures;
    }

    // BOW-RAIN must not collapse a failing node into an aggregate pass.
    {
        StaticMap m;
        OperatorSystem o(m);

        Root good;
        good.id = "good";
        good.execute = []() -> Evidence {
            return Evidence{
                .executed = true, .producedOutput = true,
                .measurementPresent = true, .callbacksObserved = true,
                .outputCount = 1
            };
        };
        Root bad;
        bad.id = "bad";
        bad.execute = []() -> Evidence {
            return Evidence{ .executed = false, .outputCount = 0 };
        };

        (void)m.addRoot(good);
        (void)m.addRoot(bad);
        (void)m.addAlias(Alias{ .mapKey = "k.good", .rootId = "good" });
        (void)m.addAlias(Alias{ .mapKey = "k.bad",  .rootId = "bad"  });

        o.setRootFactory([](std::string_view) -> std::optional<Root> {
            return std::nullopt;  // cannot rescue the failing node
        });

        int verified = 0;
        int unverified = 0;
        for (const ExecutionResult& r : o.bowRainStar()) {
            if (r.verified) ++verified; else ++unverified;
        }

        if (verified != 1 || unverified != 1) {
            std::printf("FAIL: BOW-RAIN did not report per-node results "
                        "(verified=%d unverified=%d, expected 1/1)\n",
                        verified, unverified);
            ++failures;
        }
    }

    std::printf("OPERATOR_SYSTEM_INVARIANT_CHECKS_RUN=6\n");
    std::printf("OPERATOR_SYSTEM_INVARIANT_FAILURES=%d\n", failures);
    std::printf("VERDICT=%s\n", failures == 0 ? "PASS" : "FAIL");

    return failures == 0 ? 0 : 1;
}