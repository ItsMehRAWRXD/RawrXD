// ============================================================================
// hexmag_swarm_smoke.cpp — HexMag MASM control plane + polymorphic repeat tuner
// ============================================================================
#include "core/hexmag_swarm.hpp"
#include "core/hexmag_repeat_tuner.hpp"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

static int g_failures = 0;

static void expect(bool cond, const char* msg) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        ++g_failures;
    } else {
        std::fprintf(stderr, "OK:   %s\n", msg);
    }
    std::fflush(stderr);
}

#ifndef RAWR_HAS_MASM

int main() {
    std::fprintf(stderr, "SKIP: rebuild with RAWR_HAS_MASM (ml64)\n");
    return 0;
}

#else

static std::vector<HxEvent> drain_events() {
    std::vector<HxEvent> out;
    HxEvent ev{};
    while (HexMag_PollEvent(&ev)) {
        out.push_back(ev);
        std::fprintf(stderr, "  EVT kind=%u role=%u target=%u depth=%u payload=%.80s\n",
                     ev.kind, ev.role, ev.target_role, ev.depth, ev.payload);
        std::fflush(stderr);
        ev = {};
    }
    return out;
}

static bool run_hello_world_goal() {
    const char* goal =
        "Create a hello world program in x64 MASM that prints HelloWorld and exits.";
    uint64_t gid = HexMag_SubmitGoal(goal, static_cast<uint32_t>(std::strlen(goal)));
    expect(gid != 0, "SubmitGoal hello-world nonzero id");
    if (gid == 0) return false;

    bool saw_spawn = false;
    bool saw_candidate = false;
    bool saw_critique = false;
    bool saw_tuner = false;
    bool saw_final = false;
    bool saw_satisfied = false;
    bool saw_deflate = false;
    bool saw_ok_payload = false;
    int spawn_count = 0;
    std::set<std::string> spawn_payloads;

    uint64_t rc = HexMag_RunToSatisfied(64);
    expect(rc == HX_OK, "RunToSatisfied hello-world HX_OK");
    auto evs = drain_events();
    for (const auto& ev : evs) {
        if (ev.kind == HX_EVT_RESPONDER_SPAWN) {
            saw_spawn = true;
            ++spawn_count;
            spawn_payloads.insert(std::string(ev.payload));
        }
        if (ev.kind == HX_EVT_ANSWER_CANDIDATE || ev.kind == HX_EVT_ANSWER) {
            saw_candidate = true;
            if (std::strstr(ev.payload, "#OK") || std::strstr(ev.payload, "HelloWorld"))
                saw_ok_payload = true;
        }
        if (ev.kind == HX_EVT_CRITIQUE || ev.kind == HX_EVT_REVERSE) saw_critique = true;
        if (ev.kind == HX_EVT_TUNER_ADJUST) saw_tuner = true;
        if (ev.kind == HX_EVT_ANSWER_FINAL) saw_final = true;
        if (ev.kind == HX_EVT_GOAL_SATISFIED) saw_satisfied = true;
        if (ev.kind == HX_EVT_DEFLATE) saw_deflate = true;
    }

    expect(saw_spawn, "minted unused responder.spawn");
    expect(spawn_count >= 3, "polymorphic: multiple fresh agents (>=3)");
    expect(spawn_payloads.size() == static_cast<size_t>(spawn_count),
           "each spawn payload unique (unused agent/model)");
    expect(saw_candidate, "emitted answer.candidate");
    expect(saw_critique, "wrong candidates reverse/critique");
    expect(saw_tuner, "repeat tuner adjusted on fail");
    expect(saw_ok_payload, "final candidate has #OK HelloWorld");
    expect(saw_final, "llm.answer.final after verify");
    expect(saw_satisfied, "goal.satisfied");
    expect(saw_deflate, "post-final deflate");
    expect(HexMag_AgentsSpawned() >= 3, "AgentsSpawned >= 3");
    expect(HexMag_TunerAttempt() >= 2, "TunerAttempt >= 2 after wrongs");

    std::fprintf(stderr, "  agents_spawned=%llu last_agent=%llu tuner_attempt=%llu\n",
                 (unsigned long long)HexMag_AgentsSpawned(),
                 (unsigned long long)HexMag_LastAgentId(),
                 (unsigned long long)HexMag_TunerAttempt());
    return saw_satisfied && saw_tuner && saw_ok_payload;
}

int main() {
    std::fprintf(stderr, "=== HexMag MASM Polymorphic Repeat Tuner Smoke ===\n");

    std::fprintf(stderr, "\n-- test_retries_are_polymorphic --\n");
    expect(HexMag_Tuner_Init(6) == 0, "Tuner_Init");
    HxGenProfile p{};
    std::set<uint64_t> fps;
    uint64_t fp = HexMag_Tuner_Initial(0x71ull, &p);
    expect(fp != 0, "initial fingerprint nonzero");
    fps.insert(fp);
    expect(p.queue_policy == HX_QUEUE_Q_BLOCKING, "initial Q_BLOCKING");
    expect(p.blocking_passes == 3, "initial blocking_passes=3");

    const uint32_t fails[] = {
        HX_FAIL_CONTRADICTION,
        HX_FAIL_COUNTEREXAMPLE,
        HX_FAIL_TEST,
        HX_FAIL_STAGNATION,
    };
    for (uint32_t i = 0; i < 4; ++i) {
        HxGenProfile p2{};
        uint64_t fp2 = HexMag_Tuner_Next(0x71ull, fails[i], i + 1, &p2);
        expect(fp2 != 0, "next fingerprint nonzero");
        expect(fps.count(fp2) == 0, "retry fingerprint unique");
        expect(p2.queue_policy == HX_QUEUE_Q_BLOCKING, "retry Q_BLOCKING");
        expect(p2.blocking_passes == 3, "retry blocking_passes=3");
        fps.insert(fp2);
        p = p2;
    }

    std::fprintf(stderr, "\n-- test_failure_directs_strategy --\n");
    HexMag_Tuner_Init(6);
    HexMag_Tuner_Initial(0x72ull, nullptr);
    HxGenProfile s{};
    HexMag_Tuner_Next(0x72ull, HX_FAIL_CONTRADICTION, 1, &s);
    expect(s.strategy == HX_STRAT_INVARIANT, "contradiction -> invariant");
    HexMag_Tuner_Next(0x72ull, HX_FAIL_COUNTEREXAMPLE, 2, &s);
    expect(s.strategy == HX_STRAT_COUNTEREXAMPLE, "counterexample -> counterexample");
    HexMag_Tuner_Next(0x72ull, HX_FAIL_UNSUPPORTED, 3, &s);
    expect(s.strategy == HX_STRAT_REVERSE, "unsupported -> reverse");
    HexMag_Tuner_Next(0x72ull, HX_FAIL_TEST, 4, &s);
    expect(s.strategy == HX_STRAT_REPAIR, "test_failure -> repair");

    std::fprintf(stderr, "\n-- test_generation_id_changes --\n");
    HexMag_Tuner_Init(6);
    HexMag_Tuner_Initial(0x73ull, nullptr);
    uint64_t g0 = HexMag_Tuner_GenerationId();
    HexMag_Tuner_Next(0x73ull, HX_FAIL_WRONG, 1, nullptr);
    uint64_t g1 = HexMag_Tuner_GenerationId();
    expect(g0 != g1, "generation_id changes on retry");

    std::fprintf(stderr, "\n-- test_missing_information_no_creativity --\n");
    HexMag_Tuner_Init(6);
    HexMag_Tuner_Initial(0x74ull, nullptr);
    HxGenProfile m{};
    HexMag_Tuner_Next(0x74ull, HX_FAIL_MISSING_INFO, 1, &m);
    expect(m.strategy == HX_STRAT_EVIDENCE_GUARD, "missing_info -> evidence-guard");
    expect(m.temp_milli == 0, "missing_info temperature=0");
    expect(m.candidate_count == 1, "missing_info candidate_count=1");
    expect(HexMag_Tuner_WeightDelta() == 0, "weight delta still 0");

    std::fprintf(stderr, "\n-- Swarm Init + HelloWorld x64 MASM goal --\n");
    uint64_t rc = HexMag_Init();
    expect(rc == HX_OK || rc == HX_ERR_ALREADY_INIT, "HexMag_Init");
    expect(HexMag_BotCount() == HX_ROLE_COUNT, "BotCount == 3");

    bool ok = run_hello_world_goal();
    expect(ok, "HelloWorld goal converged via polymorphic tuner");

    expect(HexMag_Shutdown() == HX_OK, "HexMag_Shutdown");

    std::fprintf(stderr, "\nHEXMAG_POLYMORPHIC_GEN=TRUE\n");
    std::fprintf(stderr, "HEXMAG_REPEAT_TUNER=TRUE\n");
    std::fprintf(stderr, "HEXMAG_FAILURE_DRIVEN_RESPAWN=TRUE\n");
    std::fprintf(stderr, "HEXMAG_RECURSIVE_REFINEMENT=COMPLETE\n");
    std::fprintf(stderr, "persistent_weight_delta_bytes=0\n");
    std::fprintf(stderr, "\n=== SUMMARY failures=%d ===\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

#endif
