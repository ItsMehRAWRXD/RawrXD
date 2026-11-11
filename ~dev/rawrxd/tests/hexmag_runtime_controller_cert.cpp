// hexmag_runtime_controller_cert.cpp — HEXMAG_RUNTIME_CONTROLLER_001
// Certifies: state machine sequencing, fail-closed, tuner mutation, FinalizePolicy authority

#include "core/hexmag_runtime_controller.hpp"
#include "core/hexmag_finalize_policy.hpp"
#include "core/hexmag_repeat_tuner.hpp"
#include <cstdio>
#include <string>
#include <vector>

using namespace RawrXD::HexMag;

struct DeterministicTransport final : IHexMagTransport {
    std::vector<ClientAskResult> results;
    size_t idx = 0;
    ClientAskResult ask(const std::string&, const std::string&) override {
        if (idx >= results.size()) {
            ClientAskResult r;
            r.ask.error = "exhausted";
            return r;
        }
        return results[idx++];
    }
};

bool testPhaseOrdering() {
    DeterministicTransport transport;
    transport.results = {
        ClientAskResult{.ask = {.action = "read", .path = "test.cpp"}, .event = {.ok = true, .data = "source"}},
        ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "fixed"}, .event = {.ok = true}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 2});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    
    // Verify phase sequence includes expected transitions
    bool sawRequest = false, sawDispatch = false, sawClientResult = false, sawCandidate = false, sawVerify = false, sawFinal = false;
    for (auto p : r.phases) {
        if (p == ControllerPhase::Request) sawRequest = true;
        if (p == ControllerPhase::Dispatch) sawDispatch = true;
        if (p == ControllerPhase::AwaitEvents) sawClientResult = true;
        if (p == ControllerPhase::CandidateReview) sawCandidate = true;
        if (p == ControllerPhase::VerifyRoute) sawVerify = true;
        if (p == ControllerPhase::FinalizeEval) sawFinal = true;
    }
    if (!sawRequest || !sawDispatch || !sawClientResult || !sawCandidate || !sawVerify || !sawFinal) {
        std::printf("  missing phases: request=%d dispatch=%d client=%d cand=%d verify=%d final=%d\n",
            sawRequest, sawDispatch, sawClientResult, sawCandidate, sawVerify, sawFinal);
        return false;
    }
    return r.sequencingOk;
}

bool testMaxRetriesEnforced() {
    DeterministicTransport transport;
    // 5 bad candidates - should exhaust at maxRetries (3)
    for (int i = 0; i < 5; ++i) {
        transport.results.push_back(ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "bad"}, .event = {.ok = true}});
    }
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 3});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    
    // Must exhaust or fail closed
    if (r.phase != ControllerPhase::Exhausted && r.phase != ControllerPhase::FailedClosed) {
        return false;
    }
    // Must have attempted maxRetries times
    if (r.redispatches < 3) return false;
    // Generation should be maxRetries + 1 (initial + 3 retries)
    if (r.generation != 4) return false;
    return true;
}

bool testNeedInputLatchesNoRetry() {
    DeterministicTransport transport;
    transport.results = {
        ClientAskResult{.ask = {.action = "need_input", .path = ""}, .event = {.ok = false, .error = "need input"}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 3});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    
    if (r.phase != ControllerPhase::NeedInputLatched && r.phase != ControllerPhase::FailedClosed) {
        return false;
    }
    // Must NOT advance generation on NEED_INPUT
    if (r.generation != 1) return false;
    if (r.attempt != 0) return false;
    if (!r.needInputLatched) return false;
    // Must not have redispatched
    if (r.redispatches != 0) return false;
    return true;
}

bool testFinalizePolicyIsAuthority() {
    FinalizePolicy policy;
    
    // Valid candidate
    Candidate c1{};
    c1.content = "return a + b;";
    c1.kind = CandidateKind::CodeChange;
    auto d1 = policy.evaluate(c1);
    if (!d1.allowed) return false;
    
    // Empty candidate
    Candidate c2{};
    c2.content = "";
    auto d2 = policy.evaluate(c2);
    if (d2.allowed) return false;
    
    // Wrong kind
    Candidate c3{};
    c3.content = "fix";
    c3.kind = CandidateKind::Explanation;
    auto d3 = policy.evaluate(c3);
    if (d3.allowed) return false;
    
    return true;
}

bool testControllerDoesNotFabricateFinal() {
    DeterministicTransport transport;
    transport.results = {
        ClientAskResult{.ask = {.action = "finish"}, .event = {.ok = true}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 1});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    
    // Controller must not fabricate final - only FinalizePolicy grants it
    if (r.fabricatedFinal) return false;
    return true;
}

bool testTunerMutationOnWrong() {
    // Test that WRONG failure triggers tuner mutation
    uint64_t req = 0xDEADBEEFDEADBEEFULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    uint32_t strat0 = p.strategy;
    uint32_t nonce0 = p.mutation_nonce;
    
    // WRONG failure
    HexMag_Tuner_Next(req, 0x0040, 1, &p); // HX_FAIL_WRONG
    
    if (p.strategy == strat0) return false;
    if (p.mutation_nonce == nonce0) return false;
    if (p.queue_policy != 1) return false; // Q_BLOCKING
    return true;
}

bool testWeightDeltaAlwaysZero() {
    // Persistent weight delta must always be 0
    uint32_t delta = HexMag_Tuner_WeightDelta();
    if (delta != 0) return false;
    return true;
}

bool testGenerationIdAdvances() {
    uint64_t req = 0xFEEDFACEFEEDFACEULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    
    uint64_t g1 = HexMag_Tuner_GenerationId();
    HexMag_Tuner_Next(req, 0x0040, 1, &p);
    uint64_t g2 = HexMag_Tuner_GenerationId();
    HexMag_Tuner_Next(req, 0x0040, 2, &p);
    uint64_t g3 = HexMag_Tuner_GenerationId();
    
    if (g2 != g1 + 1) return false;
    if (g3 != g2 + 1) return false;
    return true;
}

bool testScriptedTransport() {
    ScriptedHexMagTransport transport;
    transport.fn = [](const std::string&, const std::string&) -> ClientAskResult {
        return ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "fixed"}, .event = {.ok = true}};
    };
    
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 1});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    
    if (transport.callCount != 1) return false;
    if (r.phase != ControllerPhase::Done && r.phase != ControllerPhase::FinalizeEval) return false;
    return true;
}

bool testResetSession() {
    DeterministicTransport transport;
    transport.results = {
        ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "fixed"}, .event = {.ok = true}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 1});
    ctrl.run("fix test.cpp", "context");
    
    if (ctrl.generation() != 2) return false;
    if (ctrl.attempt() != 1) return false;
    
    ctrl.resetSession();
    
    if (ctrl.generation() != 1) return false;
    if (ctrl.attempt() != 0) return false;
    if (ctrl.needInputLatched()) return false;
    if (ctrl.finalGranted()) return false;
    return true;
}

int main() {
    int pass = 0, fail = 0;
    auto run = [&](const char* name, bool (*fn)()) {
        bool ok = fn();
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (ok) ++pass; else ++fail;
    };
    run("phase_ordering", testPhaseOrdering);
    run("max_retries_enforced", testMaxRetriesEnforced);
    run("need_input_latches_no_retry", testNeedInputLatchesNoRetry);
    run("finalize_policy_authority", testFinalizePolicyAuthority);
    run("no_fabricated_final", testControllerDoesNotFabricateFinal);
    run("tuner_mutation_on_wrong", testTunerMutationOnWrong);
    run("weight_delta_zero", testWeightDeltaAlwaysZero);
    run("generation_id_advances", testGenerationIdAdvances);
    run("scripted_transport", testScriptedTransport);
    run("reset_session", testResetSession);
    std::printf("\nVERDICT=%s pass=%d fail=%d\n", fail == 0 ? "PASS" : "FAIL", pass, fail);
    return fail == 0 ? 0 : 1;
}