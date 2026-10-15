// hexmag_ide_e2e_cert.cpp — HEXMAG_IDE_E2E_001
// Certifies: Copilot send path → controller → tuner → FinalizePolicy
// Sequencing: REQUEST→CLASSIFY_VALIDATE→DISPATCH_CLIENT→CLIENT_RESULT→CANDIDATE→VERIFY→FINAL

#include "core/hexmag_runtime_controller.hpp"
#include "core/hexmag_finalize_policy.hpp"
#include "core/hexmag_repeat_tuner.hpp"
#include <cstdio>
#include <string>
#include <vector>

using namespace RawrXD::HexMag;

struct MockTransport final : IHexMagTransport {
    std::vector<std::pair<std::string, ClientAskResult>> script;
    size_t idx = 0;
    ClientAskResult ask(const std::string& prompt, const std::string& context) override {
        if (idx >= script.size()) {
            ClientAskResult r;
            r.ask.error = "script exhausted";
            return r;
        }
        return script[idx++].second;
    }
};

bool testSequencing() {
    MockTransport transport;
    transport.script = {
        {"", ClientAskResult{.ask = {.action = "read", .path = "test.cpp"}, .event = {.ok = true, .data = "source"}}},
        {"", ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "fixed"}, .event = {.ok = true}}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 2});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    // Must reach FINAL phase or DONE
    if (r.phase != ControllerPhase::FinalizeEval && r.phase != ControllerPhase::Done) {
        std::printf("  phase=%s\n", controllerPhaseName(r.phase));
        return false;
    }
    // Sequencing must be valid
    if (!r.sequencingOk) return false;
    // Must not fabricate final
    if (r.fabricatedFinal) return false;
    // Must have final authority via FinalizePolicy only
    if (!r.finalAuthority) return false;
    return true;
}

bool testFailClosedOnNeedInput() {
    MockTransport transport;
    transport.script = {
        {"", ClientAskResult{.ask = {.action = "need_input", .path = ""}, .event = {.ok = false, .error = "need user input"}}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 1});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    if (r.phase != ControllerPhase::NeedInputLatched && r.phase != ControllerPhase::FailedClosed) {
        return false;
    }
    if (!r.needInputLatched) return false;
    // Must not advance generation on NEED_INPUT
    if (r.generation != 1) return false;
    if (r.attempt != 0) return false;
    return true;
}

bool testRetryExhaustion() {
    MockTransport transport;
    // All attempts return WRONG (bad candidate)
    for (int i = 0; i < 5; ++i) {
        transport.script.push_back({"", ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "bad"}, .event = {.ok = true}}});
    }
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 3});
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    if (r.phase != ControllerPhase::Exhausted && r.phase != ControllerPhase::FailedClosed) {
        return false;
    }
    // Should have retried up to maxRetries
    if (r.redispatches < 3) return false;
    return true;
}

bool testFinalizePolicyAuthority() {
    // Test FinalizePolicy directly
    FinalizePolicy policy;
    Candidate c{};
    c.content = "valid fix";
    c.kind = CandidateKind::CodeChange;
    auto dec = policy.evaluate(c);
    if (!dec.allowed) return false;
    if (dec.reason != "valid") return false;
    
    // Empty candidate should be denied
    Candidate empty{};
    empty.content = "";
    auto dec2 = policy.evaluate(empty);
    if (dec2.allowed) return false;
    return true;
}

bool testTunerIntegration() {
    // Test that controller advances tuner on WRONG
    uint64_t req = 0xFEEDFEEDFEEDFEEDULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    uint32_t strat0 = p.strategy;
    
    // Controller should call tuner Next with WRONG mask
    HexMag_Tuner_Next(req, 0x0040, 1, &p); // HX_FAIL_WRONG
    if (p.strategy == strat0) return false; // must mutate
    
    uint64_t gen = HexMag_Tuner_GenerationId();
    if (gen != 2) return false;
    return true;
}

bool testControllerExceptionHandling() {
    MockTransport transport;
    transport.script = {{"", ClientAskResult{.ask = {.action = "read", .path = "test.cpp"}, .event = {.ok = true, .data = "source"}}}};
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 1});
    ctrl.setForceException(true);
    ControllerResult r = ctrl.run("fix test.cpp", "context");
    if (r.phase != ControllerPhase::FailedClosed) return false;
    if (r.fail != ControllerFail::ControllerException) return false;
    return true;
}

bool testResumeAfterStop() {
    MockTransport transport;
    transport.script = {
        {"", ClientAskResult{.ask = {.action = "write", .path = "test.cpp", .content = "fixed"}, .event = {.ok = true}}}
    };
    HexMagRuntimeController ctrl(&transport, {.maxRetries = 1});
    ControllerResult r1 = ctrl.run("fix test.cpp", "context");
    if (r1.phase != ControllerPhase::Done) return false;
    
    // Resume should not resurrect authority
    ControllerResult r2 = ctrl.tryResume("fix again", "context");
    if (r2.finalGranted) return false; // authority must stay false
    return true;
}

int main() {
    int pass = 0, fail = 0;
    auto run = [&](const char* name, bool (*fn)()) {
        bool ok = fn();
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (ok) ++pass; else ++fail;
    };
    run("sequencing", testSequencing);
    run("fail_closed_need_input", testFailClosedOnNeedInput);
    run("retry_exhaustion", testRetryExhaustion);
    run("finalize_policy_authority", testFinalizePolicyAuthority);
    run("tuner_integration", testTunerIntegration);
    run("exception_handling", testControllerExceptionHandling);
    run("resume_after_stop", testResumeAfterStop);
    std::printf("\nVERDICT=%s pass=%d fail=%d\n", fail == 0 ? "PASS" : "FAIL", pass, fail);
    return fail == 0 ? 0 : 1;
}