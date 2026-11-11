// ============================================================================
// hexmag_oracle_binder_cert.cpp — HEXMAG_ORACLE_BINDER_001
// ============================================================================
#include "core/hexmag_control_plane.hpp"
#include "core/hexmag_oracle_binder.hpp"
#include "core/hexmag_swarm.hpp"
#include "agentic/HexMagAction.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_failures = 0;
static void expect(bool c, const char* m) {
    std::fprintf(stderr, "%s: %s\n", c ? "OK  " : "FAIL", m);
    if (!c) ++g_failures;
    std::fflush(stderr);
}

#ifndef RAWR_HAS_MASM
int main() {
    std::fprintf(stderr, "SKIP: need RAWR_HAS_MASM\n");
    return 0;
}
#else

using namespace RawrXD::HexMag;

static const char* kGoodMasm =
    "; x64 MASM HelloWorld candidate (not FINAL)\n"
    ".code\n"
    "main proc\n"
    "  ; print HelloWorld\n"
    "  ret\n"
    "main endp\n"
    "end\n";

struct CountingGen final : CandidateGenerator {
    CandidateSource src;
    std::string payload;
    int* counter = nullptr;
    bool avail = true;
    bool available() const override { return avail; }
    CandidateSource source() const override { return src; }
    std::string generate(const std::string&, const std::string&) override {
        if (counter) ++(*counter);
        return payload;
    }
};

int main() {
    std::fprintf(stderr, "=== HEXMAG_ORACLE_BINDER_001 ===\n");
    clearOracleBinderHooks();

    {
        int calls = 0;
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = kGoodMasm;
        g.counter = &calls;
        BinderRequest req;
        req.prompt = "Proceed — parameters are UNSPECIFIED.";
        auto r = runOracleBinder(req, {&g}, nullptr);
        expect(calls == 0, "underspec: oracle/codegen not invoked");
        expect(!r.success && !r.gateAllowFinal, "underspec: no FINAL");
    }

    {
        int calls = 0;
        CountingGen g;
        g.src = CandidateSource::Deep2;
        g.payload = kGoodMasm;
        g.counter = &calls;
        BinderRequest req;
        req.prompt = "Create hello world in x64 MASM";
        req.needInputLatched = true;
        auto r = runOracleBinder(req, {&g}, [](const CandidateArtifact&) { return true; });
        expect(calls == 0, "needInput latch: deep2 not invoked");
        expect(!r.success, "needInput latch: no FINAL resurrection");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = kGoodMasm;
        auto r = runOracleBinder(
            BinderRequest{"Create a hello world program in x64 MASM", ""},
            {&g},
            [](const CandidateArtifact& a) {
                return a.text.find("HelloWorld") != std::string::npos
                    && a.text.find(".code") != std::string::npos;
            });
        expect(r.oracleInvoked && r.codegenInvoked, "valid: oracle invoked");
        expect(r.selected.status == CandidateStatus::Ok, "valid: Ok candidate");
        expect(r.selected.text.find("candidate.impl=") == std::string::npos,
               "valid: non-stub candidate");
        expect(r.success, "valid: existing FINAL gates allow");
        expect(r.claim.evidence.size() == 1
               && r.claim.evidence[0].payload.find("HelloWorld") == std::string::npos,
               "candidate_as_evidence=FORBIDDEN");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = "";
        auto r = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&g}, nullptr);
        expect(!r.success, "oracle failure: no FINAL");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = "llm.answer.final";
        auto r = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&g},
            [](const CandidateArtifact&) { return true; });
        expect(!r.success, "empty candidate: no FINAL");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Deep2;
        g.payload = std::string("\x01\x02\x03\x04\xff\xfe", 6);
        auto r = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&g},
            [](const CandidateArtifact&) { return true; });
        expect(!r.success, "malformed: no FINAL");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = "claim_verified=true confidence=0.99";
        auto r = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&g},
            [](const CandidateArtifact&) { return true; });
        expect(!r.success, "unsupported claim: no FINAL");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = kGoodMasm;
        auto r = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&g}, nullptr);
        expect(r.claim.state == ClaimState::Candidate && !r.success,
               "unverified: no FINAL");
    }

    {
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = std::string("FINAL: ") + kGoodMasm + "\nllm.answer.final";
        auto r = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&g},
            [](const CandidateArtifact& a) {
                return a.text.find("HelloWorld") != std::string::npos;
            });
        expect(r.selected.hadFinalWording, "FINAL wording stripped");
        expect(r.success, "stripped FINAL still verifiable as candidate");
    }

    {
        CountingGen a, b;
        a.src = CandidateSource::Oracle;
        b.src = CandidateSource::Deep2;
        a.payload = std::string(kGoodMasm) + "; variant-A\n";
        b.payload = std::string(kGoodMasm) + "; variant-B\n";
        auto r1 = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&a, &b},
            [](const CandidateArtifact& c) {
                return c.text.find("HelloWorld") != std::string::npos;
            });
        auto r2 = runOracleBinder(
            BinderRequest{"Create hello world masm program", ""}, {&a, &b},
            [](const CandidateArtifact& c) {
                return c.text.find("HelloWorld") != std::string::npos;
            });
        expect(r1.selected.text == r2.selected.text, "multi: deterministic selection");
        expect(r1.success, "multi: verified selection may FINAL");
    }

    {
        int calls = 0;
        CountingGen g;
        g.src = CandidateSource::Oracle;
        g.payload = kGoodMasm;
        g.counter = &calls;
        setOracleBinderGenerators({&g});
        setOracleBinderVerifier([](const CandidateArtifact&) { return true; });
        auto ask = askWithAutoStart(
            "Proceed with the remaining steps. Target and parameters are UNSPECIFIED.",
            "");
        expect(ask.needInput && calls == 0 && !ask.oracleInvoked,
               "ask underspec: NEED_INPUT, oracle not invoked");
        clearOracleBinderHooks();
    }

    {
        CountingGen g;
        g.src = CandidateSource::Deep2;
        g.payload = kGoodMasm;
        setOracleBinderGenerators({&g});
        setOracleBinderVerifier([](const CandidateArtifact& a) {
            return a.text.find("HelloWorld") != std::string::npos;
        });
        auto ask = askWithAutoStart(
            "Create a hello world program in x64 MASM that prints HelloWorld and exits.",
            "");
        expect(ask.success && (ask.deep2Invoked || ask.oracleInvoked),
               "ask: verified non-stub FINAL via gates");
        clearOracleBinderHooks();
    }

    if (g_failures == 0) {
        std::fprintf(stderr,
                     "\nHEXMAG_ORACLE_BINDER_001=PASS\n"
                     "oracle_output=CANDIDATE_ONLY\n"
                     "deep2_output=CANDIDATE_ONLY\n"
                     "candidate_as_evidence=FORBIDDEN\n"
                     "candidate_as_final=FORBIDDEN\n"
                     "needInput_latch=HOLD\n");
    } else {
        std::fprintf(stderr, "\nHEXMAG_ORACLE_BINDER_001=FAIL failures=%d\n", g_failures);
    }
    clearOracleBinderHooks();
    return g_failures == 0 ? 0 : 1;
}

#endif
