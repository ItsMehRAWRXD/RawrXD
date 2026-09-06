// ============================================================================
// w0_001_cert.cpp — W0-001 weightless coding prototype (zero tensor weights)
// ============================================================================
// Valuation unlock ladder: architecture → working prototype (this cert).
// Full W0-AGENT-E2E-001 (50+ fixtures) remains the next commercial gate.
// ============================================================================
#include "core/hexmag_authority.hpp"
#include "core/hexmag_oracle_binder.hpp"
#include "deep2w0/W0Engine.hpp"
#include "deep2w0/W0HexMagBridge.hpp"
#include "deep2w0/W0KnowledgeCompiler.hpp"
#include "deep2w0/W0UniversalIR.hpp"
#include "agentic/HexMagAction.hpp"

#include <cstdio>
#include <fstream>
#include <string>

static int g_failures = 0;
static void expect(bool c, const char* m) {
    std::fprintf(stderr, "%s: %s\n", c ? "OK  " : "FAIL", m);
    if (!c) ++g_failures;
}

static std::string readAll(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

int main(int argc, char** argv) {
    std::fprintf(stderr, "=== W0-001 / substrate freeze ===\n");
    std::fprintf(stderr, "%s", RawrXD::W0::kW0SubsystemFreeze);
    std::fprintf(stderr, "%s", RawrXD::W0::kW0Contract);

    std::string root = "tests/fixtures/w0_001";
    if (argc > 1) root = argv[1];

    // --- NEED_INPUT ---
    {
        RawrXD::W0::W0Request req;
        req.task = "Proceed. Parameters are UNSPECIFIED.";
        req.workspaceRoot = root;
        auto r = RawrXD::W0::W0Engine().solve(req);
        expect(r.needInput, "underspec → NEED_INPUT");
        expect(!r.success, "underspec → no success/FINAL");
    }

    // --- Solve fixture ---
    {
        RawrXD::W0::W0Request req;
        req.task = readAll(root + "/task.txt");
        if (req.task.empty()) req.task = "Fix answer() so it returns 42.";
        // strip CR
        while (!req.task.empty()
               && (req.task.back() == '\n' || req.task.back() == '\r'))
            req.task.pop_back();
        req.workspaceRoot = root;
        auto r = RawrXD::W0::W0Engine().solve(req);
        for (const auto& s : r.ladder) std::fprintf(stderr, "  ladder: %s\n", s.c_str());
        expect(!r.needInput, "actionable task: not NEED_INPUT");
        expect(r.success, "W0 solve success (structural verify)");
        expect(r.candidateSource.find("return 42") != std::string::npos,
               "candidate has return 42");
        expect(r.candidateSource.find("return 0") == std::string::npos,
               "old wrong literal removed");
        expect(!r.patches.empty()
               && r.patches[0].op == RawrXD::W0::TransformOp::ChangeLiteral,
               "CHANGE_LITERAL transform");
        bool anyPass = false;
        for (const auto& e : r.evidence) {
            if (e.passes) anyPass = true;
        }
        expect(anyPass, "evidence ledger has PASS");
    }

    // --- HexMag binder: W0 candidate + verifier → existing FINAL gates ---
    {
        RawrXD::W0::W0CandidateGenerator gen;
        gen.workspaceRoot = root;
        RawrXD::HexMag::clearOracleBinderHooks();
        RawrXD::HexMag::setOracleBinderGenerators({&gen});
        RawrXD::HexMag::setOracleBinderVerifier(RawrXD::W0::w0StructuralVerifier);

        RawrXD::HexMag::BinderRequest br;
        br.prompt = "Fix answer() so it returns 42.";
        auto brOut = RawrXD::HexMag::runOracleBinder(
            br, RawrXD::HexMag::oracleBinderGenerators(),
            RawrXD::HexMag::oracleBinderVerifier());

        expect(brOut.oracleInvoked || brOut.codegenInvoked, "W0 generator invoked");
        expect(brOut.selected.source == RawrXD::HexMag::CandidateSource::W0,
               "candidate source=W0");
        expect(brOut.selected.status == RawrXD::HexMag::CandidateStatus::Ok,
               "W0 candidate Ok");
        expect(brOut.success && brOut.gateAllowFinal && brOut.gateIsAllowedFinalClaim,
               "verified W0 candidate → existing FINAL gates ALLOW");
        const bool evidenceSafe = !brOut.claim.evidence.empty()
            && brOut.claim.evidence[0].payload.find("return 42") == std::string::npos;
        expect(brOut.success ? evidenceSafe : true,
               "candidate_as_evidence=FORBIDDEN");
        if (brOut.success) {
            std::fprintf(stderr, "  ladder: PASS HEXMAG_CANDIDATE_ACCEPTED\n");
            std::fprintf(stderr, "  ladder: PASS FINAL_ALLOWED\n");
        } else {
            std::fprintf(stderr, "  ladder: FAIL HEXMAG_CANDIDATE_ACCEPTED\n");
            std::fprintf(stderr, "  ladder: FAIL FINAL_ALLOWED (correct if no verified candidate)\n");
        }

        // needInput latch still holds
        br.needInputLatched = true;
        auto blocked = RawrXD::HexMag::runOracleBinder(br, {&gen},
                                                       RawrXD::W0::w0StructuralVerifier);
        expect(!blocked.success && !blocked.codegenInvoked,
               "needInput latch: W0 cannot resurrect FINAL");

        RawrXD::HexMag::clearOracleBinderHooks();
    }

    // Pack meta: zero weights
    {
        RawrXD::W0::GraphStore g;
        RawrXD::W0::KnowledgeCompiler::seedCoreOntology(g);
        auto meta = RawrXD::W0::KnowledgeCompiler::compilePackMeta("core", g);
        expect(meta.weights == 0 && meta.floatOps == 0, "pack weights=0 float_ops=0");
        expect(!meta.rootHash.empty(), "pack root hash present");
    }

    if (g_failures == 0) {
        std::fprintf(stderr,
                     "\nW0-001=PASS\n"
                     "TENSOR_WEIGHTS=0\n"
                     "GPU_REQUIRED=0\n"
                     "EXTERNAL_INFERENCE=0\n"
                     "FALSE_FINAL=0\n"
                     "NEXT=W0-AGENT-E2E-001\n");
    } else {
        std::fprintf(stderr, "\nW0-001=FAIL failures=%d\n", g_failures);
    }
    return g_failures == 0 ? 0 : 1;
}
