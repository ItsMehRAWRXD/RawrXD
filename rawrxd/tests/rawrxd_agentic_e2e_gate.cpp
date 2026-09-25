// Standalone harness for RAWRXD_WIN32IDE_AGENTIC_001.
// The shipping IDE may call runAgenticE2EGate() directly from its existing
// Native Compile Test command so the same loaded runner is reused.

#include <filesystem>
#include <iostream>
#include <string>

#include "agentic/RawrXDAgenticE2E.hpp"
#include "rawr_run_stream.hpp"

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: rawrxd_agentic_e2e_gate <model.gguf> <workspace-root>\n";
        return 64;
    }

    const std::string model = argv[1];
    const std::filesystem::path workspace = argv[2];

    rawrxd::runstream::RawrDeep2Runner runner;
    rawrxd::runstream::RunStreamReceipt load{};
    if (!runner.load(model, load)) {
        rawrxd::agentic_e2e::AgenticE2EReceipt r;
        r.modelInference = false;
        r.toolAuthority = false;
        r.failStage = "MODEL_LOAD";
        r.failMessage = "RawrDeep2Runner::load failed; no model fallback is permitted.";
        std::cout << rawrxd::agentic_e2e::formatAgenticE2EReceipt(r);
        return 1;
    }

    rawrxd::agentic_e2e::AgenticE2EOptions opt;
    opt.workspaceRoot = workspace;
    opt.fixtureDir = ".rawr/agentic_gate";
    opt.maxSteps = 10;
    opt.maxTokensPerStep = 256;
    opt.processTimeoutMs = 120000;
    opt.keepFixture = false;

    const auto r = rawrxd::agentic_e2e::runAgenticE2EGate(runner.engine(), opt);
    std::cout << rawrxd::agentic_e2e::formatAgenticE2EReceipt(r);
    return r.pass() ? 0 : 1;
}
