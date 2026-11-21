// Minimal driver for the reusable Strata chat session.
// Build (see CMake target deep2_strata_chat_session):
//   deep2_strata_chat_session.exe --model <gguf> --tokens 1 450 --max-new 8 [--gpu|--cpu]

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "deep2/strata_chat.hpp"

int main(int argc, char** argv)
{
    std::string model;
    std::vector<uint32_t> tokens;
    int maxNew = 8;
    bool gpu = true;
    int64_t budget = -1;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--max-new" && i + 1 < argc) maxNew = std::atoi(argv[++i]);
        else if (a == "--tokens") {
            while (i + 1 < argc && argv[i + 1][0] != '-')
                tokens.push_back((uint32_t)std::strtoul(argv[++i], nullptr, 10));
        }
        else if (a == "--weight-cache-budget" && i + 1 < argc)
            budget = std::atoll(argv[++i]);
        else if (a == "--cpu") gpu = false;
        else if (a == "--gpu") gpu = true;
    }
    if (model.empty() || tokens.empty()) {
        std::printf("usage: deep2_strata_chat_session.exe --model <gguf> --tokens 1 2 3 "
                    "[--max-new N] [--gpu|--cpu]\n");
        return 2;
    }

    rawrxd::deep2::StrataChatOptions opts;
    opts.gpu = gpu;
    opts.expertTracking = true;
    opts.weightCacheBudget = budget;

    rawrxd::deep2::StrataChatSession session;
    if (!session.Open(model, opts)) {
        std::printf("OPEN_FAIL: %s\n", session.Stats().error.c_str());
        return 1;
    }
    if (!session.Prefill(tokens)) {
        std::printf("PREFILL_FAIL\n");
        return 1;
    }

    uint32_t next = 0;
    for (int i = 0; i < maxNew; ++i) {
        if (!session.Step(next)) { std::printf("STEP_FAIL at %d\n", i); break; }
        std::printf("[tok %d] %u\n", i, next);
        std::fflush(stdout);
    }
    session.Finalise();

    const auto& s = session.Stats();
    std::printf("DISPATCH gpu_calls=%llu cpu_calls=%llu nonfinite=%zu\n",
                (unsigned long long)s.gpuCalls, (unsigned long long)s.cpuCalls,
                s.nonFiniteLogits);
    std::printf("EXPERT_LEDGER observations=%llu hits=%llu evictions=%llu\n",
                (unsigned long long)s.expertObservations,
                (unsigned long long)s.expertHits,
                (unsigned long long)s.expertEvictions);
    std::printf("SESSION_STATUS %s\n", (s.ok && !s.error.empty()) ? "ERROR"
                          : (s.generatedTokens ? "OK" : "EMPTY"));
    return 0;
}