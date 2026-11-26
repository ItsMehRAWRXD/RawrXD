// deep2_strata_chat_multiturn.cpp -- SOLO-09 multi-turn / KV-cache persistence.
//
// Exercises the production StrataChatSession across TWO turns on one session:
//   turn 1: Prefill(prompt1) -> decode N1
//   turn 2: PrefillFrom(committed_len, prompt2) -> decode N2
// PrefillFrom reuses the KV already committed for positions < startPos, so a
// correct second turn proves persistent-session KV reuse (no full recompute).
// CPU-only by default (--gpu to opt in). No external server.
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "strata_chat.hpp"

static std::vector<uint32_t> ParseIds(const char* s) {
    std::vector<uint32_t> v;
    const char* p = s;
    while (*p) {
        while (*p == ' ' || *p == ',') ++p;
        if (!*p) break;
        char* end = nullptr;
        const unsigned long id = std::strtoul(p, &end, 10);
        if (end == p) break;
        v.push_back((uint32_t)id);
        p = end;
    }
    return v;
}

int main(int argc, char** argv) {
    std::string model;
    std::vector<uint32_t> turn1, turn2;
    int maxNew = 6;
    bool gpu = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--max-new" && i + 1 < argc) maxNew = std::atoi(argv[++i]);
        else if (a == "--turn1" && i + 1 < argc) turn1 = ParseIds(argv[++i]);
        else if (a == "--turn2" && i + 1 < argc) turn2 = ParseIds(argv[++i]);
        else if (a == "--cpu") gpu = false;
        else if (a == "--gpu") gpu = true;
    }
    if (model.empty() || turn1.empty() || turn2.empty()) {
        std::printf("usage: deep2_strata_chat_multiturn.exe --model <gguf> "
                    "--turn1 \"1 2 3\" --turn2 \"4 5 6\" [--max-new N] [--gpu|--cpu]\n");
        return 2;
    }

    rawrxd::deep2::StrataChatOptions opts;
    opts.gpu = gpu;
    opts.expertTracking = true;
    rawrxd::deep2::StrataChatSession s;
    if (!s.Open(model, opts)) { std::printf("OPEN_FAIL: %s\n", s.Stats().error.c_str()); return 1; }

    // ---- turn 1 ----
    if (!s.Prefill(turn1)) { std::printf("T1_PREFILL_FAIL\n"); return 1; }
    const size_t committedAfterT1 = turn1.size();
    uint32_t next = 0;
    std::printf("TURN1_PROMPT %zu\n", turn1.size());
    for (int i = 0; i < maxNew; ++i) {
        if (!s.Step(next)) { std::printf("T1_STEP_FAIL at %d\n", i); break; }
        std::printf("[t1 %d] %u\n", i, next);
    }
    const size_t gen1 = s.Stats().generatedTokens;
    const size_t committed = committedAfterT1 + gen1;

    // ---- turn 2: reuse KV committed for [0, committed) ----
    if (!s.PrefillFrom(committed, turn2)) { std::printf("T2_PREFILLFROM_FAIL\n"); return 1; }
    std::printf("TURN2_STARTPOS %zu (KV reused for %zu committed positions)\n", committed, committed);
    for (int i = 0; i < maxNew; ++i) {
        if (!s.Step(next)) { std::printf("T2_STEP_FAIL at %d\n", i); break; }
        std::printf("[t2 %d] %u\n", i, next);
    }
    s.Finalise();
    const auto& st = s.Stats();
    std::printf("MULTITURN_OK turn1_gen=%zu turn2_gen=%zu gpu_calls=%llu cpu_calls=%llu "
                "nonfinite=%zu cleanup_ok=%d\n",
                gen1, (size_t)(st.generatedTokens), (unsigned long long)st.gpuCalls,
                (unsigned long long)st.cpuCalls, st.nonFiniteLogits, st.ok ? 1 : 0);
    return st.ok ? 0 : 1;
}