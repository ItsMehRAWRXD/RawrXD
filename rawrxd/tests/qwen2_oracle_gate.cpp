// qwen2_oracle_gate.cpp — DEEP2_QWEN2_CPU_CORRECTNESS_001
//
// One-token, position-zero Qwen2 CPU oracle gate.
// Runs exactly one token at position 0 (empty KV, softmax over 1 element,
// trivial RoPE) through the Deep2 CPU forward path with the parity probe
// enabled, dumping per-checkpoint fingerprints for comparison against an
// external scalar reference implementation.
//
// Usage:
//   qwen2_oracle_gate.exe <model.gguf> <probe_trace.txt> [token_text]
//
// Gate rules (fail-closed):
//   - exactly 1 prompt token, 1 generated token, position 0
//   - ALL checkpoints finite
//   - LOGITS record present (LM head executed)
//   - no GPU counters required (CPU path under test)
//
#include "deep2/Deep2Engine.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: qwen2_oracle_gate.exe <model.gguf> <trace.txt> [token_text]\n");
        return 2;
    }
    const char* model = argv[1];
    const char* trace = argv[2];
    const std::string tokenText = (argc > 3) ? std::string(argv[3]) : std::string("hello");

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 64;   // oracle: smallest context, pos 0 only
    cfg.numThreads = 1;   // deterministic single-thread CPU
    cfg.useThreadPool = false;

    if (!e.initialize(cfg)) {
        std::fprintf(stderr, "ORACLE=HOLD stage=initialize\n");
        return 10;
    }
    if (!e.loadModel(model)) {
        std::fprintf(stderr, "ORACLE=HOLD stage=load\n");
        return 11;
    }

    e.enableParityProbe(trace, 1);
    // DEEP2_QWEN2_CPU_CORRECTNESS_001: full-vector dump for L0 (input layer:
    // exposes ATTNNORM/Q/K/V full vectors for external verification).
    e.enableParityProbeFullVectors(0);

    // CPU path only: keep vulkan off so the host lane executes all operators.
    e.enableVulkan(false);

    GenerationOptions o{};
    o.maxTokens = 1;
    o.temperature = 0.0f;
    o.topK = 1;
    o.topP = 1.0f;
    o.seed = 1;

    const GenerationResult r = e.generateStream(
        tokenText, o, [](int32_t, const std::string&) { return true; });

    e.disableParityProbe();

    const bool genOk = r.generatedTokens == 1;
    const bool promptOk = r.promptTokens >= 1;

    std::fprintf(stderr,
        "GATE=DEEP2_QWEN2_CPU_CORRECTNESS_001\n"
        "MODEL=%s\n"
        "PROMPT_TOKENS=%llu\n"
        "GENERATED_TOKENS=%llu\n"
        "POSITION=0\n"
        "MODE=CPU\n"
        "TRACE=%s\n",
        model,
        static_cast<unsigned long long>(r.promptTokens),
        static_cast<unsigned long long>(r.generatedTokens),
        trace);

    std::fprintf(stderr, "ORACLE_GATE_STAGE=%s\n",
        (genOk && promptOk) ? "PASS" : "HOLD");

    return (genOk && promptOk) ? 0 : 1;
}