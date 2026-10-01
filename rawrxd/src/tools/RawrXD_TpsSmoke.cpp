// RawrXD_TpsSmoke.cpp — RAWRXD_TPS_SMOKE_ENTRY_001
//
// RESTORED ENTRY POINT.
//
// RawrXD-TpsSmoke was declared at CMakeLists.txt as
//
//   add_executable(RawrXD-TpsSmoke EXCLUDE_FROM_ALL
//       # AUTO-REMOVED: stub file        <-- this file
//       src/core/unified_memory_executor.cpp
//       src/core/model_runtime_gate.cpp
//       src/logging/Logger.cpp)
//
// The entry point was stripped, leaving a target whose only sources are three
// libraries. That target has no main(), so it cannot link, and the documented
// driver (Run-TpsSmoke.ps1) had nothing to run. build_p2_rawr.txt recorded it as
// "No SOURCES given to target: RawrXD-TpsSmoke".
//
// This restores a real decode-throughput measurement. It measures only real
// tokens produced by Deep2Engine::generateStream across a QPC-timed window, and
// it fails closed: any incomplete stage returns a non-zero exit code and
// writes NO TPS number, so a partial run can never be read as a result.
//
// Usage:
//   RawrXD-TpsSmoke.exe <model.gguf> [tokens] [--receipt <path>]
//
// Exit codes:
//   0  measurement completed and a TPS value was written
//   2  bad usage
//   10 engine initialize failed
//   11 model load failed
//   12 warmup did not produce the requested token count
//   13 measured run produced no tokens
//   14 measured run did not complete
//   15 QPC frequency unavailable

#include "deep2/Deep2Engine.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

// Warmup is separate from the measured window on purpose: the first generation
// pays weight paging and allocator warmup, which would understate steady-state
// decode throughput.
constexpr int    kWarmupTokens = 16;
constexpr int    kDefaultTokens = 128;
// Matches EngineConfig::maxSeqLen below; the token budget is validated against it.
constexpr size_t kContextLen = 4096;

const char* kPrompt =
    "Write a complete C++ implementation of a lock-free bounded queue. "
    "Include memory ordering and correctness notes. ";

Deep2::GenerationOptions greedyOptions(int maxTokens) {
    Deep2::GenerationOptions o{};
    o.maxTokens   = maxTokens;
    o.temperature = 0.0f;   // deterministic: removes sampler variance
    o.topP        = 1.0f;
    o.topK        = 1;
    o.seed        = 0;     // 0 => auto-seed
    return o;
}

double qpcSeconds(LARGE_INTEGER a, LARGE_INTEGER b, LARGE_INTEGER freq) {
    return static_cast<double>(b.QuadPart - a.QuadPart) /
           static_cast<double>(freq.QuadPart);
}

void writeReceipt(const std::string& path,
                  const char* modelPath,
                  bool warmupOk, bool measuredCompleted,
                  unsigned long long tokens, double seconds, double tps,
                  const char* statusName) {
    FILE* f = std::fopen(path.c_str(), "w");
    if (!f) return;
    std::fprintf(f, "=== RAWRXD_TPS_SMOKE_001 ===\n");
    std::fprintf(f, "MODEL=%s\n", modelPath);
    std::fprintf(f, "MEASURED=%s\n", measuredCompleted ? "1" : "0");
    std::fprintf(f, "WARMUP_OK=%s\n", warmupOk ? "1" : "0");
    std::fprintf(f, "WINDOW_SECONDS=%.6f\n", seconds);
    std::fprintf(f, "MEASURED_TOKEN_COUNT=%llu\n", tokens);
    std::fprintf(f, "TPS=%.3f\n", tps);
    std::fprintf(f, "GENERATION_STATUS=%s\n", statusName);
    std::fprintf(f, "VERDICT=%s\n",
                 (warmupOk && measuredCompleted && tokens > 0) ? "PASS" : "FAIL");
    std::fprintf(f, "=== RECEIPT_END ===\n");
    std::fclose(f);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: RawrXD-TpsSmoke.exe <model.gguf> [tokens] [--receipt <path>]\n");
        return 2;
    }

    const char* modelPath = argv[1];
    int targetTokens = kDefaultTokens;
    std::string receiptPath;

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--receipt") == 0 && i + 1 < argc) {
            receiptPath = argv[++i];
        } else {
            targetTokens = std::atoi(argv[i]);
            if (targetTokens <= 0) targetTokens = kDefaultTokens;
        }
    }

    // Precondition, checked before loading: EngineConfig::maxSeqLen is a uint32
    // token budget and GenerationOptions::maxTokens must fit inside it, or the
    // engine answers InvalidInput (GenerationStatus, Deep2Engine.h:336-341) and
    // a real configuration problem would surface as an opaque decode failure.
    if (static_cast<size_t>(targetTokens) > kContextLen) {
        std::fprintf(stderr,
            "TPS_SMOKE=FAIL stage=PRECONDITION reason=token_budget target=%d exceeds maxSeqLen=%d\n",
            targetTokens, kContextLen);
        return 2;
    }

    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen  = kContextLen;
    cfg.numThreads = 0;   // 0 => engine default

    if (!engine.initialize(cfg)) {
        std::fprintf(stderr, "TPS_SMOKE=FAIL stage=INITIALIZE\n");
        return 10;
    }
    if (!engine.loadModel(modelPath)) {
        std::fprintf(stderr, "TPS_SMOKE=FAIL stage=LOAD_MODEL model=%s\n", modelPath);
        return 11;
    }

    // ── Warmup (not measured) ────────────────────────────────────────────
    const Deep2::GenerationResult warm = engine.generateStream(
        kPrompt, greedyOptions(kWarmupTokens),
        [](int32_t, const std::string&) { return true; });

    if (warm.generatedTokens != static_cast<unsigned long long>(kWarmupTokens)) {
        std::fprintf(stderr,
                     "TPS_SMOKE=FAIL stage=WARMUP produced=%llu expected=%d\n",
                     warm.generatedTokens, kWarmupTokens);
        return 12;
    }

    engine.reset();

    // ── Measured window ──────────────────────────────────────────────────
    LARGE_INTEGER freq{}, t0{}, t1{};
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
        std::fprintf(stderr, "TPS_SMOKE=FAIL stage=QPC\n");
        return 15;
    }

    unsigned long long callbackTokens = 0;
    QueryPerformanceCounter(&t0);

    const Deep2::GenerationResult measured = engine.generateStream(
        kPrompt, greedyOptions(targetTokens),
        [&](int32_t, const std::string&) {
            ++callbackTokens;
            return true;
        });

    QueryPerformanceCounter(&t1);

    const double seconds = qpcSeconds(t0, t1, freq);

    // Fail closed. A TPS figure derived from a cancelled or incomplete run is
    // not a measurement, so it is never printed and never written.
    //
    // Note on zero tokens: Deep2Engine.h:331 states that immediate EOS
    // legitimately yields zero tokens under GenerationStatus::EndOfSequence.
    // A TPS number cannot be computed from that case, so it is reported as a
    // distinct stage rather than folded into a generic failure -- but it is
    // still a FAIL for TPS purposes, because no throughput was observed.
    if (measured.generatedTokens == 0) {
        std::fprintf(stderr,
            "TPS_SMOKE=FAIL stage=NO_TOKENS status=%d note=immediate_EOS_yields_no_throughput_measurement\n",
            static_cast<int>(measured.status));
        return 13;
    }
    if (!measured.completed || measured.cancelled) {
        std::fprintf(stderr, "TPS_SMOKE=FAIL stage=INCOMPLETE completed=%d cancelled=%d status=%d\n",
                     measured.completed ? 1 : 0, measured.cancelled ? 1 : 0,
                     static_cast<int>(measured.status));
        return 14;
    }
    if (seconds <= 0.0) {
        std::fprintf(stderr, "TPS_SMOKE=FAIL stage=ZERO_WINDOW\n");
        return 15;
    }

    const double tps = static_cast<double>(measured.generatedTokens) / seconds;

    std::printf("=== RAWRXD_TPS_SMOKE_001 ===\n");
    std::printf("MODEL=%s\n", modelPath);
    std::printf("TARGET_TOKENS=%d\n", targetTokens);
    std::printf("MEASURED_TOKEN_COUNT=%llu\n", measured.generatedTokens);
    std::printf("CALLBACK_TOKEN_COUNT=%llu\n", callbackTokens);
    std::printf("WINDOW_SECONDS=%.6f\n", seconds);
    std::printf("TPS=%.3f\n", tps);
    std::printf("ENGINE_GENERATION_TIME_MS=%.3f\n", measured.generationTimeMs);
    std::printf("VERDICT=PASS\n");
    std::printf("=== RECEIPT_END ===\n");
    std::fflush(stdout);

    if (!receiptPath.empty()) {
        writeReceipt(receiptPath, modelPath, true, true,
                     measured.generatedTokens, seconds, tps, "Completed");
    }
    return 0;
}
