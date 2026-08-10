// ============================================================================
// B007 — Performance Baseline Certification
// ============================================================================
// Attempts to load a real GGUF model and measure actual inference performance.
//
// Rules:
//   1. Only real model execution counts as a valid baseline.
//   2. If the loader crashes (0xC0000005), the baseline is BLOCKED.
//   3. No synthetic/unit-test throughput may be reported as the baseline.
//   4. All reproducibility metadata must be captured.
//
// Metrics captured (when inference succeeds):
//   - model_load_time_ms
//   - prefill_tokens, prefill_ms, prefill_tok_per_sec
//   - decode_tokens, decode_ms, decode_tok_per_sec
//   - first_token_latency_ms (TTFT)
//   - steady_state_tok_per_sec (last 4 tokens average)
//   - memory_before_mb, memory_after_mb, memory_delta_mb
//   - backend_mode (CPU / GPU / Vulkan / etc.)
//
// Reproducibility metadata:
//   - executable path, source commit, compiler version
//   - model path, model size, model SHA-256
//   - build configuration, command line
// ============================================================================

#include "src/cpu_inference_engine.h"
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <cmath>

#pragma comment(lib, "psapi.lib")

using namespace RawrXD;

// ============================================================================
// Reproducibility Metadata
// ============================================================================
static const char* B007_EXECUTABLE    = "b007_performance_baseline.exe";
static const char* B007_SOURCE_COMMIT = "29e76f01e";
static const char* B007_COMPILER      = "MSVC 14.51.36231";
static const char* B007_BUILD_CONFIG  = "Release /O2 /MT /std:c++20";
static const char* B007_MODEL_PATH    = "F:\\Franken\\BackwardsUnlock\\1b\\unlock-1B-Q4_K_M.gguf";
static const char* B007_MODEL_SHA256  = "DDE5AA3FC5FFC17176B5E8BDC82F587B24B2678C6C66101BF7DA77AF9F7CCDFF";
static const uint64_t B007_MODEL_SIZE = 2019377376ULL;

// ============================================================================
// Result Tracking
// ============================================================================
struct PerfResult {
    const char* metric;
    double      value;
    const char* unit;
    bool        valid;
};

static std::vector<PerfResult> g_results;
static std::vector<std::string> g_blockers;
static bool g_blocked = false;

static void RecordMetric(const char* metric, double value, const char* unit, bool valid = true) {
    g_results.push_back({metric, value, unit, valid});
}

static void RecordBlocker(const char* reason) {
    g_blockers.push_back(reason);
    g_blocked = true;
}

// ============================================================================
// Memory measurement
// ============================================================================
static double GetWorkingSetMB() {
    PROCESS_MEMORY_COUNTERS pmc = {};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return static_cast<double>(pmc.WorkingSetSize) / (1024.0 * 1024.0);
    }
    return 0.0;
}

// ============================================================================
// Vectored Exception Handler — captures 0xC0000005 as BLOCKED evidence
// Avoids C2712 entirely by not using __try/__except in C++ functions.
// ============================================================================
static volatile DWORD g_b007_exception_code = 0;
static volatile const char* g_b007_exception_context = nullptr;

static LONG WINAPI B007VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION ||
        code == EXCEPTION_PRIV_INSTRUCTION ||
        code == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        g_b007_exception_code = code;
        // Terminate the process — the test harness will detect exit code 2
        ExitProcess(2);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void InstallB007Handler(const char* context) {
    g_b007_exception_code = 0;
    g_b007_exception_context = context;
    AddVectoredExceptionHandler(1, B007VectoredHandler);
}

static void UninstallB007Handler() {
    RemoveVectoredExceptionHandler(B007VectoredHandler);
}

// ============================================================================
// Safe model load with vectored exception handler
// ============================================================================
static bool SafeLoadModel(CPUInferenceEngine* engine, const char* path, double* out_ms) {
    ULONGLONG t0 = GetTickCount64();

    InstallB007Handler("LoadModel");
    bool ok = engine->LoadModel(path);
    UninstallB007Handler();

    ULONGLONG t1 = GetTickCount64();
    *out_ms = static_cast<double>(t1 - t0);

    if (g_b007_exception_code != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "SEH exception 0x%08X during LoadModel (path=%s)",
            static_cast<unsigned int>(g_b007_exception_code), path);
        RecordBlocker(buf);
        g_b007_exception_code = 0;
        return false;
    }
    return ok;
}

// ============================================================================
// Safe generation with vectored exception handler
// ============================================================================
struct GenCallbacks {
    std::function<void(const std::string&)> token_cb;
    std::function<void()> complete_cb;
    std::function<void(int32_t)> tid_cb;
};

static bool SafeGenerateStreaming(CPUInferenceEngine* engine,
    const std::vector<int32_t>& tokens, int max_tokens,
    const GenCallbacks& cbs,
    double* out_ms)
{
    ULONGLONG t0 = GetTickCount64();

    InstallB007Handler("GenerateStreaming");
    engine->GenerateStreaming(tokens, max_tokens, cbs.token_cb, cbs.complete_cb, cbs.tid_cb);
    UninstallB007Handler();

    ULONGLONG t1 = GetTickCount64();
    *out_ms = static_cast<double>(t1 - t0);

    if (g_b007_exception_code != 0) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "SEH exception 0x%08X during GenerateStreaming",
            static_cast<unsigned int>(g_b007_exception_code));
        RecordBlocker(buf);
        g_b007_exception_code = 0;
        return false;
    }
    return true;
}

// ============================================================================
// B007-001: Model load attempt with timing
// ============================================================================
static bool Test_B007_001_LoadModel() {
    printf("\n=== B007-001: Model load attempt ===\n");
    printf("  Model: %s\n", B007_MODEL_PATH);
    printf("  Size:  %.2f GB\n", static_cast<double>(B007_MODEL_SIZE) / (1024.0 * 1024.0 * 1024.0));
    printf("  SHA-256: %s\n", B007_MODEL_SHA256);

    auto engine = CPUInferenceEngine::GetSharedInstance();
    if (!engine) {
        RecordBlocker("Failed to get engine instance");
        printf("  [BLOCKED] Engine instance unavailable\n");
        return false;
    }

    double load_ms = 0.0;
    bool loaded = SafeLoadModel(engine.get(), B007_MODEL_PATH, &load_ms);

    if (!loaded) {
        printf("  [BLOCKED] Model load failed or crashed\n");
        RecordMetric("model_load_time_ms", load_ms, "ms", false);
        return false;
    }

    printf("  [PASS] Model loaded in %.1f ms\n", load_ms);
    RecordMetric("model_load_time_ms", load_ms, "ms", true);
    return true;
}

// ============================================================================
// B007-002: Prefill + decode benchmark
// ============================================================================
static bool Test_B007_002_InferenceBenchmark() {
    printf("\n=== B007-002: Inference benchmark ===\n");

    auto engine = CPUInferenceEngine::GetSharedInstance();
    if (!engine || !engine->IsModelLoaded()) {
        RecordBlocker("Engine not loaded for benchmark");
        printf("  [BLOCKED] Engine not loaded\n");
        return false;
    }

    // Tokenize prompt
    std::string prompt = "Hello, how are you today?";
    auto tokens = engine->Tokenize(prompt);
    printf("  Prompt: '%s'\n", prompt.c_str());
    printf("  Tokens: %zu\n", tokens.size());

    if (tokens.empty()) {
        RecordBlocker("Tokenization returned empty");
        printf("  [BLOCKED] Tokenization failed\n");
        return false;
    }

    // Measure memory before
    double mem_before = GetWorkingSetMB();
    printf("  Working set before: %.1f MB\n", mem_before);

    // Run generation with per-token timing
    std::vector<double> token_latencies;
    std::vector<std::string> generated_pieces;
    std::vector<int32_t> generated_ids;
    double first_token_ms = 0.0;
    bool got_first = false;
    auto gen_start = std::chrono::high_resolution_clock::now();

    auto token_cb = [&](const std::string& piece) {
        auto now = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(now - gen_start).count();
        generated_pieces.push_back(piece);
        if (!got_first) {
            first_token_ms = ms;
            got_first = true;
        }
        token_latencies.push_back(ms);
    };

    auto tid_cb = [&](int32_t tid) {
        generated_ids.push_back(tid);
    };

    double gen_ms = 0.0;
    GenCallbacks cbs;
    cbs.token_cb = token_cb;
    cbs.complete_cb = []() {};
    cbs.tid_cb = tid_cb;
    bool gen_ok = SafeGenerateStreaming(engine.get(), tokens, 8, cbs, &gen_ms);

    if (!gen_ok) {
        printf("  [BLOCKED] Generation crashed\n");
        return false;
    }

    // Measure memory after
    double mem_after = GetWorkingSetMB();
    printf("  Working set after:  %.1f MB\n", mem_after);

    // Compute metrics
    int prefill_tokens = static_cast<int>(tokens.size());
    int decode_tokens  = static_cast<int>(generated_ids.size());

    double prefill_tok_per_sec = (gen_ms > 0 && prefill_tokens > 0)
        ? (prefill_tokens * 1000.0 / gen_ms) : 0.0;
    double decode_tok_per_sec = (gen_ms > 0 && decode_tokens > 0)
        ? (decode_tokens * 1000.0 / gen_ms) : 0.0;

    // Steady-state: average of last 4 token latencies (if available)
    double steady_tok_per_sec = 0.0;
    if (token_latencies.size() >= 2) {
        int n = static_cast<int>(token_latencies.size());
        int start_idx = (n > 4) ? (n - 4) : 0;
        double span_ms = token_latencies[n - 1] - token_latencies[start_idx];
        int count = n - start_idx;
        if (span_ms > 0 && count > 1) {
            steady_tok_per_sec = ((count - 1) * 1000.0) / span_ms;
        }
    }

    // Backend mode detection
    std::string backend = "CPU";
    // Heuristic: if load was fast (< 500ms) for a 1.8GB model, likely GPU
    // This is approximate; real backend detection would query the engine
    double load_time = 0.0;
    for (const auto& r : g_results) {
        if (strcmp(r.metric, "model_load_time_ms") == 0) {
            load_time = r.value;
            break;
        }
    }
    if (load_time > 0 && load_time < 500.0 && B007_MODEL_SIZE > 1000000000ULL) {
        backend = "GPU/CACHED";
    }

    printf("  Generated %d tokens in %.1f ms\n", decode_tokens, gen_ms);
    printf("  First-token latency (TTFT): %.1f ms\n", first_token_ms);
    printf("  Prefill throughput: %.2f tok/s\n", prefill_tok_per_sec);
    printf("  Decode throughput:  %.2f tok/s\n", decode_tok_per_sec);
    printf("  Steady-state:       %.2f tok/s\n", steady_tok_per_sec);
    printf("  Memory delta:       %.1f MB\n", mem_after - mem_before);
    printf("  Backend mode:       %s\n", backend.c_str());

    RecordMetric("prefill_tokens", static_cast<double>(prefill_tokens), "tokens", true);
    RecordMetric("prefill_ms", gen_ms, "ms", true);
    RecordMetric("prefill_tok_per_sec", prefill_tok_per_sec, "tok/s", true);
    RecordMetric("decode_tokens", static_cast<double>(decode_tokens), "tokens", true);
    RecordMetric("decode_ms", gen_ms, "ms", true);
    RecordMetric("decode_tok_per_sec", decode_tok_per_sec, "tok/s", true);
    RecordMetric("first_token_latency_ms", first_token_ms, "ms", true);
    RecordMetric("steady_state_tok_per_sec", steady_tok_per_sec, "tok/s", true);
    RecordMetric("memory_before_mb", mem_before, "MB", true);
    RecordMetric("memory_after_mb", mem_after, "MB", true);
    RecordMetric("memory_delta_mb", mem_after - mem_before, "MB", true);

    // Decode throughput must be > 0 for a valid baseline
    bool ok = (decode_tokens > 0) && (decode_tok_per_sec > 0.0);
    if (!ok) {
        RecordBlocker("No tokens generated — throughput is zero");
    }
    return ok;
}

// ============================================================================
// B007-003: Reproducibility metadata dump
// ============================================================================
static void Test_B007_003_Reproducibility() {
    printf("\n=== B007-003: Reproducibility metadata ===\n");
    printf("  Executable:        %s\n", B007_EXECUTABLE);
    printf("  Source commit:       %s\n", B007_SOURCE_COMMIT);
    printf("  Compiler:            %s\n", B007_COMPILER);
    printf("  Build config:        %s\n", B007_BUILD_CONFIG);
    printf("  Model path:          %s\n", B007_MODEL_PATH);
    printf("  Model size:          %llu bytes\n", static_cast<unsigned long long>(B007_MODEL_SIZE));
    printf("  Model SHA-256:       %s\n", B007_MODEL_SHA256);
    printf("  Command line:        %s <model_path>\n", B007_EXECUTABLE);
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    printf("=================================================================\n");
    printf("  B007 — Performance Baseline Certification\n");
    printf("  RawrXD Local Inference — Real Model Execution Benchmark\n");
    printf("=================================================================\n");
    printf("  WARNING: Only real model execution counts as a valid baseline.\n");
    printf("  Synthetic/unit-test throughput is NOT acceptable.\n");
    printf("=================================================================\n");

    bool ok1 = Test_B007_001_LoadModel();
    bool ok2 = false;
    if (ok1 && !g_blocked) {
        ok2 = Test_B007_002_InferenceBenchmark();
    }

    Test_B007_003_Reproducibility();

    printf("\n=================================================================\n");
    printf("  B007 RESULT SUMMARY\n");
    printf("=================================================================\n");

    if (g_blocked) {
        printf("  STATUS: BLOCKED\n");
        printf("  Blockers:\n");
        for (const auto& b : g_blockers) {
            printf("    - %s\n", b.c_str());
        }
        printf("\n  No valid performance baseline established.\n");
        printf("  The 0xC0000005 loader failure must be resolved before B007 can pass.\n");
    } else if (ok1 && ok2) {
        printf("  STATUS: PASS\n");
        printf("  Metrics:\n");
        for (const auto& r : g_results) {
            if (r.valid) {
                printf("    %-28s %12.2f %s\n", r.metric, r.value, r.unit);
            }
        }
        printf("\n  Valid performance baseline established.\n");
        printf("  Ready for B008 CMake/CI integration.\n");
    } else {
        printf("  STATUS: FAIL\n");
        printf("  One or more tests failed without a crash blocker.\n");
    }

    printf("=================================================================\n");

    return g_blocked ? 2 : (ok1 && ok2 ? 0 : 1);
}
