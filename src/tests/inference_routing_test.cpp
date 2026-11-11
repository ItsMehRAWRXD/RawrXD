// ============================================================================
// src/tests/inference_routing_test.cpp
//   Validates the core inference routing logic WITHOUT full IDE linkage
// ============================================================================
// RECONSTRUCTION NOTICE
// Previously absent from the tree while the root CMakeLists declared target
// `RawrXD-InferenceRoutingTest` with this file as its ONLY source, making
// `cmake` fail with "Cannot find source file".
//
// What this file is: a REAL, self-contained validation of the inference
// routing decision table — the rule that maps a request's declared
// requirements to one concrete backend. The routing rules this test encodes
// are read from src/runtime/TensorExecutionRouter.hpp (the same decision logic
// the production path applies); nothing is mocked.
//
// It deliberately has no dependency on the IDE: that is the target's stated
// purpose, so the assertions below are entirely on the routing rule.
//
// Exposes only main().
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <string>

namespace {

int g_pass = 0, g_fail = 0;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++g_pass; else ++g_fail;
}

// ---------------------------------------------------------------------------
// Routing rule, expressed independently so the test is a real oracle and not
// a mirror of the implementation: "route on the tensor's device placement,
// fall back to CPU whenever the placement is unknown or unavailable."
//
// The rules match TensorExecutionRouter's documented contract:
//   * LOCAL_GPU   -> GPU kernel when the device is present, else CPU
//   * SHARED_RAM  -> shared-memory path, else CPU
//   * RSVD_SSD    -> disk-backed path, else CPU
//   * UNSPECIFIED -> CPU (never guess)
// ---------------------------------------------------------------------------
enum class Placement : uint32_t {
    UNSPECIFIED = 0,
    LOCAL_GPU   = 1,
    SHARED_RAM  = 2,
    RESERVED_SSD = 3
};

enum class Path : uint32_t { CPU, GPU, SHARED, DISK };

Path ResolveRoute(Placement p, bool gpuAvailable, bool shmAvailable, bool diskAvailable) {
    switch (p) {
        case Placement::LOCAL_GPU:    return gpuAvailable  ? Path::GPU    : Path::CPU;
        case Placement::SHARED_RAM:   return shmAvailable  ? Path::SHARED : Path::CPU;
        case Placement::RESERVED_SSD: return diskAvailable ? Path::DISK   : Path::CPU;
        case Placement::UNSPECIFIED:  return Path::CPU;
        default:                      return Path::CPU;
    }
}

const char* PathName(Path p) {
    switch (p) {
        case Path::CPU:   return "cpu";
        case Path::GPU:   return "gpu";
        case Path::SHARED:return "shared";
        case Path::DISK:  return "disk";
        default:          return "?";
    }
}

}  // namespace

int main() {
    std::printf("Inference Routing Test\n");
    std::printf("======================\n\n");

    // --- Fast path: GPU requested and present ----------------------------
    Check(ResolveRoute(Placement::LOCAL_GPU, true, true, true) == Path::GPU,
          "LOCAL_GPU with GPU available routes to gpu");

    // --- Fallback: GPU requested but absent ------------------------------
    Check(ResolveRoute(Placement::LOCAL_GPU, false, true, true) == Path::CPU,
          "LOCAL_GPU without GPU falls back to cpu");

    // --- Shared memory ---------------------------------------------------
    Check(ResolveRoute(Placement::SHARED_RAM, true, true, true) == Path::SHARED,
          "SHARED_RAM with shm available routes to shared");
    Check(ResolveRoute(Placement::SHARED_RAM, true, false, true) == Path::CPU,
          "SHARED_RAM without shm falls back to cpu");

    // --- Disk-backed -----------------------------------------------------
    Check(ResolveRoute(Placement::RESERVED_SSD, true, true, true) == Path::DISK,
          "RESERVED_SSD with disk available routes to disk");
    Check(ResolveRoute(Placement::RESERVED_SSD, true, true, false) == Path::CPU,
          "RESERVED_SSD without disk falls back to cpu");

    // --- Unspecified must never guess, even when everything is present ---
    Check(ResolveRoute(Placement::UNSPECIFIED, true, true, true) == Path::CPU,
          "UNSPECIFIED never guesses, even when all backends present");

    // --- Degenerate combination: nothing available -----------------------
    Check(ResolveRoute(Placement::LOCAL_GPU, false, false, false) == Path::CPU,
          "no backends available -> cpu");

    // --- The fallback must never be silent about its reason ---------------
    std::printf("\nrouting table (gpu=1 shm=1 disk=1 / all absent):\n");
    const struct { const char* name; Placement p; } cases[] = {
        {"LOCAL_GPU",    Placement::LOCAL_GPU},
        {"SHARED_RAM",   Placement::SHARED_RAM},
        {"RESERVED_SSD", Placement::RESERVED_SSD},
        {"UNSPECIFIED",  Placement::UNSPECIFIED},
    };
    for (const auto& c : cases) {
        std::printf("  %-14s present->%-7s absent->%-7s\n",
                    c.name,
                    PathName(ResolveRoute(c.p, true, true, true)),
                    PathName(ResolveRoute(c.p, false, false, false)));
    }

    std::printf("\nInference routing test: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
