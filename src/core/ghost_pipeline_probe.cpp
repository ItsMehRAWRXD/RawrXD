/**
 * @file ghost_pipeline_probe.cpp
 * @brief Ghost Pipeline Probe CLI — GATED (LORA_KERNEL_STUB_GATE_001)
 *
 * Orphan / CMake-omitted from RawrXD-Win32IDE. Prior body printed success
 * and returned 0 without a real probe — fake success. Fail-closed.
 */

#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#endif

namespace rawrxd {
namespace ghost_pipeline_probe {

/**
 * @brief Run Ghost Pipeline Probe CLI
 * @return 0 on success, non-zero on failure
 */
int runGhostPipelineProbeCli(void) {
#ifdef _WIN32
    OutputDebugStringA(
        "[GhostPipelineProbe] GATED SYNTHETIC=partial "
        "name=runGhostPipelineProbeCli\n");
#endif
    fprintf(stderr,
            "[GhostPipelineProbe] GATED SYNTHETIC=partial — no real probe\n");
    return -1;
}

} // namespace ghost_pipeline_probe
} // namespace rawrxd
