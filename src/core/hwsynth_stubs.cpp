// ============================================================================
// hwsynth_stubs.cpp - Stub implementations for hardware synthesizer functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

void asm_hwsynth_init() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_init stub called\n");
}

void asm_hwsynth_profile_dataflow() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_profile_dataflow stub called\n");
}

void asm_hwsynth_gen_gemm_spec() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_gen_gemm_spec stub called\n");
}

void asm_hwsynth_analyze_memhier() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_analyze_memhier stub called\n");
}

void asm_hwsynth_predict_perf() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_predict_perf stub called\n");
}

void asm_hwsynth_est_resources() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_est_resources stub called\n");
}

void asm_hwsynth_gen_jtag_header() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_gen_jtag_header stub called\n");
}

void* asm_hwsynth_get_stats() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_get_stats stub called\n");
    return nullptr;
}

void asm_hwsynth_shutdown() {
    OutputDebugStringA("[HWSynth] asm_hwsynth_shutdown stub called\n");
}

} // extern "C"
