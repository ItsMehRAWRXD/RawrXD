// asm_stubs_hwsynth.cpp - Stub implementations for hardware_synthesizer.asm exports
// Provides C++ fallbacks when MASM kernels are not available

#include <cstdint>
#include <cstring>

extern "C" {

int asm_hwsynth_init() {
    return 0;
}

int asm_hwsynth_profile_dataflow(const void* codeGraph, void* profileOut) {
    (void)codeGraph; (void)profileOut;
    return 0;
}

int asm_hwsynth_gen_gemm_spec(const void* profile, void* gemmSpec) {
    (void)profile; (void)gemmSpec;
    return 0;
}

int asm_hwsynth_analyze_memhier(const void* accessPattern, void* hierarchyOut) {
    (void)accessPattern; (void)hierarchyOut;
    return 0;
}

int asm_hwsynth_predict_perf(const void* spec, double* latency, double* throughput) {
    (void)spec;
    if (latency) *latency = 0.0;
    if (throughput) *throughput = 0.0;
    return 0;
}

int asm_hwsynth_est_resources(const void* spec, uint32_t* lutCount, uint32_t* dspCount, uint32_t* bramCount) {
    (void)spec;
    if (lutCount) *lutCount = 0;
    if (dspCount) *dspCount = 0;
    if (bramCount) *bramCount = 0;
    return 0;
}

int asm_hwsynth_gen_jtag_header(const void* bitstream, void* jtagOut) {
    (void)bitstream; (void)jtagOut;
    return 0;
}

void* asm_hwsynth_get_stats() {
    return nullptr;
}

int asm_hwsynth_shutdown() {
    return 0;
}

} // extern "C"
