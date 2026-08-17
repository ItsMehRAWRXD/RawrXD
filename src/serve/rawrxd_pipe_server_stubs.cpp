// ============================================================================
// rawrxd_pipe_server_stubs.cpp
// ============================================================================
// Stub definitions for hotpatch ASM symbols referenced by rawrxd_pipe_server.cpp
// but not linked into the rawrxd-serve target.  These are no-op stubs that
// allow the pipe server to compile and link without the full MASM hotpatch
// kernel.
// ============================================================================
#include <cstdint>

extern "C" {

uint64_t RawrXD_RequestHotpatch(void* /*modelDescriptor*/, void* /*gpuFence*/) {
    return 0;
}

uint64_t RawrXD_CheckEpochSwap(void) {
    return 0;
}

uint64_t RawrXD_WaitForHotpatchComplete(uint32_t /*timeoutMs*/) {
    return 0;
}

uint64_t RawrXD_InitHotpatchSystem(void) {
    return 0;  // success
}

uint64_t RawrXD_ForceSyncHotpatch(void* /*modelDescriptor*/) {
    return 0;
}

volatile uint64_t g_EpochCounter = 0;
volatile uint64_t g_HotpatchCount = 0;

} // extern "C"
