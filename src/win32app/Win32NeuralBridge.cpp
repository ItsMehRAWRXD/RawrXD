// Win32NeuralBridge.cpp — GATED_STUB (NEURAL_CRDT_GATE_001)
// Orphan C ABI TU: not in WIN32IDE_SOURCES / cmake product link.
// PRIOR: "Production Implementation" Init/CreateOp returned 1 (fake success).
// NOW: GateStub + return 0. Match GateMode / IDE_BRIDGE_STUB_GATE_001 (.h).
// Smoke must NOT claim PASS. PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 RELINK=NO.

#include <windows.h>
#include <cstdint>

namespace {
void GateStub(const char* name) {
    char buf[192];
    wsprintfA(buf, "[Win32NeuralBridge.cpp] GATED_STUB SYNTHETIC=partial name=%s\n", name);
    OutputDebugStringA(buf);
}
} // namespace

extern "C" __declspec(dllexport) int Win32NeuralBridge_Init() {
    GateStub("Init");
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_Shutdown() {
    GateStub("Shutdown");
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_CreateOp(const char* name, int type,
                                                                uint32_t modelId,
                                                                uint32_t* outOpId) {
    (void)name;
    (void)type;
    (void)modelId;
    (void)outOpId;
    GateStub("CreateOp");
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_CompleteOp(uint32_t opId, float accuracy) {
    (void)opId;
    (void)accuracy;
    GateStub("CompleteOp");
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_GetOpInfo(uint32_t opId, char* outName,
                                                                uint32_t maxLen, int* outType,
                                                                uint32_t* outCompleted,
                                                                float* outAccuracy) {
    (void)opId;
    (void)outName;
    (void)maxLen;
    (void)outType;
    (void)outCompleted;
    (void)outAccuracy;
    GateStub("GetOpInfo");
    return 0;
}

extern "C" __declspec(dllexport) int Win32NeuralBridge_GetCompletedCount() {
    GateStub("GetCompletedCount");
    return 0;
}
