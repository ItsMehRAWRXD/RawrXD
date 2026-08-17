// disk_recovery_stubs.cpp - Minimal stubs for DiskRecovery symbols
// Used by rawrxd-ceo target to avoid linking full asm_bridge.cpp
// ABI matches rawrxd_subsystem_api.cpp extern declarations exactly.

#include <cstdio>
#include <cstdint>

extern "C" int DiskRecovery_FindDrive(void) {
    printf("[DiskRecovery] FindDrive stub\n");
    return 0;
}

extern "C" void* DiskRecovery_Init(int driveNum) {
    printf("[DiskRecovery] Init stub (drive=%d)\n", driveNum);
    return nullptr;
}

extern "C" int DiskRecovery_ExtractKey(void* ctx) {
    printf("[DiskRecovery] ExtractKey stub\n");
    (void)ctx;
    return 0;
}

extern "C" void DiskRecovery_Run(void* ctx) {
    printf("[DiskRecovery] Run stub\n");
    (void)ctx;
}

extern "C" void DiskRecovery_Abort(void* ctx) {
    printf("[DiskRecovery] Abort stub\n");
    (void)ctx;
}

extern "C" void DiskRecovery_Cleanup(void* ctx) {
    printf("[DiskRecovery] Cleanup stub\n");
    (void)ctx;
}

extern "C" void DiskRecovery_GetStats(void* ctx, uint64_t* outGood,
                                       uint64_t* outBad, uint64_t* outCurrent,
                                       uint64_t* outTotal) {
    printf("[DiskRecovery] GetStats stub\n");
    (void)ctx;
    if (outGood)    *outGood    = 0;
    if (outBad)     *outBad     = 0;
    if (outCurrent) *outCurrent = 0;
    if (outTotal)   *outTotal   = 0;
}
