// disk_recovery_stubs.cpp - Minimal stubs for DiskRecovery symbols
// Used by rawrxd-ceo target to avoid linking full asm_bridge.cpp

#include <cstdio>

extern "C" void DiskRecovery_FindDrive() {
    printf("[DiskRecovery] FindDrive stub\n");
}

extern "C" void DiskRecovery_Init() {
    printf("[DiskRecovery] Init stub\n");
}

extern "C" void DiskRecovery_ExtractKey() {
    printf("[DiskRecovery] ExtractKey stub\n");
}

extern "C" void DiskRecovery_Run() {
    printf("[DiskRecovery] Run stub\n");
}
