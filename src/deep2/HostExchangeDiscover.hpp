#pragma once
// HostExchangeDiscover — reverse objects absent from GpuTransfer mirror.
#include <cstdint>
#include <cstdio>

namespace Deep2 {

enum class HostXchgRole : uint8_t {
    D2hStagingMap = 0,
    H2dStagingMap = 1,
    CpuMemcpyFromMap = 2,
    CpuMemcpyToMap = 3,
    DeviceToHostVisible = 4,
    HostIoCapGrow = 5,
    QbConsumerWindow = 6,
    Unknown = 7
};

// Discover/log an exchange not (correctly) present in GpuTransfer mirror.
void HostXchg_Note(const char* name, HostXchgRole role, uint64_t bytes,
                   uint64_t ptrOrKey, int inGpuTransferMirror,
                   const char* mirrorLabel /*nullable*/);

void HostXchg_Reset();
void HostXchg_Emit(FILE* f);

uint64_t HostXchg_UnmirroredBytes();
uint64_t HostXchg_UnmirroredOps();
uint64_t HostXchg_MislabeledBytes();

} // namespace Deep2
