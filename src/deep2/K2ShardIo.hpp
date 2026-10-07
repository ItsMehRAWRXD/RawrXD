// K2ShardIo.hpp — persistent Win32 shard handles for K2 stream lane
#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

namespace Deep2 {

struct K2ShardIoSnapshot {
    uint64_t readCalls = 0;
    uint64_t readBytes = 0;
    uint64_t readUs = 0;
    uint64_t reopenCount = 0;
    uint64_t seekCount = 0;
    uint64_t mapFaults = 0;
    uint64_t mapFaultUs = 0;
};

void K2ShardIo_Reset();
void K2ShardIo_Close();
void K2ShardIo_ResetCounters();
K2ShardIoSnapshot K2ShardIo_Snapshot();
void K2ShardIo_Emit(FILE* f);
bool K2ShardIo_Enabled();
void K2ShardIo_SetEnabled(bool on);
bool K2ShardIo_Read(const std::string& path, uint64_t offset, void* dst, size_t n);
size_t K2ShardIo_WarmDirectory(const std::string& dir);

} // namespace Deep2
