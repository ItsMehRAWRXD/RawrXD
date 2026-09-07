// K2WeightResolve.hpp — one weight resolver / one ownership policy
#pragma once
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace Deep2 {
class GlobalTensorIndex;

struct WeightSpan {
    const uint8_t* data = nullptr;
    size_t bytes = 0;
    bool borrowed = false; // true = retained cache; false = ownedBuf
};

// ResolveWeight: retained cache → BorrowSpan; else shard → install → borrow.
// Never memcpy on cache hit. Attn consumers must use this exclusively.
bool ResolveWeight(const GlobalTensorIndex& index, const char* name,
                   WeightSpan& out, std::vector<uint8_t>& ownedBuf,
                   std::string& error);

void WeightResolve_Reset();
void WeightResolve_Emit(FILE* f);

uint64_t AttnResolveTotal();
uint64_t AttnResolveCache();
uint64_t AttnResolveShard();
uint64_t AttnCacheKeyMiss();
uint64_t AttnCacheGenMiss();
uint64_t AttnCacheWsVeto();
uint64_t AttnCacheTypeMismatch();
uint64_t AttnCacheRangeMismatch();
uint64_t AttnBorrowBytes();
uint64_t AttnShardBytes();
uint64_t AttnShardReadCalls();
uint64_t AttnShardReopen();
uint64_t AttnMapFaultCritical();

// Vocab / output.weight resolve partition (timed: shard must be 0).
uint64_t VocabResolveTotal();
uint64_t VocabResolveCache();
uint64_t VocabResolveShard();
uint64_t VocabShardBytes();
uint64_t VocabShardReadCalls();

} // namespace Deep2
