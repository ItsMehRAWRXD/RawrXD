// K2LivePathTensorCache.hpp — live-path host residency + bound telemetry
#pragma once
#include <cstdint>
#include <cstdio>
#include <string>

namespace Deep2 {

struct K2LiveCacheStats {
    uint64_t budget = 0;
    uint64_t bytes = 0;
    uint64_t bytesPeak = 0;
    uint32_t entries = 0;
    uint32_t entriesPeak = 0;
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t bytesSaved = 0;
    uint64_t evictionCount = 0;
    uint64_t evictionBytes = 0;
    uint64_t prefetchAccepted = 0;
    uint64_t prefetchSuppressed = 0;
    uint64_t prefetchAlreadyResident = 0;
    uint64_t bytesAfterWarm = 0;
    uint64_t outputWeightBytes = 0;
    // Combined-policy ownership witnesses
    uint64_t trampOutHits = 0;
    uint64_t trampOutBytesSaved = 0;
    uint64_t cycloneLayerAcquires = 0;
    uint64_t cycloneLayerHits = 0;
    uint64_t elasticResidentHits = 0;
    uint64_t combinedDupAcquires = 0;
    uint64_t combinedRedundantBytes = 0;
    uint64_t combinedWaitUs = 0;
};

void K2LiveCache_Reset(uint64_t budgetBytes);
void K2LiveCache_Clear(); // frees entries; keeps cumulative counters
bool K2LiveCache_Wanted();
bool K2LiveCache_LayerHostFillAllowed();
bool K2LiveCache_Has(const std::string& name);
bool K2LiveCache_TryGet(const std::string& name, const uint8_t*& data,
                        size_t& bytes);
bool K2LiveCache_Put(const std::string& name, const uint8_t* data, size_t bytes);
void K2LiveCache_PrefetchLayer(const class GlobalTensorIndex& index,
                               uint32_t layer, uint32_t lookahead);
void K2LiveCache_MarkWarm();
void K2LiveCache_NotePrefetchAlready(uint64_t n);
void K2LiveCache_NotePrefetchAccepted(uint64_t n);
void K2LiveCache_NotePrefetchSuppressed(uint64_t n);
void K2LiveCache_NoteBytesSaved(uint64_t bytes);
void K2LiveCache_NoteOutputWeight(uint64_t bytes);
void K2LiveCache_NoteTrampOutHit(uint64_t bytesSaved);
void K2LiveCache_NoteLayerAcquire();
void K2LiveCache_NoteLayerHit(uint64_t bytesSaved);
void K2LiveCache_NoteCombinedDup(uint64_t bytes);
void K2LiveCache_NoteCombinedWaitUs(uint64_t us);
K2LiveCacheStats K2LiveCache_Snapshot();
void K2LiveCache_Emit(FILE* f);
uint64_t K2LiveCache_Bytes();
uint64_t K2LiveCache_Hits();
uint64_t K2LiveCache_Misses();
uint32_t K2LiveCache_Entries();
uint64_t K2LiveCache_Budget();

} // namespace Deep2
