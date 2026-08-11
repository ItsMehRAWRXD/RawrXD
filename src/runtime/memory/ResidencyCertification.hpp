// ============================================================================
// ResidencyCertification.hpp
// Four-gate certification for the B015 residency subsystem.
//
// Gate A — EvictionFill
//   Fill RAM → exceed pressure threshold → scan → old unreferenced blocks leave RAM
//   → RAM Used decreases → data remains byte-identical
//
// Gate B — Write-back
//   Modify block → DIRTY → enqueue → worker writes → completion → CLEAN → verify SSD bytes
//
// Gate C — GPU
//   RAM block → GPU upload → fence → GPU reads → compare GPU result against CPU
//
// Gate D — Combined stress
//   RAM pressure + dirty blocks + GPU uploads + concurrent inference + repeated eviction/promotion
// ============================================================================
#pragma once

#include "DRP_EvictionEngine.hpp"
#include <cstdint>
#include <cstring>
#include <vector>
#include <random>
#include <thread>
#include <chrono>
#include <cstdio>

namespace RawrXD {
namespace Memory {
namespace Cert {

// ── Gate A: EvictionFill ───────────────────────────────────────────────────

struct GateAResult {
    bool    passed = false;
    size_t  blocksInserted = 0;
    size_t  blocksEvicted = 0;
    uint64_t ramBefore = 0;
    uint64_t ramAfter = 0;
    uint64_t bytesFreed = 0;
    bool    byteIdentical = false;
    const char* error = nullptr;
};

GateAResult RunGateA(BlockTable& table, DRPEvictionEngine& engine,
                     uint64_t ramCapacity, uint64_t pressureThreshold);

// ── Gate B: Write-back ─────────────────────────────────────────────────────

struct GateBResult {
    bool    passed = false;
    size_t  blocksFlushed = 0;
    size_t  blocksVerified = 0;
    uint64_t flushLatencyUs = 0;
    bool    ssdBytesMatch = false;
    const char* error = nullptr;
};

GateBResult RunGateB(BlockTable& table, DRPEvictionEngine& engine,
                     SSDWriteBackQueue& queue, HANDLE hBackingFile,
                     size_t numBlocks, size_t blockSize);

// ── Gate C: GPU Upload (simulated) ─────────────────────────────────────────

struct GateCResult {
    bool    passed = false;
    size_t  uploadsStarted = 0;
    size_t  uploadsCompleted = 0;
    bool    generationValid = false;
    const char* error = nullptr;
};

GateCResult RunGateC(BlockTable& table, DRPEvictionEngine& engine,
                     size_t numBlocks, size_t blockSize);

// ── Gate D: Combined Stress ────────────────────────────────────────────────

struct GateDResult {
    bool    passed = false;
    uint64_t iterations = 0;
    uint64_t evictions = 0;
    uint64_t promotions = 0;
    uint64_t flushes = 0;
    uint64_t gpuUploads = 0;
    double  durationSec = 0.0;
    bool    noCorruption = false;
    const char* error = nullptr;
};

GateDResult RunGateD(BlockTable& table, DRPEvictionEngine& engine,
                     SSDWriteBackQueue& queue, HANDLE hBackingFile,
                     uint64_t durationSec, size_t numThreads);

// ── Unified runner ───────────────────────────────────────────────────────────

struct CertificationReport {
    GateAResult gateA;
    GateBResult gateB;
    GateCResult gateC;
    GateDResult gateD;
    bool        allPassed = false;
};

CertificationReport RunAllGates(BlockTable& table, DRPEvictionEngine& engine,
                                SSDWriteBackQueue& queue, HANDLE hBackingFile);

void PrintReport(const CertificationReport& r);

} // namespace Cert
} // namespace Memory
} // namespace RawrXD
