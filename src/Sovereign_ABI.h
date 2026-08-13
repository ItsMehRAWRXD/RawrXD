// ============================================================================
// Sovereign_ABI.h — Stub for RawrXDHost build
// B017: Minimal ABI compatibility header
// ============================================================================
#pragma once
#include <cstdint>

#define SOVEREIGN_ABI_VERSION_MAJOR 1
#define SOVEREIGN_ABI_VERSION_MINOR 0
#define SOVEREIGN_ABI_VERSION_PATCH 0

// Minimal ABI structures required by rawrxd_transformer.h
struct SovereignConfig {
    uint32_t abi_version;
    uint32_t flags;
    uint64_t reserved[4];
};

struct SovereignTelemetry {
    uint64_t tokens_generated;
    uint64_t tokens_processed;
    double   latency_ms;
    double   throughput_tps;
};
