// ============================================================================
// Sovereign_RingTelemetry.cpp — RingTrapdoor adapter for B014 profiler
// ============================================================================
// Purpose: Second telemetry sink that writes B014 events into a lock-free SPSC
//          shared ring. Does NOT replace authoritative JSON/CSV export.
//
// Architecture:
//   B014 Profiler (existing, authoritative)
//        │
//        ├── JSON file export  ← certification evidence
//        │
//        └── RingTelemetry adapter  ← live IDE consumption
//                 │
//                 ▼
//            SPSC shared ring
//                 │
//                 ▼
//               IDE / Agent
//
// Design:
//   - Lock-free SPSC write on the inference thread
//   - No allocation during hot path
//   - Drop events if ring full (configurable)
//   - Heartbeat for liveness detection
// ============================================================================

#include "Sovereign_ABI.h"
#include <cstring>
#include <cstdio>
#include <windows.h>

namespace {

// Ring slot layout (matches MASM RESP_SLOT layout)
struct alignas(64) RingSlot {
    uint64_t req_id;           // Matches B014 invocation ID
    uint32_t status;           // Event type (SOV_EVENT_*)
    uint32_t flags;            // FLAGS_MORE_DATA, FLAGS_FINAL_CHUNK
    uint32_t payload_len;      // Actual payload bytes
    uint32_t model_state;      // Layer index, head index packed
    uint64_t latency_us;       // Event timestamp (QPC-derived)
    uint8_t  payload[4064];    // RESP_PAYLOAD_CAP
};

static_assert(sizeof(RingSlot) == 4096, "RingSlot must be exactly 4096 bytes");

// Ring header (shared memory layout, matches MASM BRIDGE_RING_CTRL)
struct alignas(64) RingHeader {
    uint64_t magic;            // BRIDGE_MAGIC
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t bridge_state;
    uint32_t feature_bits;
    uint64_t heartbeat_qpc;
    uint32_t req_head;
    uint32_t req_tail;
    uint32_t resp_head;
    uint32_t resp_tail;
    uint64_t dropped_req;
    uint64_t dropped_resp;
    uint64_t cancel_epoch;
    uint64_t cancel_target_req_id;
    uint32_t cancel_flags;
    uint32_t cancel_ack_epoch;
    // Padding to 128 bytes for cache-line separation
    uint8_t  pad[56];
};

static_assert(sizeof(RingHeader) == 128, "RingHeader must be 128 bytes");

// Internal state
struct RingState {
    HANDLE hMapFile = nullptr;
    void*  pMap = nullptr;
    RingHeader* header = nullptr;
    RingSlot*   slots = nullptr;
    uint32_t    slot_count = 0;
    uint32_t    slot_mask = 0;
    uint32_t    local_tail = 0;     // Writer position
    bool        initialized = false;
};

static RingState g_ring;

// Simple QPC → microseconds conversion
static inline uint64_t QpcToMicroseconds(uint64_t qpc) {
    static uint64_t freq = 0;
    if (!freq) {
        LARGE_INTEGER f;
        QueryPerformanceFrequency(&f);
        freq = static_cast<uint64_t>(f.QuadPart);
    }
    return (qpc * 1000000ULL) / freq;
}

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

extern "C" {

bool Sovereign_RingTelemetry_Init(const SovereignRingTelemetryConfig* config) {
    if (!config || !(config->flags & SOV_RING_TELEMETRY_ENABLED)) {
        return false;
    }
    if (config->abi_version != SOVEREIGN_ABI_VERSION_MAJOR) {
        fprintf(stderr, "[RingTelemetry] ABI version mismatch: expected %u, got %u\n",
                SOVEREIGN_ABI_VERSION_MAJOR, config->abi_version);
        return false;
    }

    // Use provided mapping or create our own
    if (config->ring_base && config->hMapFile) {
        g_ring.pMap = config->ring_base;
        g_ring.hMapFile = config->hMapFile;
    } else {
        // Create named shared memory
        const char* mapName = "SOVEREIGN_IDE_BRIDGE_V1";
        g_ring.hMapFile = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            nullptr,
            PAGE_READWRITE,
            0,
            sizeof(RingHeader) + (config->ring_slot_count * sizeof(RingSlot)),
            mapName);
        if (!g_ring.hMapFile) {
            fprintf(stderr, "[RingTelemetry] CreateFileMappingA failed: %lu\n", GetLastError());
            return false;
        }
        g_ring.pMap = MapViewOfFile(g_ring.hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!g_ring.pMap) {
            fprintf(stderr, "[RingTelemetry] MapViewOfFile failed: %lu\n", GetLastError());
            CloseHandle(g_ring.hMapFile);
            g_ring.hMapFile = nullptr;
            return false;
        }
    }

    g_ring.header = static_cast<RingHeader*>(g_ring.pMap);
    g_ring.slots = reinterpret_cast<RingSlot*>(
        static_cast<uint8_t*>(g_ring.pMap) + sizeof(RingHeader));
    g_ring.slot_count = config->ring_slot_count;
    g_ring.slot_mask = config->ring_slot_count - 1;
    g_ring.local_tail = 0;

    // Initialize header if we're the first writer
    if (g_ring.header->magic != BRIDGE_MAGIC) {
        g_ring.header->magic = BRIDGE_MAGIC;
        g_ring.header->version_major = SOVEREIGN_ABI_VERSION_MAJOR;
        g_ring.header->version_minor = SOVEREIGN_ABI_VERSION_MINOR;
        g_ring.header->bridge_state = BRIDGE_STATE_READY;
        g_ring.header->feature_bits = config->flags;
        g_ring.header->req_head = 0;
        g_ring.header->req_tail = 0;
        g_ring.header->resp_head = 0;
        g_ring.header->resp_tail = 0;
        g_ring.header->dropped_req = 0;
        g_ring.header->dropped_resp = 0;
        g_ring.header->cancel_epoch = 0;
        g_ring.header->cancel_target_req_id = 0;
        g_ring.header->cancel_flags = 0;
        g_ring.header->cancel_ack_epoch = 0;
    }

    g_ring.initialized = true;
    fprintf(stderr, "[RingTelemetry] Initialized with %u slots @ %p\n",
            g_ring.slot_count, g_ring.pMap);
    return true;
}

void Sovereign_RingTelemetry_Shutdown() {
    if (!g_ring.initialized) return;
    if (g_ring.pMap) {
        UnmapViewOfFile(g_ring.pMap);
        g_ring.pMap = nullptr;
    }
    if (g_ring.hMapFile) {
        CloseHandle(g_ring.hMapFile);
        g_ring.hMapFile = nullptr;
    }
    g_ring.header = nullptr;
    g_ring.slots = nullptr;
    g_ring.initialized = false;
    fprintf(stderr, "[RingTelemetry] Shutdown complete\n");
}

void Sovereign_RingTelemetry_Emit(uint32_t event_type, uint64_t timestamp_ns,
                                   const void* data, size_t data_len) {
    if (!g_ring.initialized || !g_ring.header || !g_ring.slots) return;

    // Read current head (consumer position)
    uint32_t head = g_ring.header->resp_head;
    uint32_t next_tail = (g_ring.local_tail + 1) & g_ring.slot_mask;

    // Ring full check
    if (next_tail == head) {
        // Ring full — drop or block based on config
        if (g_ring.header->feature_bits & SOV_RING_TELEMETRY_DROP_OK) {
            InterlockedIncrement64(reinterpret_cast<volatile LONGLONG*>(&g_ring.header->dropped_resp));
            return;
        }
        // Blocking not implemented — drop anyway to avoid deadlock
        InterlockedIncrement64(reinterpret_cast<volatile LONGLONG*>(&g_ring.header->dropped_resp));
        return;
    }

    // Write slot
    RingSlot* slot = &g_ring.slots[g_ring.local_tail];
    slot->req_id = 0;  // TODO: map from B014 invocation ID
    slot->status = event_type;
    slot->flags = FLAGS_FINAL_CHUNK;
    slot->payload_len = static_cast<uint32_t>(data_len > 4064 ? 4064 : data_len);
    slot->model_state = 0;
    slot->latency_us = timestamp_ns;  // Caller provides QPC-derived value

    if (data && slot->payload_len > 0) {
        memcpy(slot->payload, data, slot->payload_len);
    }

    // Memory fence + publish
    _mm_sfence();
    g_ring.header->resp_tail = next_tail;
    g_ring.local_tail = next_tail;
}

} // extern "C"
