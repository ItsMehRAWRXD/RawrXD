#pragma once
#include "rawrxd_host.hpp"
#include <cstdint>
#include <cstddef>
#include <string>

// ============================================================================
// RawrXD Named Pipe Server — Binary Packet Protocol
// B017.1: Fixed header, request IDs, payload framing, status codes
// ============================================================================
// Packet structure:
//   Header (24 bytes, fixed)
//   Payload (variable, length-delimited)
//
// All multi-byte fields are little-endian.
// ============================================================================

#pragma pack(push, 1)

struct RawrXDPacketHeader {
    uint32_t magic;        // RAWRXD_PACKET_MAGIC ('RAWR')
    uint32_t version;      // 0x00010000
    uint32_t type;         // Request or response type
    uint32_t flags;        // Protocol flags
    uint32_t payload_size; // Bytes following header
    uint64_t request_id;   // Correlation ID (responses echo request_id)
};

// Payload structures for specific request types

// RAWRXD_REQ_LOAD_MODEL
struct RawrXDReqLoadModel {
    char     path[512];
    uint32_t gpu_device_index;
    uint32_t reserved;
};

// RAWRXD_REQ_GENERATE / RAWRXD_REQ_GENERATE_BATCH
struct RawrXDReqGenerate {
    uint32_t model_id;
    uint32_t max_new_tokens;
    uint32_t token_count;
    // tokens follow as uint32_t[token_count]
};

// RAWRXD_REQ_RESET
struct RawrXDReqReset {
    uint32_t model_id;
    uint32_t reserved;
};

// RAWRXD_REQ_STATS
struct RawrXDReqStats {
    uint32_t model_id;
    uint32_t reserved;
};

// RAWRXD_RESP_OK (empty payload, just status)
// RAWRXD_RESP_ERROR
struct RawrXDRespError {
    int32_t  error_code;
    char     message[256];
};

// RAWRXD_RESP_STREAM_CHUNK
struct RawrXDRespStreamChunk {
    uint32_t model_id;
    uint32_t token_id;
    uint32_t is_final;     // 1 = last token, 0 = more coming
    uint32_t reserved;
};

// RAWRXD_RESP_STATS
struct RawrXDRespStats {
    rawrxd_host_stats_t stats;
};

#pragma pack(pop)

static_assert(sizeof(RawrXDPacketHeader) == 28, "Packet header must be 28 bytes");
static_assert(sizeof(RawrXDReqLoadModel) == 520, "LoadModel payload size mismatch");
static_assert(sizeof(RawrXDReqGenerate) == 12, "Generate payload size mismatch");
static_assert(sizeof(RawrXDReqReset) == 8, "Reset payload size mismatch");
static_assert(sizeof(RawrXDReqStats) == 8, "Stats payload size mismatch");
static_assert(sizeof(RawrXDRespError) == 260, "Error payload size mismatch");
static_assert(sizeof(RawrXDRespStreamChunk) == 16, "StreamChunk payload size mismatch");
static_assert(sizeof(RawrXDRespStats) == sizeof(rawrxd_host_stats_t), "Stats payload size mismatch");

// ============================================================================
// Pipe Server API
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// Start the named pipe server. Blocks until shutdown signal.
//   pipe_name: e.g., "\\\\.\\pipe\\RawrXD" (NULL = default)
//   Returns: 0 on clean shutdown, negative on error
int rawrxd_pipe_server_run(const char* pipe_name);

// Signal the pipe server to shut down gracefully
void rawrxd_pipe_server_shutdown(void);

#ifdef __cplusplus
}
#endif
