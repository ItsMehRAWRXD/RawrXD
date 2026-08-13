#pragma once
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// RawrXD Native Host Control Plane — C ABI
// B017: IPC + lifecycle + isolation certification
// ============================================================================
// Design rules:
//   - C ABI only (opaque handles, no C++ types across boundary)
//   - Fixed-width types only
//   - No inference, GEMM, tokenizer, or GGUF parsing in host
//   - Thin translation layer into certified engine
// ============================================================================

#define RAWRXD_HOST_VERSION_MAJOR 1
#define RAWRXD_HOST_VERSION_MINOR 0
#define RAWRXD_HOST_VERSION_PATCH 0

// Opaque host handle
typedef struct RawrXDHost* rawrxd_host_t;

// ============================================================================
// Error codes
// ============================================================================
#define RAWRXD_OK                    0
#define RAWRXD_ERR_INVALID_PARAM    -1
#define RAWRXD_ERR_OUT_OF_MEMORY    -2
#define RAWRXD_ERR_MODEL_NOT_FOUND  -3
#define RAWRXD_ERR_ENGINE_INIT      -4
#define RAWRXD_ERR_INFERENCE        -5
#define RAWRXD_ERR_NOT_IMPLEMENTED  -6
#define RAWRXD_ERR_PIPE_IO          -7
#define RAWRXD_ERR_PROTOCOL         -8

// ============================================================================
// Host configuration
// ============================================================================
typedef struct {
    uint32_t version;              // Must be 0x00010000
    uint32_t flags;
    uint64_t weight_residency_max_bytes;
    uint32_t gpu_device_index;     // 0 = default, 1+ = specific device
    const char* pipe_name;         // Named pipe name (NULL = default)
} rawrxd_host_config_t;

// ============================================================================
// Model registry entry (shallow metadata only)
// ============================================================================
typedef struct {
    uint32_t model_id;
    char     path[512];
    char     architecture[64];
    uint32_t context_length;
    uint64_t parameter_count;
    char     quantization[16];
    uint8_t  metadata_checksum[32]; // SHA-256
} rawrxd_host_model_info_t;

// ============================================================================
// Engine telemetry (exposed from certified engine, not computed in host)
// ============================================================================
typedef struct {
    uint64_t total_tokens_generated;
    uint64_t total_prompt_tokens_processed;
    double   avg_latency_ms;
    double   peak_tokens_per_sec;
    uint64_t weight_residency_hits;
    uint64_t weight_residency_misses;
    uint64_t kv_cache_bytes;
    uint32_t active_layers;
    uint32_t active_heads;
    uint32_t active_kv_heads;
    uint32_t pad[3];               // Align to 64 bytes
} rawrxd_host_stats_t;

// ============================================================================
// Binary packet protocol (named pipe framing)
// ============================================================================
#define RAWRXD_PACKET_MAGIC   0x52415752u  // 'RAWR'
#define RAWRXD_PACKET_VERSION 0x00010000u

// Request types (host → engine)
#define RAWRXD_REQ_LOAD_MODEL    0x01
#define RAWRXD_REQ_GENERATE      0x02
#define RAWRXD_REQ_GENERATE_BATCH 0x03
#define RAWRXD_REQ_RESET         0x04
#define RAWRXD_REQ_STATS         0x05
#define RAWRXD_REQ_SHUTDOWN      0x06

// Response types (engine → host)
#define RAWRXD_RESP_OK           0x81
#define RAWRXD_RESP_ERROR        0x82
#define RAWRXD_RESP_STREAM_CHUNK 0x83
#define RAWRXD_RESP_STATS        0x84

// Flags
#define RAWRXD_FLAG_STREAMING    0x00000001u
#define RAWRXD_FLAG_BATCHED      0x00000002u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    uint32_t flags;
    uint32_t payload_size;
    uint32_t reserved;
    uint64_t request_id;
} rawrxd_packet_header_t;

static_assert(sizeof(rawrxd_packet_header_t) == 32, "packet header must be 32 bytes");

// ============================================================================
// C ABI functions
// ============================================================================

// Create a new host instance. Returns NULL on failure.
rawrxd_host_t rawrxd_host_create(const rawrxd_host_config_t* config);

// Load a model into the engine. Returns model_id via out_model_id.
// The host does not parse GGUF; it delegates to the certified loader.
int rawrxd_host_load_model(
    rawrxd_host_t host,
    const char* model_path,
    uint32_t* out_model_id);

// Single-token generation (delegates to Forward)
int rawrxd_host_generate(
    rawrxd_host_t host,
    uint32_t model_id,
    const uint32_t* prompt_tokens,
    size_t prompt_count,
    size_t max_new_tokens,
    float* out_logits,          // Caller-allocated, size = vocab_size
    size_t* out_logits_count);

// Batched prefill (delegates to ForwardBatch / B009)
int rawrxd_host_generate_batch(
    rawrxd_host_t host,
    uint32_t model_id,
    const uint32_t* prompt_tokens,
    size_t prompt_count,
    size_t max_new_tokens,
    float* out_logits,
    size_t* out_logits_count);

// Reset KV cache and engine state for a model
int rawrxd_host_reset(rawrxd_host_t host, uint32_t model_id);

// Retrieve engine telemetry
int rawrxd_host_get_stats(
    rawrxd_host_t host,
    uint32_t model_id,
    rawrxd_host_stats_t* out_stats);

// Destroy host instance and all associated resources
void rawrxd_host_destroy(rawrxd_host_t host);

// ============================================================================
// Utility
// ============================================================================
const char* rawrxd_host_strerror(int error_code);

#ifdef __cplusplus
}
#endif
