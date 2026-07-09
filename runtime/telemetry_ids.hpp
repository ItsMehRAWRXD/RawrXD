// ============================================================================
// telemetry_ids.hpp - Telemetry Phase ID Taxonomy
// ============================================================================
// C++ header defining telemetry phase IDs for the MASM telemetry core.
// Include this in C++ code to use consistent phase IDs.
// ============================================================================

#pragma once

#include <cstdint>

namespace RawrXD {
namespace Runtime {
namespace Telemetry {

// ============================================================================
// Phase ID Taxonomy
// ============================================================================
// Organized by subsystem with 0x1000 spacing between categories.
// Each phase has START/END pair for timing measurements.
// ============================================================================

enum PhaseID : uint32_t {
    // =========================================================================
    // Format Adapters (0x1000-0x1FFF)
    // =========================================================================
    TELEMETRY_GGUF_INIT_START       = 0x1000,
    TELEMETRY_GGUF_INIT_END         = 0x1001,
    TELEMETRY_GGUF_TENSOR_START     = 0x1002,
    TELEMETRY_GGUF_TENSOR_END       = 0x1003,
    TELEMETRY_GGUF_METADATA_PARSE   = 0x1004,
    TELEMETRY_GGUF_LOAD_COMPLETE    = 0x1005,
    
    // =========================================================================
    // Quantization (0x2000-0x2FFF)
    // =========================================================================
    TELEMETRY_Q2K_DECODE_BLOCK      = 0x2000,
    TELEMETRY_Q4K_DECODE_BLOCK      = 0x2001,
    TELEMETRY_Q6K_DECODE_BLOCK      = 0x2002,
    TELEMETRY_Q8K_DECODE_BLOCK      = 0x2003,
    TELEMETRY_F16_TO_F32            = 0x2010,
    TELEMETRY_BF16_TO_F32           = 0x2011,
    TELEMETRY_DEQUANTIZE_ROW        = 0x2020,
    
    // =========================================================================
    // Runtime - Normalization (0x3000-0x30FF)
    // =========================================================================
    TELEMETRY_RMSNORM_START         = 0x3000,
    TELEMETRY_RMSNORM_END           = 0x3001,
    TELEMETRY_LAYERNORM_START       = 0x3002,
    TELEMETRY_LAYERNORM_END         = 0x3003,
    
    // =========================================================================
    // Runtime - Attention (0x3100-0x31FF)
    // =========================================================================
    TELEMETRY_ATTENTION_START       = 0x3100,
    TELEMETRY_ATTENTION_QKV         = 0x3101,  // Q/K/V projection
    TELEMETRY_ATTENTION_ROPE        = 0x3102,  // Rotary embeddings
    TELEMETRY_ATTENTION_SCORES      = 0x3103,  // Q @ K^T
    TELEMETRY_ATTENTION_SOFTMAX     = 0x3104,
    TELEMETRY_ATTENTION_WEIGHTED    = 0x3105,  // Softmax @ V
    TELEMETRY_ATTENTION_OUTPUT      = 0x3106,  // O projection
    TELEMETRY_ATTENTION_END         = 0x3107,
    
    // =========================================================================
    // Runtime - MLP (0x3200-0x32FF)
    // =========================================================================
    TELEMETRY_MLP_START             = 0x3200,
    TELEMETRY_MLP_GATE              = 0x3201,  // Gate projection
    TELEMETRY_MLP_UP                = 0x3202,  // Up projection
    TELEMETRY_MLP_SiLU              = 0x3203,  // SiLU activation
    TELEMETRY_MLP_MUL               = 0x3204,  // Gate * Up
    TELEMETRY_MLP_DOWN              = 0x3205,  // Down projection
    TELEMETRY_MLP_END               = 0x3206,
    
    // =========================================================================
    // Runtime - Transformer Layer (0x3300-0x33FF)
    // =========================================================================
    TELEMETRY_LAYER_START           = 0x3300,
    TELEMETRY_LAYER_ATTN            = 0x3301,
    TELEMETRY_LAYER_MLP             = 0x3302,
    TELEMETRY_LAYER_END             = 0x3303,
    
    // =========================================================================
    // Backend - Bridge (0x4000-0x4FFF)
    // =========================================================================
    TELEMETRY_BRIDGE_INIT           = 0x4000,
    TELEMETRY_BRIDGE_LOAD_MODEL     = 0x4001,
    TELEMETRY_BRIDGE_BIND_TENSORS   = 0x4002,
    TELEMETRY_TOKEN_EMBED           = 0x4010,
    TELEMETRY_TRANSFORMER_FORWARD   = 0x4011,
    TELEMETRY_LOGITS_PROJECTION     = 0x4012,
    TELEMETRY_SAMPLING              = 0x4013,
    TELEMETRY_BRIDGE_SHUTDOWN       = 0x4014,
    
    // =========================================================================
    // Generation (0x5000-0x5FFF)
    // =========================================================================
    TELEMETRY_GENERATION_START      = 0x5000,
    TELEMETRY_GENERATION_TOKEN      = 0x5001,  // Per-token timing
    TELEMETRY_GENERATION_BATCH      = 0x5002,  // Batch processing
    TELEMETRY_GENERATION_PREFILL    = 0x5003,  // Initial prompt processing
    TELEMETRY_GENERATION_END        = 0x5004,
    
    // =========================================================================
    // Memory (0x6000-0x6FFF)
    // =========================================================================
    TELEMETRY_KV_CACHE_ALLOC        = 0x6000,
    TELEMETRY_KV_CACHE_WRITE        = 0x6001,
    TELEMETRY_KV_CACHE_READ         = 0x6002,
    TELEMETRY_TENSOR_ALLOC          = 0x6010,
    TELEMETRY_TENSOR_FREE           = 0x6011,
    
    // =========================================================================
    // System (0x7000-0x7FFF)
    // =========================================================================
    TELEMETRY_SYSTEM_INIT           = 0x7000,
    TELEMETRY_SYSTEM_SHUTDOWN       = 0x7001,
    TELEMETRY_THREAD_POOL_EXEC      = 0x7010,
};

// ============================================================================
// Telemetry Entry Structure (matches MASM layout)
// ============================================================================
// Layout: phase_id (4) + padding (4) + timestamp (8) + value0 (8) + value1 (8) = 32 bytes
// Note: value2 removed to fit in 32 bytes (cache line friendly)
#pragma pack(push, 1)
struct TelemetryEntry {
    uint32_t phase_id;      // PhaseID value
    uint32_t padding;       // Alignment padding
    uint64_t timestamp;     // RDTSC timestamp
    uint64_t value0;        // Context-dependent value
    uint64_t value1;        // Context-dependent value
};
#pragma pack(pop)

static_assert(sizeof(TelemetryEntry) == 32, "TelemetryEntry must be 32 bytes");

// ============================================================================
// C++ Wrapper Functions (call MASM implementations)
// ============================================================================
extern "C" {
    // Write telemetry entry
    void Telemetry_Log(uint32_t phase_id, uint64_t value0 = 0, 
                       uint64_t value1 = 0);
    
    // Dump entries to buffer
    uint64_t Telemetry_Dump(TelemetryEntry* buffer, uint64_t max_entries);
    
    // Reset telemetry buffer
    void Telemetry_Reset();
    
    // Get current entry count
    uint64_t Telemetry_GetCount();
    
    // Get dropped entry count
    uint64_t Telemetry_GetDropped();
    
    // Get current timestamp
    uint64_t Telemetry_Now();
}

// ============================================================================
// RAII Telemetry Scope (automatic START/END)
// ============================================================================
class TelemetryScope {
public:
    TelemetryScope(uint32_t start_phase, uint32_t end_phase, 
                   uint64_t value0 = 0, uint64_t value1 = 0)
        : m_endPhase(end_phase), m_value0(value0), m_value1(value1) {
        Telemetry_Log(start_phase, value0, value1);
    }
    
    ~TelemetryScope() {
        Telemetry_Log(m_endPhase, m_value0, m_value1);
    }
    
private:
    uint32_t m_endPhase;
    uint64_t m_value0;
    uint64_t m_value1;
};

// Convenience macros
#define TELEMETRY_SCOPE(start_phase, end_phase) \
    TelemetryScope _telemetry_scope(start_phase, end_phase)

#define TELEMETRY_SCOPE_VALUES(start_phase, end_phase, v0, v1) \
    TelemetryScope _telemetry_scope(start_phase, end_phase, v0, v1)

} // namespace Telemetry
} // namespace Runtime
} // namespace RawrXD
