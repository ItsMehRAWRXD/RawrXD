#pragma once
#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Runtime {
namespace Telemetry {

// ============================================================================
// MASM Telemetry Bridge - C++ to MASM Integration
// ============================================================================
// Provides zero-overhead telemetry logging to MASM ring buffer
// No CRT, no allocations, just direct syscall-based logging
// ============================================================================

// Phase IDs (must match MASM telemetry.asm)
constexpr uint32_t TELEMETRY_PHASE_INIT           = 0x0001;
constexpr uint32_t TELEMETRY_PHASE_SHUTDOWN       = 0x0002;

// Layer phases (0x1000-0x1FFF)
constexpr uint32_t TELEMETRY_LAYER_LOAD_START   = 0x1000;
constexpr uint32_t TELEMETRY_LAYER_LOAD_END     = 0x1001;
constexpr uint32_t TELEMETRY_LAYER_EXEC_START   = 0x1002;
constexpr uint32_t TELEMETRY_LAYER_EXEC_END     = 0x1003;
constexpr uint32_t TELEMETRY_LAYER_UNLOAD_START = 0x1004;
constexpr uint32_t TELEMETRY_LAYER_UNLOAD_END   = 0x1005;

// Operation phases (0x2000-0x2FFF)
constexpr uint32_t TELEMETRY_OP_RMSNORM_START   = 0x2000;
constexpr uint32_t TELEMETRY_OP_RMSNORM_END     = 0x2001;
constexpr uint32_t TELEMETRY_OP_MATMUL_START    = 0x2002;
constexpr uint32_t TELEMETRY_OP_MATMUL_END       = 0x2003;
constexpr uint32_t TELEMETRY_OP_ATTN_START       = 0x2004;
constexpr uint32_t TELEMETRY_OP_ATTN_END         = 0x2005;
constexpr uint32_t TELEMETRY_OP_MLP_START        = 0x2006;
constexpr uint32_t TELEMETRY_OP_MLP_END          = 0x2007;
constexpr uint32_t TELEMETRY_OP_DEQUANT_START    = 0x2008;
constexpr uint32_t TELEMETRY_OP_DEQUANT_END      = 0x2009;

// Memory phases (0x3000-0x3FFF)
constexpr uint32_t TELEMETRY_MEM_MMAP_START      = 0x3000;
constexpr uint32_t TELEMETRY_MEM_MMAP_END        = 0x3001;
constexpr uint32_t TELEMETRY_MEM_ALLOC           = 0x3002;
constexpr uint32_t TELEMETRY_MEM_FREE            = 0x3003;

// External function declarations (implemented in MASM)
extern "C" {
    // Initialize telemetry subsystem
    // Returns: 0 on success, non-zero on error
    int32_t MasmTelemetry_Init(uint64_t bufferSize);
    
    // Shutdown telemetry subsystem
    void MasmTelemetry_Shutdown();
    
    // Log a telemetry event (inline, zero-overhead)
    // phase: Phase ID from taxonomy above
    // value0: Generic value 0 (e.g., layer index, token count)
    // value1: Generic value 1 (e.g., bytes processed, duration)
    void MasmTelemetry_Log(uint32_t phase, uint64_t value0, uint64_t value1);
    
    // Get current timestamp (RDTSC)
    uint64_t MasmTelemetry_Rdtsc();
    
    // Flush telemetry buffer to output
    // Returns: Number of events flushed
    uint64_t MasmTelemetry_Flush();
    
    // Get telemetry statistics
    struct TelemetryStats {
        uint64_t eventsLogged;
        uint64_t eventsDropped;
        uint64_t bufferSize;
        uint64_t bufferUsed;
    };
    void MasmTelemetry_GetStats(TelemetryStats* stats);
}

// ============================================================================
// C++ Wrapper Classes
// ============================================================================

// RAII scope for automatic START/END logging
class MasmTelemetryScope {
public:
    MasmTelemetryScope(uint32_t startPhase, uint32_t endPhase, 
                       uint64_t value0 = 0, uint64_t value1 = 0)
        : m_endPhase(endPhase), m_value0(value0), m_value1(value1) {
        MasmTelemetry_Log(startPhase, value0, value1);
    }
    
    ~MasmTelemetryScope() {
        MasmTelemetry_Log(m_endPhase, m_value0, m_value1);
    }
    
    // Update values for end phase
    void SetValues(uint64_t value0, uint64_t value1) {
        m_value0 = value0;
        m_value1 = value1;
    }
    
private:
    uint32_t m_endPhase;
    uint64_t m_value0;
    uint64_t m_value1;
};

// Layer-specific telemetry helper
class LayerTelemetry {
public:
    explicit LayerTelemetry(uint32_t layerIdx) : m_layerIdx(layerIdx) {}
    
    void LoadStart() const {
        MasmTelemetry_Log(TELEMETRY_LAYER_LOAD_START, m_layerIdx, 0);
    }
    
    void LoadEnd(uint64_t bytesLoaded) const {
        MasmTelemetry_Log(TELEMETRY_LAYER_LOAD_END, m_layerIdx, bytesLoaded);
    }
    
    void ExecStart() const {
        MasmTelemetry_Log(TELEMETRY_LAYER_EXEC_START, m_layerIdx, 0);
    }
    
    void ExecEnd(uint64_t duration) const {
        MasmTelemetry_Log(TELEMETRY_LAYER_EXEC_END, m_layerIdx, duration);
    }
    
    void UnloadStart() const {
        MasmTelemetry_Log(TELEMETRY_LAYER_UNLOAD_START, m_layerIdx, 0);
    }
    
    void UnloadEnd() const {
        MasmTelemetry_Log(TELEMETRY_LAYER_UNLOAD_END, m_layerIdx, 0);
    }
    
private:
    uint32_t m_layerIdx;
};

// Operation telemetry helper
class OpTelemetry {
public:
    static void RMSNorm(uint32_t size) {
        MasmTelemetry_Log(TELEMETRY_OP_RMSNORM_START, size, 0);
    }
    
    static void RMSNormEnd(uint64_t duration) {
        MasmTelemetry_Log(TELEMETRY_OP_RMSNORM_END, duration, 0);
    }
    
    static void MatMul(uint32_t m, uint32_t n, uint32_t k) {
        // m,n,k dimensions
        MasmTelemetry_Log(TELEMETRY_OP_MATMUL_START, 
                         (static_cast<uint64_t>(m) << 32) | n, k);
    }
    
    static void MatMulEnd(uint64_t duration) {
        MasmTelemetry_Log(TELEMETRY_OP_MATMUL_END, duration, 0);
    }
    
    static void Attention(uint32_t seqLen, uint32_t numHeads, uint32_t headDim) {
        MasmTelemetry_Log(TELEMETRY_OP_ATTN_START,
                         (static_cast<uint64_t>(seqLen) << 32) | numHeads, headDim);
    }
    
    static void AttentionEnd(uint64_t duration) {
        MasmTelemetry_Log(TELEMETRY_OP_ATTN_END, duration, 0);
    }
    
    static void MLP(uint32_t hiddenSize, uint32_t intermediateSize) {
        MasmTelemetry_Log(TELEMETRY_OP_MLP_START, hiddenSize, intermediateSize);
    }
    
    static void MLPEnd(uint64_t duration) {
        MasmTelemetry_Log(TELEMETRY_OP_MLP_END, duration, 0);
    }
    
    static void Dequantize(uint32_t numElements, uint32_t type) {
        MasmTelemetry_Log(TELEMETRY_OP_DEQUANT_START, numElements, type);
    }
    
    static void DequantizeEnd(uint64_t duration) {
        MasmTelemetry_Log(TELEMETRY_OP_DEQUANT_END, duration, 0);
    }
};

// Convenience macros
#define MASM_TELEMETRY_SCOPE(start_phase, end_phase) \
    MasmTelemetryScope _masm_telemetry_scope(start_phase, end_phase)

#define MASM_TELEMETRY_SCOPE_VALUES(start_phase, end_phase, v0, v1) \
    MasmTelemetryScope _masm_telemetry_scope(start_phase, end_phase, v0, v1)

// ============================================================================
// Initialization
// ============================================================================

inline bool InitializeMasmTelemetry(uint64_t bufferSize = 1024 * 1024) {
    return MasmTelemetry_Init(bufferSize) == 0;
}

inline void ShutdownMasmTelemetry() {
    MasmTelemetry_Shutdown();
}

} // namespace Telemetry
} // namespace Runtime
} // namespace RawrXD
