//============================================================================
// nevm_isa.hpp
// RawrXD N-EVM Instruction Set Architecture
// Neural Execution Virtual Machine - VAL-034
//============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace NEVM {
namespace ISA {

//============================================================================
// Instruction Opcodes
//============================================================================

enum class OpCode : uint8_t {
    // Memory Operations
    NLOAD = 0x01,           // Load tensor block: NLOAD tensor_id, block_idx
    NSTORE = 0x02,          // Store tensor block
    NPREFETCH = 0x03,       // Prefetch tensor block
    
    // Decode Operations
    NDECODE = 0x10,         // Decode block: NDECODE mode
    NENCODE = 0x11,         // Encode block (for training/adaptation)
    
    // Compute Operations
    NMATMUL = 0x20,         // Matrix multiply: NMATMUL weight_tensor, activation
    NATTN = 0x21,           // Attention: NATTN Q, K, V
    NFFN = 0x22,            // Feed-forward network
    NACTIV = 0x23,          // Activation function
    NORM = 0x24,            // Layer normalization
    
    // Precision Control
    NPRECISION = 0x30,      // Set precision mode: NPRECISION AUTO|FP16|Q4|NANO
    NPROMOTE = 0x31,        // Promote tensor precision
    NDEMOTE = 0x32,         // Demote tensor precision
    
    // Verification
    NVERIFY = 0x40,         // Verify speculative result
    NACCEPT = 0x41,         // Accept speculative token
    NREJECT = 0x42,         // Reject and retry
    
    // Residency Management
    NRESIDENT = 0x50,       // Make resident: NRESIDENT VRAM|RAM
    NEVICT = 0x51,          // Evict to lower tier
    NSYNC = 0x52,           // Synchronize memory
    
    // Control Flow
    NJMP = 0x60,            // Jump
    NJZ = 0x61,             // Jump if zero
    NJNZ = 0x62,            // Jump if not zero
    NCALL = 0x63,           // Call layer
    NRET = 0x64,            // Return from layer
    NHALT = 0x6F,           // Halt execution
    
    // VM Control
    NCONFIG = 0x70,         // Configure VM: NCONFIG param, value
    NSTATS = 0x71,          // Get statistics
    NRESET = 0x72,          // Reset VM state
    
    // Extensions
    NEXT = 0x80             // Extension opcode (followed by ext_id)
};

//============================================================================
// Precision Modes (for NPRECISION instruction)
//============================================================================

enum class PrecisionMode : uint8_t {
    AUTO = 0,               // Runtime decides based on telemetry
    FP32 = 1,
    FP16 = 2,
    BF16 = 3,
    Q8 = 4,
    Q6 = 5,
    Q5 = 6,
    Q4 = 7,
    Q3 = 8,
    Q2 = 9,
    NANO_2BIT = 10,         // 2-bit codebook
    NANO_1BIT = 11,         // 1-bit binary
    NANO_ADAPTIVE = 12      // Multi-state representation
};

//============================================================================
// Residency Targets (for NRESIDENT instruction)
//============================================================================

enum class ResidencyTarget : uint8_t {
    COLD = 0,               // Disk only
    MAPPED = 1,             // Memory mapped
    RAM = 2,                // System RAM
    VRAM = 3,               // GPU memory
    HOT = 4                 // L3 cache resident
};

//============================================================================
// Instruction Format
//============================================================================

// Base instruction: 8 bytes
struct Instruction {
    OpCode opcode;          // 1 byte
    uint8_t flags;          // 1 byte: [precision:4][async:1][verify:1][reserved:2]
    uint16_t operand_a;     // 2 bytes: tensor_id or register
    uint16_t operand_b;     // 2 bytes: block_idx or immediate
    uint16_t operand_c;     // 2 bytes: additional operand
    
    // 8 bytes total - fits in L1 cache line with 8 instructions
};

// Extended instruction for 64-bit operands
struct ExtendedInstruction {
    Instruction base;
    uint64_t immediate;     // 8 bytes for large addresses
    
    // 16 bytes total
};

//============================================================================
// Virtual Tensor Address Format
//============================================================================

// 64-bit virtual tensor address:
// [63:56] = Layer ID (256 layers max)
// [55:48] = Tensor type (weight, bias, norm, etc.)
// [47:32] = Block index (64K blocks per tensor)
// [31:0]  = Byte offset within block (4GB blocks)

union VirtualTensorAddress {
    uint64_t raw;
    
    struct {
        uint32_t block_offset;      // [31:0]
        uint16_t block_index;       // [47:32]
        uint8_t  tensor_type;       // [55:48]
        uint8_t  layer_id;          // [63:56]
    } fields;
    
    static VirtualTensorAddress Make(uint8_t layer, uint8_t type, uint16_t block, uint32_t offset) {
        VirtualTensorAddress vta;
        vta.fields.layer_id = layer;
        vta.fields.tensor_type = type;
        vta.fields.block_index = block;
        vta.fields.block_offset = offset;
        return vta;
    }
    
    uint64_t BlockKey() const {
        return raw & ~0xFFFFFFFFULL;  // Mask off byte offset
    }
};

//============================================================================
// Tensor Type Enumeration
//============================================================================

enum class TensorType : uint8_t {
    WEIGHT = 0,             // Layer weights
    BIAS = 1,               // Bias terms
    NORM = 2,               // Layer norm parameters
    ATTENTION_Q = 3,        // Query projection
    ATTENTION_K = 4,        // Key projection
    ATTENTION_V = 5,        // Value projection
    ATTENTION_O = 6,        // Output projection
    FFN_GATE = 7,           // FFN gate
    FFN_UP = 8,             // FFN up projection
    FFN_DOWN = 9,           // FFN down projection
    EMBEDDING = 10,         // Token embeddings
    LM_HEAD = 11,           // Language model head
    KV_CACHE_K = 12,        // Key cache
    KV_CACHE_V = 13,        // Value cache
    ACTIVATION = 14,        // Temporary activations
    CUSTOM = 15             // User-defined
};

//============================================================================
// Execution Context
//============================================================================

struct ExecutionContext {
    // Program counter
    uint64_t pc;
    
    // Stack pointer (for layer calls)
    uint64_t sp;
    
    // Current precision mode
    PrecisionMode precision;
    
    // Current layer
    uint8_t current_layer;
    
    // Verification state
    bool speculative_mode;
    float acceptance_threshold;
    
    // Statistics
    uint64_t instructions_executed;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t decodes_performed;
    uint64_t precision_switches;
};

//============================================================================
// Block State Descriptor
//============================================================================

// Represents a tensor block's current representation state
struct BlockState {
    VirtualTensorAddress vta;
    
    // Current representation
    PrecisionMode current_format;
    ResidencyTarget residency;
    
    // Available representations (bitmask)
    uint16_t available_formats;
    
    // Quality metrics
    float reconstruction_error;
    float decode_latency_ms;
    size_t memory_footprint;
    
    // Access statistics
    uint64_t access_count;
    uint64_t last_access_tick;
    float importance_score;      // 0.0-1.0
    
    // Physical location
    void* physical_ptr;
    uint64_t physical_size;
};

} // namespace ISA
} // namespace NEVM
} // namespace RawrXD
