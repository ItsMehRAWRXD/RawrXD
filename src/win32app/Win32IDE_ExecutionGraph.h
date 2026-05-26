#pragma once

#include <cstdint>

namespace RawrXD {
namespace OS {

// ============================================================================
// PHASE 1: Execution Graph Core (Spec + Contracts)
// ============================================================================

enum XR_DOMAIN : uint8_t {
    CPU_MASM = 0,        // assembly kernels
    CPU_CPP  = 1,        // runtime logic
    GPU_VK   = 2,        // Vulkan/compute shaders
    IO_RING  = 3,        // zero-copy ring bridge
    META     = 4         // scheduler/meta operations
};

enum XR_MEMORY_DOMAIN : uint8_t {
    HOT_KV_CACHE   = 0,
    ACTIVE_TENSOR  = 1,
    RING_BUFFER    = 2,
    GPU_SHARED     = 3,
    NVME_MAPPED    = 4,
    IDE_UI_LAYER   = 5
};

enum XR_DEP_TYPE : uint8_t {
    DATA_DEP = 0,   // output -> input dependency
    CONTROL = 1,    // must execute after
    MEMORY = 2,     // shared buffer dependency
    GPU_SYNC = 3    // GPU pipeline ordering
};

struct XR_MEMORY_BINDING {
    XR_MEMORY_DOMAIN input;
    XR_MEMORY_DOMAIN output;
    uint64_t size_bytes;
    uint8_t zero_copy;
};

struct XR_EXEC_CONTRACT {
    uint64_t latency_ns;        // hard ceiling
    uint64_t avg_latency_ns;    // measured
    uint32_t input_size;
    uint32_t output_size;

    XR_MEMORY_BINDING mem;

    uint8_t domain;
    uint8_t deterministic;
    uint8_t gpu_migratable;
    uint8_t can_skip;
};

struct XR_KVContract {
    uint64_t kv_read_pages[8];     // KV pages required before execution
    uint64_t kv_write_pages[8];    // KV pages modified
    uint32_t read_count;
    uint32_t write_count;

    uint8_t  requires_kv_lock;     // hard dependency barrier
    uint8_t  allow_page_fault;     // soft fault allowed
    uint8_t  eviction_safe;        // can be evicted after execution
    uint8_t  padding;
};

struct XR_CONTRACT {
    uint64_t latency_budget_ns;     // hard real-time expectation
    uint32_t input_region;          // memory zone ID
    uint32_t output_region;         // memory zone ID

    XR_KVContract kv;               // memory-causality contract

    uint8_t  deterministic;         // 1 = no hidden state allowed
    uint8_t  reentrant;             // can execute concurrently
    uint8_t  gpu_allowed;           // can migrate to GPU
    uint8_t  speculative;           // allowed to be skipped under load
};

struct XR_NODE {
    uint32_t node_id;
    void* entry;         // Function pointer (MASM / C++ / GPU kernel thunk)
    uint8_t domain;      // XR_DOMAIN
};

struct XR_NODE_FULL {
    XR_NODE node;
    XR_CONTRACT contract;

    uint32_t dependency_start;
    uint32_t dependency_count;

    uint64_t last_exec_time_ns;
};

struct XR_EDGE {
    uint32_t from_node;
    uint32_t to_node;
    uint8_t dependency_type; // XR_DEP_TYPE
};

struct XR_GRAPH {
    XR_NODE_FULL* nodes;
    uint32_t node_count;

    XR_EDGE* edges;
    uint32_t edge_count;

    uint64_t graph_timestamp;
};

// ============================================================================
// SYSTEM MESSAGE FORMAT
// ============================================================================

enum XR_SYSCALL_TYPE : uint32_t {
    SUBMIT_GRAPH = 0,
    STREAM_TOKEN = 1,
    ATTACH_KV = 2,
    GPU_DISPATCH = 3,
    TELEMETRY = 4
};

struct XR_SYSCALL {
    uint32_t type;            // XR_SYSCALL_TYPE
    uint32_t node_id;
    uint64_t payload_ptr;
    uint8_t priority;
};

// ============================================================================
// SCHEDULER INTERFACE (Minimal core contract)
// ============================================================================

struct XR_RUNTIME {
    XR_GRAPH* graph;

    void (*submit)(XR_GRAPH*);
    void (*tick)(uint64_t budget_ns);
    void (*resolve_dependencies)();
    void (*execute_node)(XR_NODE_FULL*);
};

} // namespace OS
} // namespace RawrXD