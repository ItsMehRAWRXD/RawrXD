#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>

// ---------------------------------------------------------
// Sovereign Execution Graph - Node & Registry Spec
// ---------------------------------------------------------

enum XR_State : uint8_t {
    XR_BLOCKED   = 0,
    XR_READY     = 1,
    XR_RUNNING   = 2,
    XR_DONE      = 3,
    XR_FAILED    = 4,
    XR_PREEMPTED = 5
};

enum XR_NodeType : uint8_t {
    XR_NODE_MASM = 0,
    XR_NODE_CPP  = 1,
    XR_NODE_GPU  = 2,
    XR_NODE_IO   = 3,
    XR_NODE_KV   = 4
};

// Represents a bounding box in the KV Cache Memory space
struct XR_KVContract {
    uint64_t kv_base_ptr;
    uint32_t kv_span_bytes;
    uint32_t stride;
};

struct XR_Node {
    uint64_t id;

    // Execution identity
    const char* name;
    XR_NodeType type;

    // Note: The memory layout here must align with Sovereign_OS_Core.asm
    // Offset 8: Kernel Function Pointer
    void (*pKernel)(void* kv, void* in, void* out, void* meta);
    
    // Offset 16: Deadline
    uint64_t deadline_ns; // Evaluated against RDTSCP

    // Offset 24: Runtime State
    volatile XR_State state;

    // Graph edges
    uint64_t dependencies[8];
    uint32_t dep_count;

    uint64_t dependents[8];
    uint32_t out_count;

    // Execution contract
    XR_KVContract kv;

    // Scheduling metadata
    uint64_t priority;
    uint64_t earliest_ns;
};

// Application-facing Registry to construct the DAG
class XR_GraphRegistry {
public:
    XR_GraphRegistry() = default;
    
    XR_Node* CreateNode(const char* name, XR_NodeType type, void* pKernel) {
        XR_Node node = {};
        node.id = next_id_++;
        node.name = name;
        node.type = type;
        node.pKernel = (void (*)(void*, void*, void*, void*))pKernel;
        node.state = XR_BLOCKED;
        node.dep_count = 0;
        node.out_count = 0;
        
        nodes_.push_back(node);
        return &nodes_.back();
    }
    
    void AddDependency(XR_Node* from, XR_Node* to) {
        if (from->dep_count < 8 && to->out_count < 8) {
            from->dependencies[from->dep_count++] = to->id;
            to->dependents[to->out_count++] = from->id;
        }
    }
    
    std::vector<XR_Node>& GetNodes() { return nodes_; }
    
private:
    uint64_t next_id_ = 1;
    std::vector<XR_Node> nodes_;
};

// Represents the universal execution ABI window passed to MASM instances
struct KVExecutionWindow {
    uint64_t node_id;
    uint64_t kv_base_ptr;
    uint32_t kv_span_bytes;
    uint64_t ttl_ns;
};

extern "C" {
    // FFI Link to MASM Sovereign OS primitives
    void XR_SchedulerTick(void* kv, void* input, void* output, void* metaNodeTable);
    void XR_Kernel_Fuse(void* nodeABase, void* nodeBBase);
}
