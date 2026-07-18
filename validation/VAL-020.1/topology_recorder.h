// topology_recorder.h
// VAL-020.1 Execution Topology Capture
// Records kernel dispatch order, hardware, execution trace

#ifndef TOPOLOGY_RECORDER_H
#define TOPOLOGY_RECORDER_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include "tensor_manifest.h"

namespace val020 {

// Hardware capabilities
struct HardwareFingerprint {
    struct CPUInfo {
        std::string vendor;
        std::string model;
        std::vector<std::string> features;  // AVX2, AVX-512, FMA, etc.
        int cores;
        int threads;
    };
    
    struct GPUInfo {
        std::string vendor;
        std::string model;
        std::string driver_version;
        size_t memory_mb;
    };
    
    CPUInfo cpu;
    GPUInfo gpu;  // null if CPU-only
    size_t system_memory_mb;
    
    static HardwareFingerprint detect();
    std::string to_json() const;
};

// Kernel execution record
struct KernelExecution {
    std::string kernel_id;
    std::string kernel_name;
    std::string kernel_version;
    std::string backend;  // "Native", "Vulkan", "ROCm", etc.
    
    std::vector<std::string> input_tensors;
    std::vector<std::string> output_tensors;
    
    std::chrono::high_resolution_clock::time_point start_time;
    std::chrono::high_resolution_clock::time_point end_time;
    double execution_time_ms;
    
    int exit_code;
    std::string error_message;
};

// Execution graph edge
struct ExecutionEdge {
    std::string from_kernel;
    std::string to_kernel;
    std::string tensor_id;
};

// Complete topology capture
struct ExecutionTopology {
    std::string graph_name;
    std::string graph_version;
    std::string backend;
    std::string execution_mode;  // "sequential", "parallel", etc.
    
    HardwareFingerprint hardware;
    
    std::vector<KernelExecution> kernels;
    std::vector<ExecutionEdge> edges;
    
    std::chrono::high_resolution_clock::time_point graph_start;
    std::chrono::high_resolution_clock::time_point graph_end;
    double total_execution_time_ms;
    
    // Serialization
    std::string to_json() const;
    void save_to_file(const std::string& path) const;
};

// Topology recorder - captures execution in real-time
class TopologyRecorder {
public:
    void begin_graph(const std::string& graph_name, 
                     const std::string& backend,
                     const std::string& execution_mode);
    
    void record_kernel_dispatch(const KernelExecution& kernel);
    void record_tensor_flow(const std::string& from_kernel,
                           const std::string& to_kernel,
                           const std::string& tensor_id);
    
    void end_graph();
    
    ExecutionTopology get_topology() const;
    void save_evidence(const std::string& path) const;
    
    // Verification
    bool verify_execution_order() const;
    bool verify_tensor_flow() const;
    
private:
    ExecutionTopology topology_;
    bool recording_ = false;
};

} // namespace val020

#endif // TOPOLOGY_RECORDER_H
