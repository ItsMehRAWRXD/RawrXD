#pragma once
#include <string>
#include <vector>
#include <map>
#include <mutex>

namespace RawrXD::Fleet {

class FleetOptimizer {
public:
    struct OptimizationResult {
        std::string recommendation;
        double expected_improvement = 0.0;
        std::string target_node;
    };

    FleetOptimizer() = default;
    ~FleetOptimizer() = default;

    void Measure();
    void CompareNodes();
    OptimizationResult FindBottleneck();
    void GenerateOptimization();
    void DeployImprovement();
    void Benchmark();

    std::vector<OptimizationResult> GetHistory() const;

private:
    struct NodeMetrics {
        std::string node_id;
        double throughput = 0.0;
        double latency = 0.0;
        double gpu_util = 0.0;
        double memory_util = 0.0;
    };

    std::vector<NodeMetrics> metrics_;
    std::vector<OptimizationResult> history_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Fleet
