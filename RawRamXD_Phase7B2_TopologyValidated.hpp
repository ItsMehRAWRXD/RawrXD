// =============================================================================
// RawRamXD_Phase7B2_TopologyValidated.hpp
// Multi-GPU Fabric with Real Topology, Cost Model, and Transfer Validation
// =============================================================================
// Gates F1-F6: Enumeration, Topology, Bandwidth, Placement, Inference, Economics
// =============================================================================

#ifndef RAWRAMXD_PHASE7B2_TOPOLOGY_VALIDATED_HPP
#define RAWRAMXD_PHASE7B2_TOPOLOGY_VALIDATED_HPP

#include <windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <fstream>
#include <json/json.h>

#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "dxgi.lib")

namespace RawRamXD {

// =============================================================================
// F1: Real GPU Enumeration with DXGI Identity
// =============================================================================

struct GPUDeviceIdentity {
    uint32_t deviceId;              // Fabric device ID
    wchar_t name[256];              // DXGI adapter name
    std::string pciBusPath;         // PCI bus/device/function path
    LUID adapterLuid;               // DXGI adapter LUID
    uint32_t vendorId;              // PCI vendor ID
    uint32_t deviceId_pci;          // PCI device ID
    uint32_t revision;              // PCI revision
    
    // Memory
    uint64_t dedicatedVRAM;       // From DXGI
    uint64_t sharedSystemMemory;    // From DXGI
    uint64_t budget;                // QueryVideoMemoryInfo
    uint64_t currentUsage;          // QueryVideoMemoryInfo
    uint64_t availableForReservation;
    
    // Topology
    uint32_t nodeCount;             // Multi-GPU node count
    uint32_t nodeMask;              // Node affinity mask
};

// =============================================================================
// F2: Real Topology Graph with PCI Link Info
// =============================================================================

enum class LinkType : uint8_t {
    UNKNOWN = 0,
    PCIE_GEN3 = 3,      // PCIe Gen3
    PCIE_GEN4 = 4,      // PCIe Gen4
    PCIE_GEN5 = 5,      // PCIe Gen5
    INFINITY_FABRIC = 10, // AMD Infinity Fabric
    NVLINK = 11,         // NVIDIA NVLink
    CXL = 12,            // CXL.mem
    NETWORK = 20         // Remote fabric
};

struct TopologyLink {
    uint32_t srcNode;
    uint32_t dstNode;
    LinkType linkType;
    uint32_t linkWidth;         // x1, x4, x8, x16
    uint32_t linkSpeed;         // GT/s
    uint64_t theoreticalBandwidth; // Bytes/sec
    uint64_t measuredBandwidth;    // From benchmark
    uint32_t latencyNs;            // Measured latency
    bool isSymmetric;                // Same bandwidth both directions
};

struct FabricTopology {
    std::vector<GPUDeviceIdentity> nodes;
    std::vector<TopologyLink> links;
    std::unordered_map<uint64_t, size_t> linkIndex; // (src << 32 | dst) -> index
    
    bool SaveToJson(const std::string& filename) const;
    bool LoadFromJson(const std::string& filename);
};

// =============================================================================
// F3: Peer Path Validation with Actual Bandwidth Measurement
// =============================================================================

struct BandwidthBenchmarkResult {
    uint32_t srcNode;
    uint32_t dstNode;
    size_t transferSize;
    uint64_t elapsedNs;
    double bandwidthGBps;
    double latencyUs;
    bool isP2P;
};

class BandwidthValidator {
public:
    bool Initialize(ID3D12Device* device);
    void Shutdown();
    
    // Measure actual copy bandwidth
    BandwidthBenchmarkResult MeasureP2P(uint32_t srcNode, uint32_t dstNode, 
                                         size_t size, ID3D12Resource* srcRes,
                                         ID3D12Resource* dstRes);
    
    // Measure via staging buffer (bridge path)
    BandwidthBenchmarkResult MeasureBridge(uint32_t srcNode, uint32_t dstNode,
                                            size_t size);
    
    // Run full benchmark suite
    std::vector<BandwidthBenchmarkResult> BenchmarkAllPaths(
        const std::vector<uint32_t>& nodes, size_t testSize);

private:
    ID3D12Device* device_;
    ID3D12CommandQueue* copyQueue_;
    ID3D12Fence* fence_;
    uint64_t fenceValue_;
    HANDLE fenceEvent_;
    
    uint64_t GetTimestamp();
    double CalculateBandwidth(size_t bytes, uint64_t ns);
};

// =============================================================================
// F4: Tensor Placement with Shard Residency Map
// =============================================================================

enum class ResidencyLocation : uint8_t {
    GPU_VRAM = 0,
    CPU_RAM = 1,
    NVMe_STORAGE = 2,
    REMOTE_NODE = 3,
    MIGRATING = 4
};

struct TensorShard {
    uint64_t tensorId;
    uint64_t shardId;
    size_t offset;
    size_t size;
    ResidencyLocation location;
    uint32_t nodeId;
    uint64_t physicalHandle;
    uint64_t lastAccessTick;
    uint32_t accessCount;
};

struct ResidencyMap {
    uint64_t tensorId;
    size_t totalSize;
    std::vector<TensorShard> shards;
    
    // Placement metadata
    uint32_t homeNode;          // Preferred location
    float hotnessScore;         // Access frequency
    bool isReplicated;          // Exists on multiple nodes
    std::vector<uint32_t> replicaNodes;
};

class ShardResidencyManager {
public:
    bool Initialize();
    void Shutdown();
    
    // Register tensor with initial placement
    uint64_t RegisterTensor(size_t size, uint32_t preferredNode);
    
    // Get current residency map
    ResidencyMap GetResidencyMap(uint64_t tensorId);
    
    // Split tensor into shards across nodes
    bool DistributeShards(uint64_t tensorId, const std::vector<uint32_t>& nodes,
                          const std::vector<float>& weights);
    
    // Migrate shard
    bool MigrateShard(uint64_t shardId, uint32_t targetNode);
    
    // Update access tracking
    void RecordAccess(uint64_t shardId);
    
    // Save residency map to JSON
    bool SaveResidencyMap(uint64_t tensorId, const std::string& filename);

private:
    std::unordered_map<uint64_t, ResidencyMap> residencyMaps_;
    std::unordered_map<uint64_t, TensorShard> shards_;
    std::atomic<uint64_t> nextTensorId_{1};
    std::atomic<uint64_t> nextShardId_{1};
    std::mutex mutex_;
};

// =============================================================================
// F5: Federated Inference with Tokens/sec Measurement
// =============================================================================

struct FederatedInferenceResult {
    uint64_t tokensGenerated;
    uint64_t elapsedNs;
    double tokensPerSecond;
    double latencyPerTokenMs;
    
    // Per-node contribution
    std::vector<std::pair<uint32_t, uint64_t>> tokensPerNode;
    
    // Migration overhead
    uint64_t migrationCount;
    uint64_t migrationNs;
    double migrationOverheadPercent;
};

class FederatedInferenceEngine {
public:
    bool Initialize(FabricTopology* topology);
    void Shutdown();
    
    // Run inference across federated nodes
    FederatedInferenceResult RunInference(
        const std::vector<uint64_t>& tensorIds,
        uint64_t maxTokens,
        const std::vector<uint32_t>& activeNodes);
    
    // Measure tokens/sec for single node
    double BenchmarkNodeTPS(uint32_t nodeId, size_t modelSize);
    
    // Get performance projection
    double ProjectFederatedTPS(const std::vector<uint32_t>& nodes);

private:
    FabricTopology* topology_;
    std::unordered_map<uint32_t, double> nodeTPSCache_;
};

// =============================================================================
// F6: Migration Economics with Cost Model
// =============================================================================

struct MigrationCost {
    uint32_t srcNode;
    uint32_t dstNode;
    size_t bytes;
    
    // Cost components (normalized 0-1)
    double bandwidthCost;         // Time to transfer
    double latencyCost;         // Synchronization overhead
    double thermalCost;         // Power/heat impact
    double computeCost;         // Lost compute during migration
    double residencyPenalty;      // Cache invalidation
    
    // Total cost (weighted sum)
    double totalCost;
    uint64_t estimatedNs;
};

class MigrationEconomicsEngine {
public:
    struct CostWeights {
        double bandwidth = 0.30;
        double latency = 0.25;
        double thermal = 0.15;
        double compute = 0.20;
        double residency = 0.10;
    };
    
    bool Initialize(FabricTopology* topology);
    void Shutdown();
    
    // Calculate migration cost
    MigrationCost CalculateCost(uint32_t srcNode, uint32_t dstNode, size_t bytes);
    
    // Compare predicted vs actual
    struct CostValidation {
        MigrationCost predicted;
        uint64_t actualNs;
        double errorPercent;
    };
    CostValidation ValidatePrediction(uint32_t srcNode, uint32_t dstNode, 
                                       size_t bytes, uint64_t actualNs);
    
    // Update weights based on observed behavior
    void UpdateWeights(const CostValidation& validation);
    
    // Should we migrate? (cost-benefit analysis)
    bool ShouldMigrate(uint32_t srcNode, uint32_t dstNode, size_t bytes,
                       double expectedComputeGain);
    
    // Set custom weights
    void SetWeights(const CostWeights& weights) { weights_ = weights; }

private:
    FabricTopology* topology_;
    CostWeights weights_;
    std::vector<CostValidation> validationHistory_;
};

// =============================================================================
// Cost-Model Scheduler (Evolved from memory-only to multi-factor)
// =============================================================================

class CostModelScheduler {
public:
    struct PlacementScore {
        uint32_t nodeId;
        double memoryHeadroomCost;
        double bandwidthCost;
        double migrationCost;
        double thermalCost;
        double computeCost;
        double residencyPenalty;
        double totalScore;
    };
    
    bool Initialize(FabricTopology* topology, 
                    MigrationEconomicsEngine* economics,
                    ShardResidencyManager* residency);
    void Shutdown();
    
    // Score a placement option
    PlacementScore ScorePlacement(uint64_t tensorId, uint32_t nodeId);
    
    // Select optimal node
    uint32_t SelectOptimalNode(uint64_t tensorId, 
                               const std::vector<uint32_t>& candidates);
    
    // Generate placement decision trace
    struct PlacementDecision {
        uint64_t timestamp;
        uint64_t tensorId;
        uint32_t selectedNode;
        PlacementScore selectedScore;
        std::vector<PlacementScore> allScores;
        std::string reasoning;
    };
    PlacementDecision MakePlacementDecision(uint64_t tensorId);
    
    // Save decision history
    bool SaveDecisionLog(const std::string& filename);

private:
    FabricTopology* topology_;
    MigrationEconomicsEngine* economics_;
    ShardResidencyManager* residency_;
    std::vector<PlacementDecision> decisionHistory_;
    std::mutex mutex_;
};

// =============================================================================
// Fabric Topology Report Generator
// =============================================================================

class TopologyReportGenerator {
public:
    bool GenerateReport(const FabricTopology& topology,
                        const std::string& filename);
    
    bool GenerateFullReport(const FabricTopology& topology,
                            const std::vector<BandwidthBenchmarkResult>& benchmarks,
                            const std::string& filename);

private:
    Json::Value NodeToJson(const GPUDeviceIdentity& node);
    Json::Value LinkToJson(const TopologyLink& link);
    Json::Value BenchmarkToJson(const BandwidthBenchmarkResult& result);
};

// =============================================================================
// Main Fabric Controller (Phase 7B.2 Validated)
// =============================================================================

class FabricController {
public:
    static FabricController& Instance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    
    // F1: Enumeration
    std::vector<GPUDeviceIdentity> EnumerateGPUs();
    
    // F2: Topology
    FabricTopology* GetTopology() { return &topology_; }
    bool DiscoverTopology();
    
    // F3: Validation
    bool ValidatePeerPaths();
    std::vector<BandwidthBenchmarkResult> GetBenchmarkResults() { return benchmarks_; }
    
    // F4: Placement
    ShardResidencyManager* GetResidencyManager() { return residencyManager_.get(); }
    
    // F5: Inference
    FederatedInferenceEngine* GetInferenceEngine() { return inferenceEngine_.get(); }
    
    // F6: Economics
    MigrationEconomicsEngine* GetEconomicsEngine() { return economicsEngine_.get(); }
    CostModelScheduler* GetScheduler() { return scheduler_.get(); }
    
    // Reporting
    bool GenerateTopologyReport(const std::string& filename);
    bool GenerateCostModelReport(const std::string& filename);

private:
    FabricController() = default;
    ~FabricController() = default;
    
    bool initialized_ = false;
    FabricTopology topology_;
    std::vector<BandwidthBenchmarkResult> benchmarks_;
    
    std::unique_ptr<BandwidthValidator> bandwidthValidator_;
    std::unique_ptr<ShardResidencyManager> residencyManager_;
    std::unique_ptr<FederatedInferenceEngine> inferenceEngine_;
    std::unique_ptr<MigrationEconomicsEngine> economicsEngine_;
    std::unique_ptr<CostModelScheduler> scheduler_;
};

// =============================================================================
// C API
// =============================================================================

extern "C" {
    __declspec(dllexport) bool RawRamXD_Topology_Initialize();
    __declspec(dllexport) void RawRamXD_Topology_Shutdown();
    
    // F1: Enumeration
    __declspec(dllexport) uint32_t RawRamXD_EnumerateGPUs();
    __declspec(dllexport) bool RawRamXD_GetGPUInfo(uint32_t index, 
                                                     wchar_t* name, size_t nameLen,
                                                     uint64_t* vramBytes,
                                                     char* pciPath, size_t pciPathLen);
    
    // F2: Topology
    __declspec(dllexport) bool RawRamXD_DiscoverTopology();
    __declspec(dllexport) bool RawRamXD_SaveTopology(const char* filename);
    
    // F3: Validation
    __declspec(dllexport) bool RawRamXD_ValidatePeerPaths();
    __declspec(dllexport) double RawRamXD_GetMeasuredBandwidth(uint32_t src, uint32_t dst);
    
    // F4: Placement
    __declspec(dllexport) uint64_t RawRamXD_RegisterTensor(size_t size, uint32_t preferredNode);
    __declspec(dllexport) bool RawRamXD_SaveResidencyMap(uint64_t tensorId, const char* filename);
    
    // F5: Inference
    __declspec(dllexport) double RawRamXD_BenchmarkNodeTPS(uint32_t nodeId);
    
    // F6: Economics
    __declspec(dllexport) double RawRamXD_CalculateMigrationCost(uint32_t src, uint32_t dst, size_t bytes);
    __declspec(dllexport) bool RawRamXD_ShouldMigrate(uint32_t src, uint32_t dst, size_t bytes, double gain);
}

} // namespace RawRamXD

#endif // RAWRAMXD_PHASE7B2_TOPOLOGY_VALIDATED_HPP