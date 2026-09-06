// ============================================================================
// ExecutionPolicy.hpp — user-owned model execution contract
// Placement + budgets + streaming + KV + compute + reuse + scheduling
// ============================================================================
#pragma once

#include "Tunable.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace Deep2 {
namespace Exec {

enum class DeviceKind : int8_t {
    Host = -1,
    Gpu0 = 0,
    Gpu1 = 1,
    Stream = 2,
    Hybrid = 3,
    Disk = 4
};

enum class TensorClass : uint8_t {
    Attention = 0,
    FFN,
    Embeddings,
    LmHead,
    Norms,
    KvCache,
    Rope,
    Activations,
    Scratch
};

enum class WeightPolicy : uint8_t { Gpu, Cpu, Hybrid, Stream };
enum class KVPlacement : uint8_t { GPU, GPUPaged, RAM, Hybrid, DiskPaged };
enum class PrefetchPolicy : uint8_t {
    Off, Sequential, DependencyAware, Predictive, Aggressive
};
enum class StreamGranularity : uint8_t {
    WholeModel, WholeLayer, WholeTensor, TensorSlice, FixedBytes, RowGroups
};
enum class EvictionPolicyKind : uint8_t {
    LRU, NextUse, CostAware, DependencyAware, UserPinned
};
enum class OptimizationTarget : uint8_t {
    LowestMemory, HighestTPS, LowestLatency, LowestPower, Balanced
};
enum class ReuseMode : uint8_t { Disabled, ExactOnly, CertifiedReuse };
enum class CapKind : uint8_t { Soft, Hard };

struct LayerRange {
    int first = 0;
    int last = -1; // inclusive; -1 = open end
};

struct PlacementRule {
    std::string pattern; // e.g. "blk.0-7.*", "blk.*.ffn_*.weight", "token_embd.weight"
    DeviceKind device = DeviceKind::Host;
    SettingAuthority authority = SettingAuthority::UserOverride;
};

struct VramPartition {
    Tunable<Bytes> weights;
    Tunable<Bytes> kv;
    Tunable<Bytes> activations;
    Tunable<Bytes> streaming;
    Tunable<Bytes> scratch;
    Tunable<Bytes> reserve;

    uint64_t sum() const {
        auto g = [](const Tunable<Bytes>& t) { return t.present ? t.value.n : 0ULL; };
        return g(weights) + g(kv) + g(activations) + g(streaming) + g(scratch) + g(reserve);
    }
};

struct GpuSlot {
    int index = 0;
    Tunable<Bytes> budget;
    VramPartition partition;
    Tunable<bool> permanentResidency; // else streaming-friendly
};

struct RamPolicy {
    Tunable<Bytes> hardCap;
    Tunable<Bytes> softCap;
    Tunable<Bytes> maxMapped;
    Tunable<Bytes> weightCache;
    Tunable<Bytes> kvSpill;
    Tunable<Bytes> staging;
    Tunable<bool> hugePages;
    Tunable<bool> lockPages;
    Tunable<int> numaNode;
};

struct StreamingPolicy {
    Tunable<bool> enabled;
    Tunable<Bytes> chunkSize;
    Tunable<int> prefetchDepth;
    Tunable<int> queueDepth;
    Tunable<int> buffers;
    Tunable<bool> directIo;
    Tunable<PrefetchPolicy> prefetch;
    Tunable<StreamGranularity> granularity;
};

struct KVPolicy {
    Tunable<KVPlacement> placement;
    Tunable<Bytes> gpuBudget;
    Tunable<Bytes> ramBudget;
    Tunable<std::string> quant; // "q8","fp16",...
    Tunable<Bytes> pageSize;
    Tunable<int> context;
    Tunable<bool> slidingWindow;
};

struct ComputePolicy {
    Tunable<DeviceKind> attention;
    Tunable<DeviceKind> ffn;
    Tunable<DeviceKind> sampling;
    Tunable<DeviceKind> tokenizer;
    Tunable<DeviceKind> lmHead;
};

struct ReusePolicy {
    Tunable<bool> enabled;
    Tunable<ReuseMode> mode;
    Tunable<bool> persistentCache;
    Tunable<bool> failClosed;
};

struct SchedulerPolicy {
    Tunable<OptimizationTarget> objective;
    Tunable<EvictionPolicyKind> eviction;
    Tunable<bool> autoTune;          // full auto
    Tunable<bool> respectOverrides;  // AUTO — RESPECT OVERRIDES
};

struct HotpatchPolicy {
    Tunable<bool> enabled;
    Tunable<bool> adaptive;
    Tunable<bool> persistLearnedPlan;
};

// Latency is the INPUT constraint; speedup is derived (see LatencyIntent.hpp).
struct LatencyPolicyInline {
    Tunable<double> targetDecodeMs;
    Tunable<double> targetTtftMs;
    Tunable<double> targetE2eMs;
    Tunable<bool> autoTarget;
    Tunable<double> maxRiskBudget;
};

struct SpeedupPolicyInline {
    Tunable<double> targetRealSpeedup;
    Tunable<bool> autoTarget;
    Tunable<double> minimumAcceptedGain;
    Tunable<double> maxRiskBudget;
};

struct PlacementPolicy {
    Tunable<DeviceKind> embeddings;
    Tunable<DeviceKind> lmHead;
    Tunable<DeviceKind> norms;
    Tunable<DeviceKind> attentionClass;
    Tunable<DeviceKind> ffnClass;
    Tunable<WeightPolicy> weightPolicy;
    std::vector<std::pair<LayerRange, DeviceKind>> layerRanges;
    std::vector<PlacementRule> rules; // tensor / glob overrides (highest precedence)
    std::vector<std::string> pinned;  // NEVER EVICT patterns
};

struct MemoryPolicy {
    Tunable<Bytes> vramBudget;
    Tunable<CapKind> vramCapKind;
    Tunable<Bytes> ramBudget;
    Tunable<CapKind> ramCapKind;
    Tunable<Bytes> diskCacheBudget;
    VramPartition vramParts;
    std::vector<GpuSlot> gpus;
    RamPolicy ram;
};

struct ExecutionPolicy {
    uint64_t version = 1;
    UiMode mode = UiMode::Guided;
    Tunable<bool> persistRuntimeChanges;
    Tunable<std::string> modelPath;
    Tunable<std::string> modelFingerprint; // sha256:...
    Tunable<int> context;
    Tunable<int> batchSize;
    Tunable<int> microbatch;

    MemoryPolicy memory;
    PlacementPolicy placement;
    StreamingPolicy streaming;
    KVPolicy kv;
    ComputePolicy compute;
    ReusePolicy reuse;
    SchedulerPolicy scheduler;
    HotpatchPolicy hotpatch;
    LatencyPolicyInline latency;
    SpeedupPolicyInline speedup;

    // Resolve placement for a tensor name (precedence: tensor > layer > class > global).
    DeviceKind resolvePlacement(const std::string& tensorName, int layer,
                                TensorClass cls) const;
};

struct PolicyValidation {
    bool ok = false;
    std::string detail;
};

PolicyValidation Validate(const ExecutionPolicy& p);
std::string PolicySha256(const ExecutionPolicy& p); // stable digest of effective values

// Defaults suitable for guided mode on a dual-GPU desktop.
ExecutionPolicy MakeDefaultPolicy();

} // namespace Exec
} // namespace Deep2
