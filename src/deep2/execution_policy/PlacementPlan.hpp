// ============================================================================
// PlacementPlan.hpp — derived residency plan from ExecutionPolicy
// policy parsed ≠ plan derived ≠ plan applied ≠ observed match
// ============================================================================
#pragma once

#include "ExecutionPolicy.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace Deep2 {
namespace Exec {

struct PlannedTensor {
    std::string name;
    int layer = -1;
    TensorClass cls = TensorClass::Scratch;
    DeviceKind device = DeviceKind::Host;
    uint64_t bytes = 0;
    bool pinned = false;
};

struct PlacementPlan {
    uint64_t policyVersion = 0;
    std::string policySha;
    UiMode mode = UiMode::Guided;

    uint64_t vramCapBytes = 0;
    uint64_t ramCapBytes = 0;
    uint64_t gpu0Budget = 0;
    uint64_t gpu1Budget = 0;

    bool streamingEnabled = false;
    uint64_t streamChunkBytes = 0;
    int streamPrefetchDepth = 0;
    int streamBuffers = 0;

    KVPlacement kvPlacement = KVPlacement::Hybrid;
    uint64_t kvGpuBudget = 0;
    int kvContext = 0;

    // Layer → device (resolved ranges collapsed)
    std::vector<DeviceKind> layerDevice; // size = nLayers
    std::vector<PlannedTensor> tensors;

    bool derived = false;
    std::string detail;
};

struct ObservedPlacement {
    std::string name;
    int observedGpu = -1; // -1 host/stream, 0/1 GPU
    DeviceKind planned = DeviceKind::Host;
    bool match = false;
    uint64_t bytes = 0;
};

struct PlacementApplyReport {
    bool policyLoaded = false;
    bool effectiveVisible = false;
    bool planDerived = false;
    bool gpuLayerCountsApplied = false;
    bool vramCapsApplied = false;
    bool ramCapApplied = false;
    bool streamPolicyApplied = false;
    bool kvPolicyApplied = false;
    bool lockedOverridesPreserved = false;
    bool overBudgetFailClosed = false; // true if invalid budget correctly rejected
    bool modelReady = false;
    bool observedMatchesPlan = false;

    size_t plannedTensors = 0;
    size_t observedTensors = 0;
    size_t mismatches = 0;
    size_t gpu0Layers = 0;
    size_t gpu1Layers = 0;
    size_t streamLayers = 0;
    size_t hostLayers = 0;

    std::string policySha;
    uint64_t policyVersion = 0;
    std::string detail;
    std::vector<ObservedPlacement> observations;
};

TensorClass ClassifyTensorName(const std::string& name);
int DeviceKindToGpuIndex(DeviceKind d); // 0,1, or -1 for host/stream/disk/hybrid→host fallback marker

PlacementPlan DerivePlacementPlan(const ExecutionPolicy& policy, int nLayers);

// Fill only AutoDetect/AutoPlanner authority cells (respect locks).
void RunAutoPlanner(ExecutionPolicy& policy, int nLayers,
                    uint64_t detectedVram0, uint64_t detectedVram1,
                    uint64_t detectedRam);

// Bind model path/fingerprint into session (does not replace Bridge EnsurePolicyLoaded).
void BindModelToPolicy(const std::string& modelPath,
                       const std::string& modelFingerprint = {});

} // namespace Exec
} // namespace Deep2
