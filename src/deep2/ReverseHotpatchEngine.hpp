// ============================================================================
// ReverseHotpatchEngine.hpp - Staged Reverse GGUF Repair & Hotpatch Pipeline
// ============================================================================
// Pipeline stages (each with single responsibility):
//   1. ReverseHop_Discover   - Scan files, detect corruption/truncation
//   2. ReverseUnlayer_Parse  - Parse headers, metadata, tensor descriptors
//   3. ReverseUnlayer_Index  - Build reverse tensor index (offset→tensor map)
//   4. ReverseCompute_Graph  - Compute missing offsets, block sizes, alignments
//   5. ReverseHotpatch_Next  - Generate hotpatch plan, apply patches
//   6. ReverseHop_Verify     - Verify tensor bounds, checksums
//   7. ReverseHop_Commit     - Commit corrected view to loader
//
// For mixed-quant models (Q2_K/Q3_K/Q5_K/Q6_K), the forward size calculator
// often undercounts block overhead. This engine reconstructs the true tensor
// extents from the file footer/index rather than trusting header claims.
// ============================================================================

#pragma once

#include "PipelineState.hpp"
#include "DualGPUHook.hpp"
#include "ReverseTensorRecovery.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <span>
#include <functional>
#include <filesystem>

namespace Deep2 {

// Forward declarations
struct TensorInfo;
struct GGUFLoadResult;

// ============================================================================
// Stage result — each stage returns this so the pipeline can retry per-stage
// ============================================================================
struct ReverseStageResult {
    bool   success = false;
    int    stageIndex = 0;          // 1..7
    std::string stageName;
    std::string error;
    size_t itemsProcessed = 0;
    size_t itemsRepaired = 0;

    bool ok() const { return success; }
};

// ============================================================================
// Tensor repair record — produced by ReverseHotpatch_Next, consumed by Commit
// ============================================================================
struct TensorRepair {
    std::string name;
    uint64_t    oldOffset = 0;
    uint64_t    newOffset = 0;
    uint64_t    oldSize   = 0;
    uint64_t    newSize   = 0;
    uint32_t    ggmlType  = 0;
    bool        wasRepaired = false;
    std::string repairReason;
};

// ============================================================================
// Corruption detection record
// ============================================================================
struct TensorCorruption {
    std::string name;
    uint64_t    claimedOffset = 0;
    uint64_t    claimedSize   = 0;
    uint64_t    fileSize      = 0;
    std::string description;
};

// ============================================================================
// ReverseHotpatchEngine — staged pipeline
// ============================================================================
class ReverseHotpatchEngine {
public:
    ReverseHotpatchEngine();
    ~ReverseHotpatchEngine();

    // ------------------------------------------------------------------------
    // Main entry: process one or more GGUF files
    // ------------------------------------------------------------------------
    bool ProcessFiles(const std::vector<std::filesystem::path>& files);

    // ------------------------------------------------------------------------
    // Per-stage accessors (for inspection, logging, retry)
    // ------------------------------------------------------------------------
    const std::vector<TensorRepair>&   GetRepairs()   const;
    const std::vector<TensorCorruption>& GetCorruptions() const;
    const std::vector<std::string>&    GetDiscoveredFiles() const;

    // ------------------------------------------------------------------------
    // Apply repairs to an existing GGUFLoadResult (mutates offsets/sizes)
    // Returns number of tensors patched.
    // ------------------------------------------------------------------------
    size_t ApplyRepairs(GGUFLoadResult& result) const;

    // ------------------------------------------------------------------------
    // Stage retry — re-run a single stage without re-running the whole pipeline
    // ------------------------------------------------------------------------
    bool RetryStage(int stageIndex);

    // ------------------------------------------------------------------------
    // Progress callback: (stageName, current, total) -> bool continue?
    // ------------------------------------------------------------------------
    using ProgressCallback = std::function<bool(const std::string&, size_t, size_t)>;
    void SetProgressCallback(ProgressCallback cb);

    // ------------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------------
    void SetVerbose(bool v);
    void SetAlignment(uint32_t alignment);   // default 64
    void SetAllowTruncationRepair(bool allow); // repair truncated tensors?

    // ------------------------------------------------------------------------
    // Dual GPU / Reverse Recovery Integration
    // ------------------------------------------------------------------------
    void SetDualGPUHook(DualGPUHook* hook);
    void SetTensorBackend(ReverseTensorBackend* backend);

    // ------------------------------------------------------------------------
    // Fallback-safe reverse execution pipeline
    //   Normal pipeline bypassed when not applicable → re-enters through GPU
    //   backend recovery path.
    // ------------------------------------------------------------------------
    PipelineState RunReverseGPUPath(
        const std::vector<std::filesystem::path>& files,
        bool gpuAvailable,
        bool cpuFallback);

    ReverseGPUPath GetReverseGPUPath() const;

    // ------------------------------------------------------------------------
    // Model load with automatic reverse fallback
    // ------------------------------------------------------------------------
    LoadResult LoadModelWithFallback(
        const std::string& path,
        bool gpuAvailable,
        bool cpuFallback);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;

    // ------------------------------------------------------------------------
    // Seven stages — each has a single responsibility
    // ------------------------------------------------------------------------
    bool ReverseHopDiscover();      // Stage 1: scan files, detect issues
    bool ReverseUnlayerParse();       // Stage 2: parse headers & metadata
    bool ReverseUnlayerIndex();     // Stage 3: build reverse tensor index
    bool ReverseComputeGraph();     // Stage 4: compute offsets, sizes, alignments
    bool ReverseHotpatchNext();     // Stage 5: generate & apply hotpatch plan
    bool ReverseHopVerify();        // Stage 6: verify tensors post-patch
    bool ReverseHopCommit();        // Stage 7: commit corrected view
};

// ============================================================================
// Free helpers — block-size computation for mixed-quant GGUF repair
// ============================================================================

uint64_t ComputeBlockSizeGGML(uint32_t type);
uint64_t ComputeTensorBytesGGML(uint32_t type, const std::vector<uint64_t>& dims);
uint64_t ComputeAlignmentGGML(uint64_t offset, uint32_t alignment);
bool     ComputeTensorBoundsGGML(uint64_t tensorOffset, uint64_t tensorBytes, uint64_t fileSize);

// Mixed-quant block-size table (Q2_K … Q6_K)
uint64_t unBlockGGUFSize(uint32_t type, uint64_t elements);

} // namespace Deep2
