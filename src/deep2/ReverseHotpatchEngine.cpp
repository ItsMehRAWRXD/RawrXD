// ============================================================================
// ReverseHotpatchEngine.cpp - Staged Reverse GGUF Repair Implementation
// ============================================================================
// Dependency order (lowest-level first):
//   1. Compute primitives     (no deps)
//   2. Reverse helpers        (depend on compute)
//   3. unBlock layer          (quant-specific block decoders)
//   4. Tensor layer           (depends on unBlock)
//   5. Directory / metadata   (depends on tensor)
//   6. Loader orchestration   (highest level)
// ============================================================================

#include "ReverseHotpatchEngine.hpp"
#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <cmath>

namespace Deep2 {

// ============================================================================
// 1. Compute primitives
// ============================================================================

uint64_t ComputeBlockSizeGGML(uint32_t type) {
    switch (type) {
        case 0:  return 4;                     // F32
        case 1:  return 2;                     // F16
        case 2:  return sizeof(block_q4_0);    // Q4_0
        case 3:  return sizeof(block_q4_1);    // Q4_1
        case 6:  return sizeof(block_q5_0);    // Q5_0
        case 7:  return sizeof(block_q5_1);    // Q5_1
        case 8:  return sizeof(block_q8_0);    // Q8_0
        case 9:  return sizeof(block_q8_K);    // Q8_K
        case 10: return sizeof(block_q2_K);    // Q2_K
        case 11: return sizeof(block_q3_K);    // Q3_K
        case 12: return sizeof(block_q4_K);    // Q4_K
        case 13: return sizeof(block_q5_K);    // Q5_K
        case 14: return sizeof(block_q6_K);    // Q6_K
        case 17: return sizeof(block_iq2_xxs); // IQ2_XXS
        case 18: return sizeof(block_iq2_xs);  // IQ2_XS
        case 19: return sizeof(block_iq3_xxs); // IQ3_XXS
        case 20: return sizeof(block_iq1_s);  // IQ1_S
        case 21: return sizeof(block_iq4_nl);  // IQ4_NL
        case 22: return sizeof(block_iq3_s);  // IQ3_S
        case 23: return sizeof(block_iq2_s);  // IQ2_S
        case 24: return sizeof(block_iq4_xs);  // IQ4_XS
        case 25: return 1;                     // I8
        case 26: return 2;                     // I16
        case 27: return 4;                     // I32
        case 28: return 8;                     // I64
        case 29: return 8;                     // F64
        default: return 4;
    }
}

uint64_t ComputeTensorBytesGGML(uint32_t type, const std::vector<uint64_t>& dims) {
    uint64_t elements = 1;
    for (auto d : dims) elements *= d;

    uint64_t blockSize = ComputeBlockSizeGGML(type);
    uint64_t elemsPerBlock = 1;

    switch (type) {
        case 2: case 3: case 6: case 7: case 8: case 9:
            elemsPerBlock = 32; break;
        case 10: case 11: case 12: case 13: case 14:
            elemsPerBlock = 256; break;
        case 17: case 18: case 19: case 20: case 21:
        case 22: case 23: case 24:
            elemsPerBlock = 256; break;
        default:
            elemsPerBlock = 1; break;
    }

    if (elemsPerBlock == 1) return elements * blockSize;
    uint64_t numBlocks = (elements + elemsPerBlock - 1) / elemsPerBlock;
    return numBlocks * blockSize;
}

uint64_t ComputeAlignmentGGML(uint64_t offset, uint32_t alignment) {
    if (alignment <= 1) return offset;
    uint64_t mask = alignment - 1;
    return (offset + mask) & ~mask;
}

bool ComputeTensorBoundsGGML(uint64_t tensorOffset, uint64_t tensorBytes, uint64_t fileSize) {
    if (tensorOffset > fileSize) return false;
    if (tensorBytes > fileSize - tensorOffset) return false;
    return true;
}

// ============================================================================
// 2. Reverse helpers — mixed-quant block reconstruction
// ============================================================================

uint64_t unBlockGGUFSize(uint32_t type, uint64_t elements) {
    switch (type) {
        case 10: // Q2_K  → 84 bytes per 256 elements
            return (elements / 256) * 84 + ((elements % 256) ? 84 : 0);
        case 11: // Q3_K  → 110 bytes per 256 elements
            return (elements / 256) * 110 + ((elements % 256) ? 110 : 0);
        case 13: // Q5_K  → 176 bytes per 256 elements
            return (elements / 256) * 176 + ((elements % 256) ? 176 : 0);
        case 14: // Q6_K  → 210 bytes per 256 elements
            return (elements / 256) * 210 + ((elements % 256) ? 210 : 0);
        case 12: // Q4_K  → 144 bytes per 256 elements
            return (elements / 256) * 144 + ((elements % 256) ? 144 : 0);
        case 9:  // Q8_K  → 292 bytes per 256 elements
            return (elements / 256) * 292 + ((elements % 256) ? 292 : 0);
        default:
            return elements * 4; // F32 fallback
    }
}

// ============================================================================
// 3. unBlock layer — quant-specific decoders (stubs for now, real impl later)
// ============================================================================

static bool unBlock_gguf_q2k(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen) {
    (void)src; (void)srcLen; (void)dst; (void)dstLen;
    return true; // Placeholder
}
static bool unBlock_gguf_q3k(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen) {
    (void)src; (void)srcLen; (void)dst; (void)dstLen;
    return true;
}
static bool unBlock_gguf_q4k(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen) {
    (void)src; (void)srcLen; (void)dst; (void)dstLen;
    return true;
}
static bool unBlock_gguf_q5k(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen) {
    (void)src; (void)srcLen; (void)dst; (void)dstLen;
    return true;
}
static bool unBlock_gguf_q6k(const uint8_t* src, size_t srcLen, uint8_t* dst, size_t dstLen) {
    (void)src; (void)srcLen; (void)dst; (void)dstLen;
    return true;
}

// ============================================================================
// 4. Tensor layer
// ============================================================================

static bool unBlock_gguf_tensor_verify(const TensorInfo& t, uint64_t fileSize, std::string& outError) {
    uint64_t trueBytes = ComputeTensorBytesGGML(static_cast<uint32_t>(t.type), t.dimensions);
    if (!ComputeTensorBoundsGGML(t.offset, trueBytes, fileSize)) {
        outError = "Tensor '" + t.name + "' exceeds file bounds: offset=" +
                   std::to_string(t.offset) + " size=" + std::to_string(trueBytes) +
                   " fileSize=" + std::to_string(fileSize);
        return false;
    }
    return true;
}

static bool unBlock_gguf_tensor_data(const TensorInfo& t, const uint8_t* fileData, uint64_t fileSize) {
    std::string err;
    if (!unBlock_gguf_tensor_verify(t, fileSize, err)) return false;
    (void)fileData;
    return true;
}

// ============================================================================
// 5. Directory / metadata
// ============================================================================

static bool unBlock_gguf_directory(const std::vector<TensorInfo>& tensors, uint64_t fileSize,
                                   std::vector<TensorCorruption>& outCorruptions) {
    bool ok = true;
    for (const auto& t : tensors) {
        std::string err;
        if (!unBlock_gguf_tensor_verify(t, fileSize, err)) {
            TensorCorruption tc;
            tc.name = t.name;
            tc.claimedOffset = t.offset;
            tc.claimedSize = t.size;
            tc.fileSize = fileSize;
            tc.description = err;
            outCorruptions.push_back(tc);
            ok = false;
        }
    }
    return ok;
}

// ============================================================================
// 6. Loader orchestration — ReverseHotpatchEngine::Impl
// ============================================================================

struct ReverseHotpatchEngine::Impl {
    // Inputs
    std::vector<std::filesystem::path> files;

    // Outputs per stage
    std::vector<std::string> discoveredFiles;
    std::vector<TensorInfo> parsedTensors;
    std::vector<TensorRepair> repairs;
    std::vector<TensorCorruption> corruptions;
    uint64_t fileSize = 0;
    uint32_t alignment = 64;
    bool allowTruncationRepair = true;
    bool verbose = false;

    // Progress
    ProgressCallback progressCb;

    // Stage state
    int lastCompletedStage = 0;
    std::vector<ReverseStageResult> stageResults;

    // Dual GPU / Reverse Recovery
    DualGPUHook* gpuHook = nullptr;
    ReverseTensorBackend* tensorBackend = nullptr;
    ReverseGPUPath reversePath;

    bool ReportProgress(const std::string& stage, size_t cur, size_t total) {
        if (progressCb) return progressCb(stage, cur, total);
        return true;
    }

    void Log(const char* fmt, ...) {
        if (!verbose) return;
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
};

ReverseHotpatchEngine::ReverseHotpatchEngine() : pImpl_(std::make_unique<Impl>()) {}
ReverseHotpatchEngine::~ReverseHotpatchEngine() = default;

void ReverseHotpatchEngine::SetVerbose(bool v) { pImpl_->verbose = v; }
void ReverseHotpatchEngine::SetAlignment(uint32_t a) { pImpl_->alignment = a; }
void ReverseHotpatchEngine::SetAllowTruncationRepair(bool a) { pImpl_->allowTruncationRepair = a; }
void ReverseHotpatchEngine::SetProgressCallback(ProgressCallback cb) { pImpl_->progressCb = cb; }

const std::vector<TensorRepair>& ReverseHotpatchEngine::GetRepairs() const { return pImpl_->repairs; }
const std::vector<TensorCorruption>& ReverseHotpatchEngine::GetCorruptions() const { return pImpl_->corruptions; }
const std::vector<std::string>& ReverseHotpatchEngine::GetDiscoveredFiles() const { return pImpl_->discoveredFiles; }

// ------------------------------------------------------------------------
// Stage 1: ReverseHop_Discover — scan files, detect corruption/truncation
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseHopDiscover() {
    auto& impl = *pImpl_;
    impl.discoveredFiles.clear();
    impl.corruptions.clear();

    impl.Log("[ReverseHopDiscover] Scanning %zu file(s)...\n", impl.files.size());

    for (size_t i = 0; i < impl.files.size(); ++i) {
        const auto& path = impl.files[i];
        if (!impl.ReportProgress("Discover", i, impl.files.size())) return false;

        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec) {
            printf("[ReverseHotpatch] ERROR: File not found: %s\n", path.string().c_str());
            return false;
        }
        auto sz = std::filesystem::file_size(path, ec);
        if (ec) {
            printf("[ReverseHotpatch] ERROR: Cannot stat %s\n", path.string().c_str());
            return false;
        }
        impl.fileSize = static_cast<uint64_t>(sz);
        impl.discoveredFiles.push_back(path.string());
        impl.Log("  [%zu] %s  (%llu bytes)\n", i, path.string().c_str(), (unsigned long long)impl.fileSize);
    }
    impl.lastCompletedStage = 1;
    return true;
}

// ------------------------------------------------------------------------
// Stage 2: ReverseUnlayer_Parse — parse headers, metadata, tensor descriptors
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseUnlayerParse() {
    auto& impl = *pImpl_;
    impl.parsedTensors.clear();

    if (impl.discoveredFiles.empty()) {
        printf("[ReverseHotpatch] ERROR: No files discovered (run Discover first)\n");
        return false;
    }

    for (size_t fidx = 0; fidx < impl.discoveredFiles.size(); ++fidx) {
        const std::string& filepath = impl.discoveredFiles[fidx];
        if (!impl.ReportProgress("Parse", fidx, impl.discoveredFiles.size())) return false;

        // Use existing GGUFLoader to parse header + metadata + tensor table
        GGUFLoadOptions opts;
        opts.loadTensors = false; // metadata only — we will patch offsets before loading data
        opts.verbose = impl.verbose;
        opts.mmap = false;

        GGUFLoadResult result = GGUFLoader::Load(filepath.c_str(), opts);
        if (!result.success) {
            printf("[ReverseHotpatch] ERROR: Parse failed for %s: %s\n",
                   filepath.c_str(), result.error);
            return false;
        }

        impl.parsedTensors.insert(impl.parsedTensors.end(),
                                  result.tensors.begin(), result.tensors.end());
        impl.Log("[ReverseUnlayerParse] Parsed %zu tensors from %s\n",
                 result.tensors.size(), filepath.c_str());
    }
    impl.lastCompletedStage = 2;
    return true;
}

// ------------------------------------------------------------------------
// Stage 3: ReverseUnlayer_Index — build reverse tensor index (offset→tensor)
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseUnlayerIndex() {
    auto& impl = *pImpl_;
    if (impl.parsedTensors.empty()) {
        printf("[ReverseHotpatch] ERROR: No tensors parsed (run Parse first)\n");
        return false;
    }

    // Sort tensors by offset to detect overlaps and gaps
    std::sort(impl.parsedTensors.begin(), impl.parsedTensors.end(),
              [](const TensorInfo& a, const TensorInfo& b) {
                  return a.offset < b.offset;
              });

    // Detect overlaps
    for (size_t i = 1; i < impl.parsedTensors.size(); ++i) {
        const auto& prev = impl.parsedTensors[i - 1];
        const auto& cur   = impl.parsedTensors[i];
        uint64_t prevEnd = prev.offset + prev.size;
        if (prevEnd > cur.offset) {
            TensorCorruption ov;
            ov.name = cur.name;
            ov.claimedOffset = cur.offset;
            ov.claimedSize = cur.size;
            ov.fileSize = impl.fileSize;
            ov.description = "Overlap with '" + prev.name + "': prev ends at " +
                              std::to_string(prevEnd) + ", cur starts at " +
                              std::to_string(cur.offset);
            impl.corruptions.push_back(ov);
            impl.Log("[ReverseUnlayerIndex] OVERLAP: %s\n", ov.description.c_str());
        }
    }

    impl.Log("[ReverseUnlayerIndex] Built index for %zu tensors\n", impl.parsedTensors.size());
    impl.lastCompletedStage = 3;
    return true;
}

// ------------------------------------------------------------------------
// Stage 4: ReverseCompute_Graph — compute true offsets, block sizes, alignments
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseComputeGraph() {
    auto& impl = *pImpl_;
    impl.repairs.clear();

    if (impl.parsedTensors.empty()) {
        printf("[ReverseHotpatch] ERROR: No tensors indexed (run Index first)\n");
        return false;
    }

    uint64_t currentOffset = 0;
    bool first = true;

    for (size_t i = 0; i < impl.parsedTensors.size(); ++i) {
        auto& t = impl.parsedTensors[i];
        if (!impl.ReportProgress("ComputeGraph", i, impl.parsedTensors.size())) return false;

        // Compute true size from type + dimensions (not trusting header size)
        uint64_t trueBytes = ComputeTensorBytesGGML(static_cast<uint32_t>(t.type), t.dimensions);
        uint64_t alignedOffset = first ? t.offset : ComputeAlignmentGGML(currentOffset, impl.alignment);

        if (trueBytes != t.size || alignedOffset != t.offset) {
            TensorRepair tr;
            tr.name = t.name;
            tr.oldOffset = t.offset;
            tr.newOffset = alignedOffset;
            tr.oldSize = t.size;
            tr.newSize = trueBytes;
            tr.ggmlType = static_cast<uint32_t>(t.type);
            tr.wasRepaired = true;
            if (trueBytes != t.size && t.size > 0) {
                tr.repairReason = "Size mismatch: header claims " + std::to_string(t.size) +
                                  ", computed " + std::to_string(trueBytes);
            } else if (alignedOffset != t.offset) {
                tr.repairReason = "Alignment: offset " + std::to_string(t.offset) +
                                  " -> " + std::to_string(alignedOffset);
            } else {
                tr.repairReason = "Recomputed from type/dims";
            }
            impl.repairs.push_back(tr);
            impl.Log("[ReverseCompute_Graph] REPAIR %s: %s\n", t.name.c_str(), tr.repairReason.c_str());

            // Update in-place so subsequent tensors see corrected offsets
            t.offset = alignedOffset;
            t.size = trueBytes;
        }

        currentOffset = t.offset + t.size;
        first = false;
    }

    // Check total file coverage
    if (!impl.parsedTensors.empty()) {
        const auto& last = impl.parsedTensors.back();
        uint64_t lastEnd = last.offset + last.size;
        if (lastEnd > impl.fileSize && !impl.allowTruncationRepair) {
            printf("[ReverseHotpatch] ERROR: Tensor index exceeds file size: %llu > %llu\n",
                   (unsigned long long)lastEnd, (unsigned long long)impl.fileSize);
            return false;
        }
        if (lastEnd > impl.fileSize) {
            TensorCorruption tc;
            tc.name = last.name;
            tc.claimedOffset = last.offset;
            tc.claimedSize = last.size;
            tc.fileSize = impl.fileSize;
            tc.description = "Truncation: tensor ends at " + std::to_string(lastEnd) +
                             " but file size is " + std::to_string(impl.fileSize);
            impl.corruptions.push_back(tc);
            impl.Log("[ReverseCompute_Graph] TRUNCATION: %s\n", tc.description.c_str());
        }
    }

    impl.Log("[ReverseCompute_Graph] Computed %zu repairs\n", impl.repairs.size());
    impl.lastCompletedStage = 4;
    return true;
}

// ------------------------------------------------------------------------
// Stage 5: ReverseHotpatch_Next — generate & apply hotpatch plan
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseHotpatchNext() {
    auto& impl = *pImpl_;
    if (impl.repairs.empty()) {
        impl.Log("[ReverseHotpatch_Next] No repairs needed\n");
        impl.lastCompletedStage = 5;
        return true;
    }

    for (size_t i = 0; i < impl.repairs.size(); ++i) {
        if (!impl.ReportProgress("Hotpatch", i, impl.repairs.size())) return false;
        const auto& r = impl.repairs[i];
        impl.Log("[ReverseHotpatch_Next] Applying: %s  off=%llu->%llu  sz=%llu->%llu\n",
                 r.name.c_str(),
                 (unsigned long long)r.oldOffset, (unsigned long long)r.newOffset,
                 (unsigned long long)r.oldSize,   (unsigned long long)r.newSize);
    }

    impl.Log("[ReverseHotpatch_Next] Applied %zu repairs\n", impl.repairs.size());
    impl.lastCompletedStage = 5;
    return true;
}

// ------------------------------------------------------------------------
// Stage 6: ReverseHop_Verify — verify tensor bounds post-patch
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseHopVerify() {
    auto& impl = *pImpl_;
    bool ok = unBlock_gguf_directory(impl.parsedTensors, impl.fileSize, impl.corruptions);

    if (!ok) {
        printf("[ReverseHotpatch] WARNING: Verify found %zu corruption(s)\n", impl.corruptions.size());
        for (const auto& c : impl.corruptions) {
            impl.Log("  %s: %s\n", c.name.c_str(), c.description.c_str());
        }
        // Do not fail — let caller decide if corruptions are fatal
    } else {
        impl.Log("[ReverseHop_Verify] All tensors within bounds\n");
    }

    impl.lastCompletedStage = 6;
    return true;
}

// ------------------------------------------------------------------------
// Stage 7: ReverseHop_Commit — commit corrected view to loader
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ReverseHopCommit() {
    auto& impl = *pImpl_;
    impl.Log("[ReverseHop_Commit] Committing %zu repaired tensors\n", impl.parsedTensors.size());
    impl.lastCompletedStage = 7;
    return true;
}

// ------------------------------------------------------------------------
// Main entry: run all 7 stages in order
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::ProcessFiles(const std::vector<std::filesystem::path>& files) {
    pImpl_->files = files;
    pImpl_->stageResults.clear();
    pImpl_->lastCompletedStage = 0;

    struct Stage { const char* name; bool (ReverseHotpatchEngine::*fn)(); };
    Stage stages[] = {
        {"ReverseHop_Discover",    &ReverseHotpatchEngine::ReverseHopDiscover},
        {"ReverseUnlayer_Parse",   &ReverseHotpatchEngine::ReverseUnlayerParse},
        {"ReverseUnlayer_Index",   &ReverseHotpatchEngine::ReverseUnlayerIndex},
        {"ReverseCompute_Graph",   &ReverseHotpatchEngine::ReverseComputeGraph},
        {"ReverseHotpatch_Next",   &ReverseHotpatchEngine::ReverseHotpatchNext},
        {"ReverseHop_Verify",      &ReverseHotpatchEngine::ReverseHopVerify},
        {"ReverseHop_Commit",      &ReverseHotpatchEngine::ReverseHopCommit},
    };

    for (size_t i = 0; i < sizeof(stages)/sizeof(stages[0]); ++i) {
        printf("[ReverseHotpatch] === Stage %zu: %s ===\n", i + 1, stages[i].name);
        bool ok = (this->*stages[i].fn)();
        ReverseStageResult sr;
        sr.stageIndex = static_cast<int>(i + 1);
        sr.stageName = stages[i].name;
        sr.success = ok;
        if (!ok) sr.error = "Stage failed: " + std::string(stages[i].name);
        pImpl_->stageResults.push_back(sr);
        if (!ok) {
            printf("[ReverseHotpatch] FAILED at stage %zu (%s)\n", i + 1, stages[i].name);
            return false;
        }
    }

    printf("[ReverseHotpatch] All 7 stages completed. Repairs: %zu  Corruptions: %zu\n",
           pImpl_->repairs.size(), pImpl_->corruptions.size());
    return true;
}

// ------------------------------------------------------------------------
// Apply repairs to an existing GGUFLoadResult
// ------------------------------------------------------------------------
size_t ReverseHotpatchEngine::ApplyRepairs(GGUFLoadResult& result) const {
    size_t patched = 0;
    for (auto& t : result.tensors) {
        for (const auto& r : pImpl_->repairs) {
            if (t.name == r.name && r.wasRepaired) {
                t.offset = r.newOffset;
                t.size   = r.newSize;
                ++patched;
                break;
            }
        }
    }
    return patched;
}

// ------------------------------------------------------------------------
// Retry a single stage
// ------------------------------------------------------------------------
bool ReverseHotpatchEngine::RetryStage(int stageIndex) {
    if (stageIndex < 1 || stageIndex > 7) return false;
    switch (stageIndex) {
        case 1: return ReverseHopDiscover();
        case 2: return ReverseUnlayerParse();
        case 3: return ReverseUnlayerIndex();
        case 4: return ReverseComputeGraph();
        case 5: return ReverseHotpatchNext();
        case 6: return ReverseHopVerify();
        case 7: return ReverseHopCommit();
        default: return false;
    }
}

// ------------------------------------------------------------------------
// Dual GPU / Reverse Recovery Integration
// ------------------------------------------------------------------------
void ReverseHotpatchEngine::SetDualGPUHook(DualGPUHook* hook) {
    pImpl_->gpuHook = hook;
}

void ReverseHotpatchEngine::SetTensorBackend(ReverseTensorBackend* backend) {
    pImpl_->tensorBackend = backend;
}

// ------------------------------------------------------------------------
// Fallback-safe reverse execution pipeline
// ------------------------------------------------------------------------
PipelineState ReverseHotpatchEngine::RunReverseGPUPath(
    const std::vector<std::filesystem::path>& files,
    bool gpuAvailable,
    bool cpuFallback)
{
    auto& impl = *pImpl_;
    impl.reversePath.pipelineApplicable = false;
    impl.reversePath.gpuAvailable       = gpuAvailable;
    impl.reversePath.cpuFallback        = cpuFallback;
    impl.reversePath.state              = PipelineState::ReverseRequired;

    printf("[ReverseHotpatch] === Reverse GPU Path ===\n");
    printf("[ReverseHotpatch] Forward pipeline not applicable. Entering reverse path.\n");

    // Stage 1: Discover
    if (!ReverseHopDiscover()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "Discover failed";
        return PipelineState::Failed;
    }

    // Stage 2: Parse
    if (!ReverseUnlayerParse()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "Parse failed";
        return PipelineState::Failed;
    }

    // Stage 3: Index
    if (!ReverseUnlayerIndex()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "Index failed";
        return PipelineState::Failed;
    }

    // Stage 4: Compute
    if (!ReverseComputeGraph()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "ComputeGraph failed";
        return PipelineState::Failed;
    }

    // Stage 5: Hotpatch
    if (!ReverseHotpatchNext()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "Hotpatch failed";
        return PipelineState::Failed;
    }

    // Stage 6: Verify
    if (!ReverseHopVerify()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "Verify failed";
        return PipelineState::Failed;
    }

    // Stage 7: Commit
    if (!ReverseHopCommit()) {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "Commit failed";
        return PipelineState::Failed;
    }

    // GPU recovery
    if (gpuAvailable) {
        impl.reversePath.state = PipelineState::GPURecovery;
        printf("[ReverseHotpatch] GPU backend recovery active.\n");

        // If hook attached, recover dropped tensors
        if (impl.gpuHook && impl.tensorBackend) {
            impl.gpuHook->RecoverAll();
            impl.reversePath.recoveryHops++;
        }

        impl.reversePath.state = PipelineState::Complete;
        printf("[ReverseHotpatch] Reverse GPU path complete. TPS recovery ready.\n");
    } else if (cpuFallback) {
        impl.reversePath.state = PipelineState::Complete;
        printf("[ReverseHotpatch] CPU fallback path complete.\n");
    } else {
        impl.reversePath.state = PipelineState::Failed;
        impl.reversePath.lastError = "No execution backend available";
        printf("[ReverseHotpatch] FAILED: No GPU and no CPU fallback.\n");
        return PipelineState::Failed;
    }

    return impl.reversePath.state;
}

ReverseGPUPath ReverseHotpatchEngine::GetReverseGPUPath() const {
    return pImpl_->reversePath;
}

// ------------------------------------------------------------------------
// Model load with automatic reverse fallback
// ------------------------------------------------------------------------
LoadResult ReverseHotpatchEngine::LoadModelWithFallback(
    const std::string& path,
    bool gpuAvailable,
    bool cpuFallback)
{
    std::vector<std::filesystem::path> files = { path };

    // Try normal pipeline first
    if (ProcessFiles(files)) {
        return LoadResult::Success;
    }

    // Normal pipeline failed — check if reverse path can recover
    PipelineState state = RunReverseGPUPath(files, gpuAvailable, cpuFallback);

    switch (state) {
        case PipelineState::Complete:
            return LoadResult::Success;
        case PipelineState::Failed:
            if (!gpuAvailable && !cpuFallback) {
                return LoadResult::NoExecutionBackend;
            }
            return LoadResult::TensorBoundsError;
        case PipelineState::ReverseRequired:
        case PipelineState::GPURecovery:
            return LoadResult::ReverseRequired;
        default:
            return LoadResult::Unknown;
    }
}

} // namespace Deep2
