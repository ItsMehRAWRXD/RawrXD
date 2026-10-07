#pragma once
#include <cstddef>
#include <cstdint>

namespace Deep2 {

static constexpr std::size_t kQ2KBlockBytes = 84;
static constexpr std::size_t kQ2KBlockElements = 256;

struct SsVkQ2KRequest {
    const void* packedWeights = nullptr;
    const float* input = nullptr;
    float* output = nullptr;

    std::size_t rows = 0;
    std::size_t cols = 0;
    std::size_t weightBytes = 0;

    std::uint64_t tokenOrdinal = 0;
    std::uint64_t operatorOrdinal = 0;
    const char* tensorName = nullptr;
};

struct SsVkQ2KOpProof {
    std::uint64_t gpu0StartNs = 0;
    std::uint64_t gpu0EndNs = 0;
    std::uint64_t gpu1StartNs = 0;
    std::uint64_t gpu1EndNs = 0;

    std::uint64_t gpu0PackedBytes = 0;
    std::uint64_t gpu1PackedBytes = 0;

    std::uint32_t productLinked = 0;
    std::uint32_t packedQ2KLive = 0;
    std::uint32_t materialSameTokenOverlap = 0;
    std::uint32_t aggregateBwAuthority = 0;

    std::uint32_t gpu0RealForwards = 0;
    std::uint32_t gpu1RealForwards = 0;
    std::uint32_t compactMergeReal = 0;
    std::uint32_t outputParity = 0;

    std::uint32_t fullDequantBuffer = 0;
    std::uint32_t materializedWeightBytesNonzero = 0;
    std::uint32_t serialGpuChain = 0;
    std::uint32_t weightMigration = 0;

    std::uint32_t syntheticIo = 0;
    std::uint32_t deviceLost = 0;
    std::uint32_t criticalPathNvmeReads = 0;
    std::uint32_t reserved = 0;
};

using SsVkPackedQ2KFn =
    int (*)(void* user, const SsVkQ2KRequest* req, SsVkQ2KOpProof* outProof);

struct SsVkTokenProof {
    std::uint64_t tokenOrdinal = 0;
    std::uint64_t q2kOpsSeen = 0;
    std::uint64_t q2kOpsProduct = 0;
    std::uint64_t gpu0PackedBytes = 0;
    std::uint64_t gpu1PackedBytes = 0;

    std::uint64_t overlapNsSum = 0;
    std::uint64_t criticalPathNsSum = 0;
    std::uint64_t finishSkewNsMax = 0;

    std::uint32_t allOpsAuthoritative = 1;
    std::uint32_t anyDualForward = 0;
    std::uint32_t anyDeviceLost = 0;
    std::uint32_t stale72BytePathUsed = 0;

    std::uint32_t fullModelForward = 0;
    std::uint32_t finalNormReal = 0;
    std::uint32_t lmHeadReal = 0;
    std::uint32_t samplerCommitReal = 0;

    std::uint32_t kvAdvanceReal = 0;
    std::uint32_t sealedLogitsReuse = 0;
    std::uint32_t hostForwardLayerCalls = 0;
    std::uint32_t hostMaterializations = 0;

    std::uint32_t cpuF32Expands = 0;
    std::uint32_t criticalPathNvmeReads = 0;
    std::uint32_t externalRuntimeCalls = 0;
    std::uint32_t reserved = 0;
};

class SsVkProductBind {
public:
    void bind(SsVkPackedQ2KFn fn, void* user) noexcept;
    void unbind() noexcept;
    bool bound() const noexcept { return fn_ != nullptr; }

    void beginToken(std::uint64_t tokenOrdinal) noexcept;

    // Returns true only when the product callback executed and its proof was
    // authoritative. A bound-but-failed callback must be treated as fatal by
    // the strict product decode path; do not silently fall back.
    bool dispatchQ2K(const SsVkQ2KRequest& req) noexcept;

    void noteFullModelForward(bool ok) noexcept {
        token_.fullModelForward = ok ? 1u : 0u;
    }
    void noteFinalNorm(bool ok) noexcept {
        token_.finalNormReal = ok ? 1u : 0u;
    }
    void noteLmHead(bool ok) noexcept {
        token_.lmHeadReal = ok ? 1u : 0u;
    }
    void noteSamplerCommit(bool ok) noexcept {
        token_.samplerCommitReal = ok ? 1u : 0u;
    }
    void noteKvAdvance(bool ok) noexcept {
        token_.kvAdvanceReal = ok ? 1u : 0u;
    }
    void noteSealedLogitsReuse(bool used) noexcept {
        token_.sealedLogitsReuse = used ? 1u : 0u;
    }
    void noteHostCounters(std::uint32_t hostForwardLayerCalls,
                          std::uint32_t hostMaterializations,
                          std::uint32_t cpuF32Expands) noexcept {
        token_.hostForwardLayerCalls = hostForwardLayerCalls;
        token_.hostMaterializations = hostMaterializations;
        token_.cpuF32Expands = cpuF32Expands;
    }
    void noteCriticalPathNvmeReads(std::uint32_t reads) noexcept {
        token_.criticalPathNvmeReads = reads;
    }
    void noteExternalRuntimeCalls(std::uint32_t calls) noexcept {
        token_.externalRuntimeCalls = calls;
    }

    const SsVkTokenProof& tokenProof() const noexcept { return token_; }

    // Batch-2 product decode authority. This does NOT set PROMOTE.
    bool tokenAuthoritative() const noexcept;

private:
    static bool proofAuthoritative(const SsVkQ2KOpProof& p) noexcept;
    static std::uint64_t overlapNs(const SsVkQ2KOpProof& p) noexcept;
    static std::uint64_t criticalNs(const SsVkQ2KOpProof& p) noexcept;
    static std::uint64_t finishSkewNs(const SsVkQ2KOpProof& p) noexcept;

    SsVkPackedQ2KFn fn_ = nullptr;
    void* user_ = nullptr;
    SsVkTokenProof token_{};
    std::uint64_t nextOperatorOrdinal_ = 0;
};

} // namespace Deep2
