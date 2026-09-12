#include "Deep2SsVkProductBind.hpp"

namespace Deep2 {

static std::uint64_t u64min(std::uint64_t a, std::uint64_t b) noexcept {
    return a < b ? a : b;
}
static std::uint64_t u64max(std::uint64_t a, std::uint64_t b) noexcept {
    return a > b ? a : b;
}
static std::uint64_t u64abs(std::uint64_t a, std::uint64_t b) noexcept {
    return a >= b ? a - b : b - a;
}

void SsVkProductBind::bind(SsVkPackedQ2KFn fn, void* user) noexcept {
    fn_ = fn;
    user_ = user;
}

void SsVkProductBind::unbind() noexcept {
    fn_ = nullptr;
    user_ = nullptr;
    token_ = SsVkTokenProof{};
    nextOperatorOrdinal_ = 0;
}

void SsVkProductBind::beginToken(std::uint64_t tokenOrdinal) noexcept {
    token_ = SsVkTokenProof{};
    token_.tokenOrdinal = tokenOrdinal;
    token_.allOpsAuthoritative = 1;
    nextOperatorOrdinal_ = 0;
}

bool SsVkProductBind::proofAuthoritative(const SsVkQ2KOpProof& p) noexcept {
    return
        p.productLinked &&
        p.packedQ2KLive &&
        p.materialSameTokenOverlap &&
        p.aggregateBwAuthority &&
        p.gpu0RealForwards &&
        p.gpu1RealForwards &&
        p.compactMergeReal &&
        p.outputParity &&
        !p.fullDequantBuffer &&
        !p.materializedWeightBytesNonzero &&
        !p.serialGpuChain &&
        !p.weightMigration &&
        !p.syntheticIo &&
        !p.deviceLost &&
        !p.criticalPathNvmeReads;
}

std::uint64_t SsVkProductBind::overlapNs(const SsVkQ2KOpProof& p) noexcept {
    const std::uint64_t s = u64max(p.gpu0StartNs, p.gpu1StartNs);
    const std::uint64_t e = u64min(p.gpu0EndNs, p.gpu1EndNs);
    return e > s ? e - s : 0;
}

std::uint64_t SsVkProductBind::criticalNs(const SsVkQ2KOpProof& p) noexcept {
    const std::uint64_t s = u64min(p.gpu0StartNs, p.gpu1StartNs);
    const std::uint64_t e = u64max(p.gpu0EndNs, p.gpu1EndNs);
    return e > s ? e - s : 0;
}

std::uint64_t SsVkProductBind::finishSkewNs(const SsVkQ2KOpProof& p) noexcept {
    return u64abs(p.gpu0EndNs, p.gpu1EndNs);
}

bool SsVkProductBind::dispatchQ2K(const SsVkQ2KRequest& in) noexcept {
    ++token_.q2kOpsSeen;

    if (!fn_ || !in.packedWeights || !in.input || !in.output ||
        !in.rows || !in.cols || (in.cols % kQ2KBlockElements) != 0) {
        token_.allOpsAuthoritative = 0;
        return false;
    }

    // Certified GGUF Q2_K geometry: 84 bytes / 256 weights.
    // A 72-byte stride is forbidden; it is a stale legacy layout.
    const std::size_t blocksPerRow =
        (in.cols + kQ2KBlockElements - 1) / kQ2KBlockElements;
    const std::size_t rowBytes = blocksPerRow * kQ2KBlockBytes;

    if (rowBytes / blocksPerRow != kQ2KBlockBytes) {
        token_.allOpsAuthoritative = 0;
        return false;
    }

    if (in.rows > (static_cast<std::size_t>(-1) / rowBytes) ||
        in.rows * rowBytes > in.weightBytes) {
        token_.allOpsAuthoritative = 0;
        return false;
    }

    SsVkQ2KRequest req = in;
    req.tokenOrdinal = token_.tokenOrdinal;
    req.operatorOrdinal = nextOperatorOrdinal_++;

    SsVkQ2KOpProof p{};
    const int rc = fn_(user_, &req, &p);
    if (rc != 0 || !proofAuthoritative(p)) {
        token_.allOpsAuthoritative = 0;
        if (p.deviceLost) token_.anyDeviceLost = 1;
        token_.criticalPathNvmeReads += p.criticalPathNvmeReads;
        return false;
    }

    ++token_.q2kOpsProduct;
    token_.gpu0PackedBytes += p.gpu0PackedBytes;
    token_.gpu1PackedBytes += p.gpu1PackedBytes;
    token_.overlapNsSum += overlapNs(p);
    token_.criticalPathNsSum += criticalNs(p);
    const auto skew = finishSkewNs(p);
    if (skew > token_.finishSkewNsMax) token_.finishSkewNsMax = skew;
    token_.anyDualForward = 1;
    return true;
}

bool SsVkProductBind::tokenAuthoritative() const noexcept {
    return
        bound() &&
        token_.q2kOpsSeen > 0 &&
        token_.q2kOpsProduct == token_.q2kOpsSeen &&
        token_.allOpsAuthoritative &&
        token_.anyDualForward &&
        !token_.anyDeviceLost &&
        !token_.stale72BytePathUsed &&
        token_.fullModelForward &&
        token_.finalNormReal &&
        token_.lmHeadReal &&
        token_.samplerCommitReal &&
        token_.kvAdvanceReal &&
        !token_.sealedLogitsReuse &&
        token_.hostForwardLayerCalls == 0 &&
        token_.hostMaterializations == 0 &&
        token_.cpuF32Expands == 0 &&
        token_.criticalPathNvmeReads == 0 &&
        token_.externalRuntimeCalls == 0;
}

} // namespace Deep2
