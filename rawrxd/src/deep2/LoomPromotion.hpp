#pragma once
// ============================================================================
// LoomPromotion.hpp — RAWRXD_KERNEL_LOOM_LIVE_GEMV_BG8_001
//
// The types that decide whether a generated kernel may replace production
// weight computation. Every one of them is fed MEASURED values only.
//
// The central change from the declaration-only loom: modelResidual() is gone.
// It was a MODEL of GEMV error, and a model cannot be compared against another
// model to decide which is better -- both are wrong in the same unknown way.
// Nothing may enter these gates that did not come out of a real execution and a
// real differential against a real reference.
//
// Three laws this file exists to make checkable:
//
//   PROMOTION_WHEN_OWNERSHIP_UNKNOWN      = FORBIDDEN
//   PROMOTION_WHEN_RESIDUAL_NOT_MEASURED  = FORBIDDEN
//   EXECUTABLE_HASH != GENOME_FINGERPRINT
//
// The last one matters because two materially different compiled kernels can
// come from one genome. The fingerprint proves the RECIPE. It says nothing
// about what the compiler did with it.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace rawrxd::deep2::loom {

// ---------------------------------------------------------------------------
// Ownership — copied from loom_48.hpp so promotion cannot silently disagree
// with the declaration surface. Calling LinearW() proves ENTRY, not ownership.
// ---------------------------------------------------------------------------
enum class Ownership : std::uint8_t {
    Bypass, Delegated, Owned, Conditional, Unknown
};

const char* ownershipName(Ownership o);

// Promotion requires a KNOWN ownership. Generation may explore Unknown; an
// isolated harness may even execute it; but nothing may REPLACE production
// weight computation until the real consumption path is known.
constexpr bool ownershipAdmitsPromotion(Ownership o) noexcept {
    return o == Ownership::Bypass ||
           o == Ownership::Delegated ||
           o == Ownership::Owned ||
           o == Ownership::Conditional;
}

// ---------------------------------------------------------------------------
// MeasuredResidual — output of a real differential. There is no constructor
// that takes a synthetic estimate.
// ---------------------------------------------------------------------------
struct MeasuredResidual {
    double   maxAbsError   = 0.0;
    double   meanAbsError  = 0.0;
    double   rmsError      = 0.0;
    double   relativeL2    = 1.0;
    std::uint64_t mismatched   = 0;
    std::uint64_t elementCount = 0;
    bool     finite        = false;

    // True only when this residual came from an executed comparison.
    constexpr bool measured() const noexcept {
        return elementCount > 0 && finite;
    }
};

// The only widening rule. No synthetic estimate can enter it because there is
// no field it could enter through: every field is set by the comparator.
constexpr bool mayWiden(const MeasuredResidual& incumbent,
                        const MeasuredResidual& candidate) noexcept {
    if (!candidate.measured())          return false;   // no measurement, no widening
    if (!incumbent.measured())          return true;    // nothing to beat yet
    return candidate.relativeL2 < incumbent.relativeL2;
}

// ---------------------------------------------------------------------------
// Resource axes. A numerically valid candidate is NOT automatically a winner:
// a kernel that is 3% faster while reconstructing the whole weight defeats the
// entire point of a SpacelessGemvView.
// ---------------------------------------------------------------------------
struct ResourceCost {
    std::uint64_t reconstructedWeightBytes = 0;  // MUST be 0 for spaceless
    std::uint64_t dequantBufferBytes       = 0;  // MUST be 0 for spaceless
    std::uint64_t scratchBytes             = 0;
    std::uint64_t sourceBytesRead          = 0;
    std::uint64_t deviceBytesTransferred   = 0;
    std::uint64_t wallTimeNs               = 0;
};

constexpr bool isSpaceless(const ResourceCost& c) noexcept {
    return c.reconstructedWeightBytes == 0 &&
           c.dequantBufferBytes       == 0;
}

// ---------------------------------------------------------------------------
// Executable identity — deliberately NOT the genome fingerprint.
// ---------------------------------------------------------------------------
struct ExecutableIdentity {
    std::uint64_t genomeHash           = 0;
    std::uint64_t materializerHash     = 0;
    std::string   compilerId;
    std::string   compilerFlags;
    std::string   targetIsa;
    std::uint64_t generatedSourceHash  = 0;
    std::uint64_t binaryHash           = 0;

    // FNV-1a over all of the above. Two kernels are the same executable only if
    // every component matches; a re-compile with different flags changes it.
    std::uint64_t hash() const noexcept;
};

// ---------------------------------------------------------------------------
// Traffic contract.
//
// The reversal is NOT "400 GB becomes 8 GB of traffic". 400 GB is the LOGICAL
// weight scope and it is allowed to stay 400 GB, or grow. What must collapse is
// the FRESH PHYSICAL BYTES PER TOKEN:
//
//     TPS  ~=  sustainedBandwidth / freshPhysicalBytesPerToken
//
// A 400 GB model at 8 GB/token on 1.2 TB/s has a bandwidth-only ceiling near
// 150 TPS, leaving the rest of the machine for KV, attention, reconstruction,
// synchronisation and dispatch. Re-reading 400 GB per token cannot.
// ---------------------------------------------------------------------------
struct TrafficContract {
    // LOGICAL scope. Unbounded on purpose.
    std::uint64_t logicalWeightBytes      = 0;
    std::uint64_t logicalWeightBytesUnbounded = 0;  // "or larger", stated not assumed

    // PHYSICAL realization. This is what is actually contracted.
    std::uint64_t physicalFreshBytesPerToken = 0;
    std::uint64_t physicalBudgetBytesPerToken = 0;  // <= ~8 GB at 1.2 TB/s / 150 TPS

    std::uint64_t sustainedBandwidthBytesPerSec = 0;
    std::uint32_t targetTokensPerSecond           = 0;

    // Derived, never assigned.
    std::uint64_t bandwidthCeilingTps() const noexcept;
    std::uint64_t minTrafficCollapse() const noexcept;
    bool logicalExceedsPhysical() const noexcept {
        return physicalFreshBytesPerToken < logicalWeightBytes;
    }
    bool physicalWithinBudget() const noexcept {
        return physicalFreshBytesPerToken <= physicalBudgetBytesPerToken;
    }
    // 400 GB logical is compatible with <= 8 GB realized ONLY IF the same
    // required computation is preserved. That is a separate gate; this type
    // does not assert it.
    bool verdict() const noexcept {
        return physicalWithinBudget() && bandwidthCeilingTps() >= targetTokensPerSecond;
    }
};

} // namespace rawrxd::deep2::loom
