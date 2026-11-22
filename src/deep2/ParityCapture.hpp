// ============================================================================
// ParityCapture.hpp  --  RAWRXD_DEEP2 Sprint 9 P0-01 / P0-02
// ============================================================================
// Native, dependency-free first-divergence capture contract.
//
// Purpose
//   Sprint 8 closed with a *measurable* CPU reference-parity defect instead of
//   a crash (PREFILL_PARITY_MAX_REL=21.9, NUMERICAL_PARITY=FAIL). Sprint 9 must
//   turn that single aggregate number into an actionable localisation: the
//   earliest (layer, position, operation) tensor whose serial and batched CPU
//   prefill outputs disagree.
//
//   This header defines the capture contract shared by BOTH execution paths so
//   their records are directly comparable. It performs no model I/O and pulls in
//   only the C++ standard library, so it can be unit-tested and reused by any
//   driver (serial-vs-batched CPU prefill, GPU-vs-CPU, REAP, Vulkan) without
//   linking the 356 KB executor.
//
// Comparison rules (authoritative; every path MUST use these verbatim)
//   For reference value a and candidate value b at index i:
//     d       = a - b
//     absErr  = |d|
//     scale   = max(|a|, |b|)
//     relErr  = (scale > 0) ? absErr / scale : 0        // 0 vs 0 -> 0
//   An element is a MISMATCH when:
//     absErr > absTol + relTol * scale                  (numpy.isclose-style)
//   Aggregate:
//     maxAbsError       = max_i absErr(i)
//     maxRelError       = max_i relErr(i)
//     rmsError          = sqrt( (1/n) * sum_i absErr(i)^2 )
//     firstMismatchIndex= smallest i that is a MISMATCH, else elementCount
//   Fail closed: a size mismatch, empty input, or any non-finite operand makes
//   `valid=false`; callers MUST NOT treat an invalid capture as a pass.
// ============================================================================
#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace RawrXD {
namespace Deep2 {
namespace Parity {

// The first-divergence capture record. One record describes ONE comparable
// tensor produced by ONE operation at ONE (layer, position).
//
//   layer         transformer block index (0-based); use kSentinelLayer for
//                 tensors that live outside any single block (final logits).
//   position      token position the tensor was produced for.
//   operation     an operation discriminator. For executor op traces this is
//                 the program counter (pc); for the final lm-head it is a
//                 reserved sentinel (kSentinelOperation). The exact numbering
//                 is the driver's contract as long as both paths agree.
//   elementCount  number of float elements compared.
//   maxAbsError   see comparison rules above.
//   maxRelError   see comparison rules above.
//   rmsError      see comparison rules above.
//   firstMismatchIndex  index of the first mismatching element, or elementCount
//                 when no element exceeded tolerance.
//   valid         false when the two buffers could not be compared at all
//                 (size mismatch / empty / non-finite). A caller MUST NOT pass
//                 on an invalid record.
//   hasMismatch   true iff firstMismatchIndex < elementCount.
struct ParityCapture {
    std::uint32_t layer = 0;
    std::uint32_t position = 0;
    std::uint32_t operation = 0;
    std::uint64_t elementCount = 0;
    double maxAbsError = 0.0;
    double maxRelError = 0.0;
    double rmsError = 0.0;
    std::uint64_t firstMismatchIndex = 0;
    bool valid = false;
    bool hasMismatch = false;
    std::uint64_t worstRelativeIndex = 0;
    double worstReference = 0.0;
    double worstCandidate = 0.0;
    double worstAbsoluteError = 0.0;
    double worstRelativeError = 0.0;
    bool hasWorstRelative = false;
    bool hasNonFinite = false;
    std::uint64_t nonFiniteIndex = 0;

    // True when the capture is valid AND no element exceeded tolerance.
    bool Equivalent() const noexcept { return valid && !hasMismatch; }
};

// Reserved coordinate values so non-block / non-op tensors still form a unique,
// comparable key rather than colliding with a real layer/operation.
inline constexpr std::uint32_t kSentinelLayer = 0xFFFFFFFFu;
inline constexpr std::uint32_t kSentinelPosition = 0xFFFFFFFFu;
inline constexpr std::uint32_t kSentinelOperation = 0xFFFFFFFFu;

// Relative-error denominator floor. When scale==0 (both operands zero) relErr is
// defined as 0, so this floor only guards the pathological scale==0-with-nonzero-
// difference case, which cannot occur for finite floats; it exists so the
// division is always defined and reproducible.
inline constexpr double kRelDenomFloor = 1e-30;

// Comparison tolerances. Defaults are diagnostic (tight) defaults; product
// acceptance profiles choose their own and record them on the receipt.
struct Tolerance {
    double absTol = 1e-4;
    double relTol = 1e-3;
};

inline bool IsFiniteCapture(double absTol, double relTol) noexcept {
    return std::isfinite(absTol) && std::isfinite(relTol) &&
           absTol >= 0.0 && relTol >= 0.0;
}

// Compare two float buffers element-by-element and produce one ParityCapture.
// `layer`, `position`, `operation` are copied through unchanged so the record is
// self-describing. Returns an invalid capture (valid=false) when n==0, when
// either pointer is null with n>0, or when any operand is non-finite.
inline ParityCapture Compare(const float* reference,
                             const float* candidate,
                             std::size_t n,
                             std::uint32_t layer,
                             std::uint32_t position,
                             std::uint32_t operation,
                             const Tolerance& tol = {}) {
    ParityCapture cap;
    cap.layer = layer;
    cap.position = position;
    cap.operation = operation;
    cap.elementCount = static_cast<std::uint64_t>(n);
    // Default firstMismatchIndex to "past the end" == no mismatch; corrected
    // below if one is found.
    cap.firstMismatchIndex = cap.elementCount;

    if (!IsFiniteCapture(tol.absTol, tol.relTol)) {
        return cap; // valid stays false
    }
    if (n == 0 || reference == nullptr || candidate == nullptr) {
        return cap; // valid stays false
    }

    double sumSq = 0.0;
    bool sawNonFinite = false;
    bool sawMismatch = false;
    std::uint64_t firstMismatch = cap.elementCount;

    for (std::size_t i = 0; i < n; ++i) {
        const double a = static_cast<double>(reference[i]);
        const double b = static_cast<double>(candidate[i]);
        if (!std::isfinite(a) || !std::isfinite(b)) {
            sawNonFinite = true;
            cap.hasNonFinite = true;
            cap.nonFiniteIndex = static_cast<std::uint64_t>(i);
            break;
        }
        const double d = a - b;
        const double absErr = std::abs(d);
        const double scale = std::max(std::abs(a), std::abs(b));
        const double relErr = (scale > 0.0) ? (absErr / scale) : 0.0;

        sumSq += absErr * absErr;
        if (absErr > cap.maxAbsError) cap.maxAbsError = absErr;
        if (relErr > cap.maxRelError) cap.maxRelError = relErr;
        if (!cap.hasWorstRelative || relErr > cap.worstRelativeError) {
            cap.hasWorstRelative = true;
            cap.worstRelativeIndex = static_cast<std::uint64_t>(i);
            cap.worstReference = a;
            cap.worstCandidate = b;
            cap.worstAbsoluteError = absErr;
            cap.worstRelativeError = relErr;
        }

        if (!sawMismatch && absErr > tol.absTol + tol.relTol * scale) {
            sawMismatch = true;
            firstMismatch = static_cast<std::uint64_t>(i);
        }
    }

    if (sawNonFinite) {
        // Fail closed: do not report a numeric comparison on non-finite data.
        cap.valid = false;
        cap.hasMismatch = false;
        return cap;
    }

    cap.rmsError = std::sqrt(sumSq / static_cast<double>(n));
    cap.firstMismatchIndex = firstMismatch;
    cap.hasMismatch = sawMismatch;
    cap.valid = true;
    return cap;
}

// Convenience overload for std::vector. Returns an invalid capture when the two
// vectors differ in length (a size mismatch is never a pass).
inline ParityCapture Compare(const std::vector<float>& reference,
                             const std::vector<float>& candidate,
                             std::uint32_t layer,
                             std::uint32_t position,
                             std::uint32_t operation,
                             const Tolerance& tol = {}) {
    if (reference.size() != candidate.size()) {
        ParityCapture cap;
        cap.layer = layer;
        cap.position = position;
        cap.operation = operation;
        cap.elementCount = static_cast<std::uint64_t>(reference.size());
        cap.firstMismatchIndex = cap.elementCount;
        cap.valid = false;
        cap.hasMismatch = false;
        return cap;
    }
    return Compare(reference.data(), candidate.data(), reference.size(),
                   layer, position, operation, tol);
}

// Index of the first mismatching element, or `n` when the buffers are
// equivalent within tolerance. Convenience wrapper for callers that only need
// the localisation index. Returns n (== "no mismatch") for invalid input.
inline std::uint64_t FirstDivergence(const float* reference,
                                     const float* candidate,
                                     std::size_t n,
                                     const Tolerance& tol = {}) {
    const ParityCapture cap = Compare(reference, candidate, n,
                                      kSentinelLayer, kSentinelPosition,
                                      kSentinelOperation, tol);
    return cap.valid ? cap.firstMismatchIndex : n;
}

// ---------------------------------------------------------------------------
// Op-sequence comparison (P0-02 first-divergence across layers/positions).
// ---------------------------------------------------------------------------

// One captured tensor in execution order. A driver converts its executor's op
// trace (or per-position logits) into these samples; the two paths under test
// must emit samples in the SAME order for a positional diff to be meaningful.
struct TensorSample {
    std::uint32_t layer = 0;
    std::uint32_t position = 0;
    std::uint32_t operation = 0;
    std::string name;              // human label, diagnostics only
    std::vector<float> values;
};

// A single divergence verdict between two ordered sample sequences.
struct Divergence {
    bool valid = false;            // sequences were structurally comparable
    bool diverged = false;         // an element exceeded tolerance somewhere
    std::size_t sampleIndex = 0;   // index into the sequences of the FIRST
                                   // divergent sample (or size() if none)
    std::string reason;            // why valid=false, when applicable
    ParityCapture capture;         // the first divergent sample's full record
};

// Compare two ordered sample sequences. The FIRST sample whose comparison is
// invalid or divergent is reported; `diverged` is true if any sample diverges.
// Structural problems (length mismatch) make the result invalid but still
// report how far the comparison got, so a driver can point at the exact sample.
inline Divergence CompareSamples(const std::vector<TensorSample>& reference,
                                 const std::vector<TensorSample>& candidate,
                                 const Tolerance& tol = {}) {
    Divergence out;
    if (reference.size() != candidate.size()) {
        out.valid = false;
        out.reason = "sample count mismatch: reference=" +
                     std::to_string(reference.size()) + " candidate=" +
                     std::to_string(candidate.size());
        // Compare the common prefix so a length mismatch still localises.
        const std::size_t common = std::min(reference.size(), candidate.size());
        for (std::size_t i = 0; i < common; ++i) {
            const ParityCapture cap = Compare(reference[i].values,
                                              candidate[i].values,
                                              reference[i].layer,
                                              reference[i].position,
                                              reference[i].operation, tol);
            if (!cap.valid || cap.hasMismatch) {
                out.diverged = cap.hasMismatch;
                out.sampleIndex = i;
                out.capture = cap;
                out.reason = cap.valid ? "divergence in common prefix"
                                       : "invalid capture in common prefix";
                return out;
            }
        }
        out.sampleIndex = common;
        return out;
    }

    out.valid = true;
    for (std::size_t i = 0; i < reference.size(); ++i) {
        const ParityCapture cap = Compare(reference[i].values,
                                          candidate[i].values,
                                          reference[i].layer,
                                          reference[i].position,
                                          reference[i].operation, tol);
        if (!cap.valid) {
            out.valid = false;
            out.reason = "invalid capture at sample " + std::to_string(i) +
                         " (" + reference[i].name + ")";
            out.sampleIndex = i;
            out.capture = cap;
            return out;
        }
        if (cap.hasMismatch) {
            out.diverged = true;
            out.sampleIndex = i;
            out.capture = cap;
            return out;
        }
    }
    out.sampleIndex = reference.size();
    return out;
}

// Short human-readable summary of one record; used by drivers and tests.
inline std::string Describe(const ParityCapture& cap) {
    std::string s = "ParityCapture{layer=" + std::to_string(cap.layer) +
                    " position=" + std::to_string(cap.position) +
                    " operation=" + std::to_string(cap.operation) +
                    " elements=" + std::to_string(cap.elementCount);
    if (!cap.valid) {
        s += " valid=false}";
        return s;
    }
    s += " maxAbs=" + std::to_string(cap.maxAbsError);
    s += " maxRel=" + std::to_string(cap.maxRelError);
    s += " rms=" + std::to_string(cap.rmsError);
    s += " firstMismatch=" + std::to_string(cap.firstMismatchIndex);
    if (cap.hasWorstRelative)
        s += " worstRelIndex=" + std::to_string(cap.worstRelativeIndex) +
             " worstRel=" + std::to_string(cap.worstRelativeError);
    if (cap.hasNonFinite)
        s += " nonFiniteIndex=" + std::to_string(cap.nonFiniteIndex);
    s += cap.hasMismatch ? " MISMATCH}" : " OK}";
    return s;
}

} // namespace Parity
} // namespace Deep2
} // namespace RawrXD
