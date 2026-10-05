// Measured.hpp
// RAWRXD_INPUT_AUTHORITY_001
//
// THE LAW
// ------
//   Before proving that two things agree, prove that two independently
//   populated things actually exist.
//
// WHY IT EXISTS
// -------------
// Three separate defects in this repository produced confident, wrong
// PASS receipts, and all three had the same shape:
//
//   1. A stale object file linked successfully. The comparison ran. The
//      compared binary did not contain the code under test.
//   2. A `size_t`-truncated accumulator made MIN_COSINE report 0 while every
//      input was 1. The aggregation ran. The aggregate was meaningless.
//   3. An edit silently failed to apply (wrong working directory), so a
//      manifest comparison compared "" against "" and reported
//      RESTORE_MATCHES_ORIGINAL=True. The comparison ran. The operands were
//      never populated.
//
// In every case the comparison logic was correct and the INPUTS were not. So
// input authority is checked first and separately, and a gate is structurally
// unable to reach a PASS verdict without it.
//
// THE DISTINCTION
// ---------------
// A zero/default value must never be able to mean both "measured zero" and
// "never measured". `Measured<T>` separates them: `populated` is the only
// thing that authorises reading `value`, and compare() refuses to produce
// Match or Mismatch for an unpopulated arm.
//
// Never write this:
//     compare(empty, empty);  // equal, therefore PASS
//
// Write this:
//     if (!a.populated || !b.populated) return InvalidInput;
//     return compare(a.value, b.value);

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

namespace rawrxd::authority {

enum class CompareStatus {
    Match,          // both populated, agree within the declared criterion
    Mismatch,       // both populated, disagree
    InvalidInput,   // at least one arm was never populated -- NOT a result
    NotAdmissible,  // both populated but the comparison itself is invalid
                    // (coordinate mismatch, element-count mismatch, ...)
};

// ---------------------------------------------------------------------------
// Measured<T> -- a value that knows whether it was ever observed.
// ---------------------------------------------------------------------------
template <typename T>
struct Measured {
    bool     populated = false;
    T        value{};
    uint64_t sourceGeneration = 0;  // identifies the build/arm that produced it
    uint64_t observationId    = 0;  // which observation point within that arm
    uint32_t originTag       = 0;  // which route/arm

    Measured() = default;

    static Measured observe(T v, uint64_t gen, uint64_t obs, uint32_t tag) {
        Measured m;
        m.populated        = true;
        m.value            = v;
        m.sourceGeneration = gen;
        m.observationId    = obs;
        m.originTag        = tag;
        return m;
    }

    // Never returns a meaningful value unless populated. Kept explicit so a
    // caller that forgets to check gets an obvious sentinel rather than a
    // plausible number.
    T get() const { return value; }
};

// ---------------------------------------------------------------------------
// InputAuthority -- the pre-comparison gate.
//
// Every serious gate fills this in BEFORE comparing anything. If any required
// field is not satisfied the gate may not emit PASS or FAIL; it may only emit
// INVALID_INPUT.
// ---------------------------------------------------------------------------
struct InputAuthority {
    // Presence
    bool inputAPresent = false;
    bool inputBPresent = false;

    // Non-vacuity: an empty vector satisfies "present" but not "elements > 0".
    uint64_t inputAElements = 0;
    uint64_t inputBElements = 0;

    // Provenance: which build/arm produced each side.
    bool inputASourceValid   = false;
    bool inputBSourceValid   = false;
    bool inputABuildIdValid  = false;
    bool inputBBuildIdValid  = false;

    // Coordinate agreement. Two tensors at different positions, layers or
    // stages are not comparable no matter what their bytes say.
    bool sameToken     = false;
    bool samePosition  = false;
    bool sameLayer     = false;
    bool sameStage     = false;
    bool sameElements  = false;
    bool sameDtype     = false;

    const char* nameA = "A";
    const char* nameB = "B";

    bool presenceOk()  const { return inputAPresent && inputBPresent; }
    bool nonVacuous()  const { return inputAElements > 0 && inputBElements > 0; }
    bool provenanceOk()const {
        return inputASourceValid && inputBSourceValid &&
               inputABuildIdValid && inputBBuildIdValid;
    }
    bool coordinatesOk() const {
        return sameToken && samePosition && sameLayer && sameStage &&
               sameElements && sameDtype;
    }

    bool admissible() const {
        return presenceOk() && nonVacuous() && provenanceOk() && coordinatesOk();
    }

    void print(const char* gate) const {
        std::fprintf(stderr, "INPUT_A_PRESENT=%d\n",          inputAPresent  ? 1 : 0);
        std::fprintf(stderr, "INPUT_B_PRESENT=%d\n",          inputBPresent  ? 1 : 0);
        std::fprintf(stderr, "INPUT_A_ELEMENTS_GT_0=%d\n",     inputAElements > 0 ? 1 : 0);
        std::fprintf(stderr, "INPUT_B_ELEMENTS_GT_0=%d\n",     inputBElements > 0 ? 1 : 0);
        std::fprintf(stderr, "INPUT_A_SOURCE_VALID=%d\n",      inputASourceValid ? 1 : 0);
        std::fprintf(stderr, "INPUT_B_SOURCE_VALID=%d\n",      inputBSourceValid ? 1 : 0);
        std::fprintf(stderr, "INPUT_A_BUILD_ID_VALID=%d\n",   inputABuildIdValid ? 1 : 0);
        std::fprintf(stderr, "INPUT_B_BUILD_ID_VALID=%d\n",   inputBBuildIdValid ? 1 : 0);
        std::fprintf(stderr, "SAME_TOKEN=%d\n",     sameToken    ? 1 : 0);
        std::fprintf(stderr, "SAME_POSITION=%d\n",  samePosition ? 1 : 0);
        std::fprintf(stderr, "SAME_LAYER=%d\n",     sameLayer    ? 1 : 0);
        std::fprintf(stderr, "SAME_STAGE=%d\n",     sameStage    ? 1 : 0);
        std::fprintf(stderr, "SAME_ELEMENTS=%d\n",  sameElements ? 1 : 0);
        std::fprintf(stderr, "SAME_DTYPE=%d\n",     sameDtype    ? 1 : 0);
        std::fprintf(stderr, "INPUTS_POPULATED=%d\n",     presenceOk()  ? 1 : 0);
        std::fprintf(stderr, "INPUTS_NON_VACUOUS=%d\n",   nonVacuous()  ? 1 : 0);
        std::fprintf(stderr, "INPUTS_PROVENANCED=%d\n",   provenanceOk()? 1 : 0);
        std::fprintf(stderr, "COMPARISON_COORDINATES_VALID=%d\n", coordinatesOk() ? 1 : 0);
        std::fprintf(stderr, "COMPARISON_ADMISSIBLE=%d\n", admissible() ? 1 : 0);
        if (!admissible()) {
            std::fprintf(stderr,
                "GATE=%s VERDICT=INVALID_INPUT RESULT_MAY_NOT_EQUAL_PASS=1\n", gate);
        }
    }
};

// ---------------------------------------------------------------------------
// FNV-1a over raw bytes -- for HASH_MATCH without a crypto dependency.
// ---------------------------------------------------------------------------
inline uint64_t fnv1a64(const void* data, size_t bytes, uint64_t seed = 1469598103934665603ULL) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = seed;
    for (size_t i = 0; i < bytes; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

inline uint64_t hashVectorF32(const std::vector<float>& v) {
    return fnv1a64(v.data(), v.size() * sizeof(float));
}

// ---------------------------------------------------------------------------
// Comparison of two measured float vectors.
//
// Hash equality is exact bit identity. Numerical equality is a declared
// threshold, and the threshold is a parameter -- it is fixed BEFORE the run and
// never tuned after seeing the answer.
// ---------------------------------------------------------------------------
struct VectorComparison {
    CompareStatus status = CompareStatus::InvalidInput;
    bool     hashMatch     = false;
    bool     numericalMatch = false;
    double   cosine = 0.0;
    double   rmse   = 0.0;
    double   maxAbs = 0.0;
    double   meanAbs = 0.0;
    double   l2A = 0.0;
    double   l2B = 0.0;
    uint64_t hashA = 0;
    uint64_t hashB = 0;
    size_t   elements = 0;
};

// Declared once, up front. Tuning this after seeing a result converts the gate
// into a description of whatever answer was already obtained.
struct NumericCriterion {
    double minCosine  = 0.9999999;
    double maxRmse    = 1e-3;
    double maxAbsEps  = 1e-4;
};

inline VectorComparison compareVectors(const Measured<std::vector<float>>& A,
                                       const Measured<std::vector<float>>& B,
                                       const NumericCriterion& crit = NumericCriterion{}) {
    VectorComparison r;
    // Input authority FIRST. A comparison is unreachable below this line.
    if (!A.populated || !B.populated) {
        r.status = CompareStatus::InvalidInput;
        return r;
    }
    if (A.value.empty() || B.value.empty()) {
        r.status = CompareStatus::InvalidInput;
        return r;
    }
    if (A.value.size() != B.value.size()) {
        r.status = CompareStatus::NotAdmissible;   // coordinate mismatch
        r.elements = A.value.size();
        return r;
    }

    const std::vector<float>& a = A.value;
    const std::vector<float>& b = B.value;
    r.elements = a.size();
    r.hashA = hashVectorF32(a);
    r.hashB = hashVectorF32(b);
    r.hashMatch = (r.hashA == r.hashB);

    double dot = 0.0, na = 0.0, nb = 0.0, sumAbs = 0.0, sumSq = 0.0;
    bool finite = true;
    for (size_t i = 0; i < a.size(); ++i) {
        const double va = a[i], vb = b[i];
        if (!std::isfinite(va) || !std::isfinite(vb)) { finite = false; break; }
        dot += va * vb;
        na  += va * va;
        nb  += vb * vb;
        const double d = std::fabs(va - vb);
        sumAbs += d;
        if (d > r.maxAbs) r.maxAbs = d;
        sumSq += d * d;
    }
    if (!finite) {
        r.status = CompareStatus::NotAdmissible;   // non-finite: no verdict
        return r;
    }

    r.cosine  = (na > 0.0 && nb > 0.0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
    r.l2A     = std::sqrt(na);
    r.l2B     = std::sqrt(nb);
    r.meanAbs = sumAbs / static_cast<double>(a.size());
    r.rmse    = std::sqrt(sumSq / static_cast<double>(a.size()));

    r.numericalMatch = (r.cosine >= crit.minCosine) &&
                       (r.rmse   <= crit.maxRmse) &&
                       (r.maxAbs <= crit.maxAbsEps);
    r.status = (r.hashMatch || r.numericalMatch) ? CompareStatus::Match
                                                : CompareStatus::Mismatch;
    return r;
}

// ---------------------------------------------------------------------------
// Scalar comparison, same discipline.
// ---------------------------------------------------------------------------
struct ScalarComparison {
    CompareStatus status = CompareStatus::InvalidInput;
    bool     hashMatch = false;
    bool     equal     = false;
    uint64_t hashA = 0, hashB = 0;
    double   deltaAbs = 0.0;
};

inline ScalarComparison compareScalars(const Measured<double>& A,
                                       const Measured<double>& B,
                                       double eps = 0.0) {
    ScalarComparison r;
    if (!A.populated || !B.populated) { r.status = CompareStatus::InvalidInput; return r; }
    r.hashA = fnv1a64(&A.value, sizeof(double));
    r.hashB = fnv1a64(&B.value, sizeof(double));
    r.hashMatch = (r.hashA == r.hashB);
    r.deltaAbs  = std::fabs(A.value - B.value);
    r.equal     = (r.deltaAbs <= eps);
    r.status    = r.equal ? CompareStatus::Match : CompareStatus::Mismatch;
    return r;
}

// ---------------------------------------------------------------------------
// Conservation -- catches an aggregator that did not consume what it was fed.
//
// A min/mean/max that silently saw fewer values than were produced is the same
// defect class as an unpopulated comparison operand: the report is confident
// and wrong. So the counts are checked explicitly.
// ---------------------------------------------------------------------------
struct Conservation {
    size_t expected   = 0;  // values the producer says it emitted
    size_t observed   = 0;  // values the consumer says it saw
    size_t consumed   = 0;  // values that actually entered the aggregation

    bool ok() const { return expected > 0 && expected == observed && observed == consumed; }

    void print(const char* label) const {
        std::fprintf(stderr, "%s_EXPECTED_VALUES=%zu\n", label, expected);
        std::fprintf(stderr, "%s_OBSERVED_VALUES=%zu\n", label, observed);
        std::fprintf(stderr, "%s_CONSUMED_BY_AGGREGATOR=%zu\n", label, consumed);
        std::fprintf(stderr, "%s_INPUT_CONSERVATION=%s\n", label, ok() ? "PASS" : "FAIL");
    }
};

} // namespace rawrxd::authority
