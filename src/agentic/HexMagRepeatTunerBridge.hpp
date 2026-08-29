#pragma once
// HexMagRepeatTunerBridge.hpp
// C++ ABI bridge for RawrXD_HexMag_RepeatTuner.asm.
// The MASM implementation owns one global state block. HexMagRepeatSession therefore
// holds a process-local mutex for the entire request, enforcing Q_BLOCKING and preventing
// concurrent agent requests from clobbering g_Tuner.

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

namespace rawrxd::agentic::hexmag {

enum Strategy : std::uint32_t {
    HX_STRAT_DIRECT = 0,
    HX_STRAT_DECOMPOSE = 1,
    HX_STRAT_REVERSE = 2,
    HX_STRAT_COUNTEREXAMPLE = 3,
    HX_STRAT_INVARIANT = 4,
    HX_STRAT_REPAIR = 5,
    HX_STRAT_EVIDENCE_GUARD = 6,
};

enum Specialist : std::uint32_t {
    HX_SPEC_GENERALIST = 0,
    HX_SPEC_PLANNER = 1,
    HX_SPEC_FALSIFIER = 2,
    HX_SPEC_BOUNDARY = 3,
    HX_SPEC_CONSISTENCY = 4,
    HX_SPEC_RESOLVER = 5,
    HX_SPEC_ASSUMPTION_BREAKER = 6,
    HX_SPEC_TEST_DRIVEN = 7,
    HX_SPEC_ALT_DERIVATION = 8,
    HX_SPEC_EPISTEMIC = 9,
};

enum Failure : std::uint32_t {
    HX_FAIL_CONTRADICTION = 0x0001u,
    HX_FAIL_COUNTEREXAMPLE = 0x0002u,
    HX_FAIL_UNSUPPORTED = 0x0004u,
    HX_FAIL_TEST = 0x0008u,
    HX_FAIL_STAGNATION = 0x0010u,
    HX_FAIL_MISSING_INFO = 0x0020u,
    HX_FAIL_WRONG = 0x0040u,
};

inline constexpr std::uint32_t HX_QUEUE_Q_BLOCKING = 1u;

struct GenProfile {
    std::uint32_t strategy = 0;
    std::uint32_t specialist = 0;
    std::uint32_t tempMilli = 0;
    std::uint32_t topPMilli = 0;
    std::uint32_t candidateCount = 0;
    std::uint32_t reverseDepth = 0;
    std::uint32_t counterexampleBudget = 0;
    std::uint32_t invariantBudget = 0;
    std::uint32_t blockingPasses = 0;
    std::uint32_t queuePolicy = 0;
    std::uint32_t mutationNonce = 0;
    std::uint32_t pad0 = 0;
};
static_assert(sizeof(GenProfile) == 48, "HX_GEN_PROFILE ABI drift");

extern "C" {
std::uint32_t HexMag_Tuner_Init(std::uint32_t maxAttempts);
std::uint32_t HexMag_Tuner_Reset(std::uint64_t requestIdHash);
std::uint64_t HexMag_Tuner_Initial(std::uint64_t requestIdHash, GenProfile* out);
std::uint64_t HexMag_Tuner_Next(std::uint64_t requestIdHash,
                                std::uint32_t failKindMask,
                                std::uint32_t attempt,
                                GenProfile* out);
std::uint64_t HexMag_Tuner_Fingerprint(const GenProfile* profile);
std::uint64_t HexMag_Tuner_GenerationId();
std::uint32_t HexMag_Tuner_GetProfile(GenProfile* out);
std::uint32_t HexMag_Tuner_WeightDelta();
std::uint32_t HexMag_Tuner_Attempt();
std::uint32_t HexMag_Tuner_Strategy();
}

inline const char* strategyName(std::uint32_t strategy) {
    switch (strategy) {
    case HX_STRAT_DIRECT: return "direct";
    case HX_STRAT_DECOMPOSE: return "decompose";
    case HX_STRAT_REVERSE: return "reverse";
    case HX_STRAT_COUNTEREXAMPLE: return "counterexample";
    case HX_STRAT_INVARIANT: return "invariant";
    case HX_STRAT_REPAIR: return "repair";
    case HX_STRAT_EVIDENCE_GUARD: return "evidence_guard";
    default: return "unknown";
    }
}

inline const char* specialistName(std::uint32_t specialist) {
    switch (specialist) {
    case HX_SPEC_GENERALIST: return "generalist";
    case HX_SPEC_PLANNER: return "planner";
    case HX_SPEC_FALSIFIER: return "falsifier";
    case HX_SPEC_BOUNDARY: return "boundary";
    case HX_SPEC_CONSISTENCY: return "consistency";
    case HX_SPEC_RESOLVER: return "resolver";
    case HX_SPEC_ASSUMPTION_BREAKER: return "assumption_breaker";
    case HX_SPEC_TEST_DRIVEN: return "test_driven";
    case HX_SPEC_ALT_DERIVATION: return "alternate_derivation";
    case HX_SPEC_EPISTEMIC: return "epistemic";
    default: return "unknown";
    }
}

inline std::uint64_t requestHash(std::string_view task) {
    // FNV-1a plus a monotonic salt so identical tasks in the same process are distinct requests.
    std::uint64_t h = 14695981039346656037ull;
    for (unsigned char c : task) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    static std::atomic<std::uint64_t> sequence{1};
    const std::uint64_t salt = sequence.fetch_add(1, std::memory_order_relaxed);
    h ^= salt + 0x9E3779B97F4A7C15ull + (h << 6) + (h >> 2);
    return h ? h : 1ull;
}

inline std::mutex& globalQueueMutex() {
    static std::mutex m;
    return m;
}

class RepeatSession final {
public:
    explicit RepeatSession(std::uint64_t requestIdHash, std::uint32_t maxAttempts = 6)
        : queueLock_(globalQueueMutex()), requestIdHash_(requestIdHash) {
        if (maxAttempts == 0) maxAttempts = 6;
        maxAttempts_ = maxAttempts;
        if (HexMag_Tuner_Init(maxAttempts_) != 0) return;
        fingerprint_ = HexMag_Tuner_Initial(requestIdHash_, &profile_);
        generationId_ = HexMag_Tuner_GenerationId();
        valid_ = fingerprint_ != 0 &&
                 generationId_ != 0 &&
                 profile_.blockingPasses == 3 &&
                 profile_.queuePolicy == HX_QUEUE_Q_BLOCKING &&
                 HexMag_Tuner_WeightDelta() == 0;
    }

    bool valid() const { return valid_; }
    std::uint32_t attempt() const { return attempt_; }
    std::uint32_t maxAttempts() const { return maxAttempts_; }
    std::uint64_t fingerprint() const { return fingerprint_; }
    std::uint64_t generationId() const { return generationId_; }
    const GenProfile& profile() const { return profile_; }

    bool advance(std::uint32_t failureMask) {
        if (!valid_) return false;
        const std::uint64_t oldFingerprint = fingerprint_;
        const std::uint64_t oldGeneration = generationId_;
        ++attempt_;
        fingerprint_ = HexMag_Tuner_Next(requestIdHash_, failureMask, attempt_, &profile_);
        generationId_ = HexMag_Tuner_GenerationId();
        if (fingerprint_ == 0) {
            valid_ = false; // exhausted
            return false;
        }
        const bool invariantOk =
            fingerprint_ != oldFingerprint &&
            generationId_ != oldGeneration &&
            profile_.blockingPasses == 3 &&
            profile_.queuePolicy == HX_QUEUE_Q_BLOCKING &&
            HexMag_Tuner_WeightDelta() == 0;
        valid_ = invariantOk;
        return valid_;
    }

    std::string directive() const {
        std::ostringstream out;
        out << "HEXMAG_REPEAT_PROFILE"
            << " generation_id=0x" << std::hex << generationId_ << std::dec
            << " attempt=" << attempt_
            << " strategy=" << strategyName(profile_.strategy)
            << " specialist=" << specialistName(profile_.specialist)
            << " mutation_nonce=" << profile_.mutationNonce
            << " candidates=" << std::max<std::uint32_t>(1, profile_.candidateCount)
            << " reverse_depth=" << profile_.reverseDepth
            << " counterexample_budget=" << profile_.counterexampleBudget
            << " invariant_budget=" << profile_.invariantBudget
            << " blocking_passes=" << profile_.blockingPasses
            << ". Treat this generation as distinct from every prior attempt. "
               "Do not repeat a rejected answer or identical failed tool call. ";
        switch (profile_.strategy) {
        case HX_STRAT_DECOMPOSE:
            out << "Decompose the problem and solve the smallest verified subproblem first.";
            break;
        case HX_STRAT_REVERSE:
            out << "Work backward from required invariants; actively search for unsupported assumptions.";
            break;
        case HX_STRAT_COUNTEREXAMPLE:
            out << "Try to falsify the current approach with boundary cases before proceeding.";
            break;
        case HX_STRAT_INVARIANT:
            out << "Reconcile contradictions against explicit invariants and tool evidence.";
            break;
        case HX_STRAT_REPAIR:
            out << "Use the failing build/test/tool observation as the authority and make a targeted repair.";
            break;
        case HX_STRAT_EVIDENCE_GUARD:
            out << "Do not invent missing facts. Use only supplied/tool evidence; if evidence is insufficient, say so.";
            break;
        default:
            out << "Proceed directly but ground every factual completion claim in observed evidence.";
            break;
        }
        return out.str();
    }

    float temperature() const { return static_cast<float>(profile_.tempMilli) / 1000.0f; }
    float topP() const { return static_cast<float>(profile_.topPMilli) / 1000.0f; }

private:
    std::unique_lock<std::mutex> queueLock_;
    std::uint64_t requestIdHash_ = 0;
    std::uint32_t maxAttempts_ = 6;
    std::uint32_t attempt_ = 0;
    GenProfile profile_{};
    std::uint64_t fingerprint_ = 0;
    std::uint64_t generationId_ = 0;
    bool valid_ = false;
};

} // namespace rawrxd::agentic::hexmag
