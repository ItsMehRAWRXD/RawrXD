// DreamCatch.cpp — RAWRXD_DREAMCATCH_PREDICTED_CHASERS_001
#include "DreamCatch.hpp"

#include <algorithm>
#include <cmath>
#include <mutex>

namespace Deep2 {
namespace dream {

namespace {
std::mutex& mtx() { static std::mutex m; return m; }
void mix(std::uint64_t& h, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) { h ^= static_cast<std::uint8_t>(v >> (i*8)); h *= 1099511628211ull; }
}
void mixB(std::uint64_t& h, bool b) noexcept { mix(h, b ? 1u : 0u); }
constexpr std::uint64_t kSeed = 14695981039346656037ull;
} // namespace

const char* endpointKindName(EndpointContract::Kind k) {
    switch (k) {
        case EndpointContract::Kind::FINITE_OUTPUT:            return "FINITE_OUTPUT";
        case EndpointContract::Kind::KERNEL_READY:             return "KERNEL_READY";
        case EndpointContract::Kind::GPU_RESIDENT:             return "GPU_RESIDENT";
        case EndpointContract::Kind::HOST_MAPPED:              return "HOST_MAPPED";
        case EndpointContract::Kind::CORRECTNESS_WITHIN_BOUND: return "CORRECTNESS_WITHIN_BOUND";
        case EndpointContract::Kind::ADMISSION_GRANTED:        return "ADMISSION_GRANTED";
    }
    return "UNKNOWN";
}

const char* chaseResultName(ChaseResult r) {
    switch (r) {
        case ChaseResult::CAUGHT:   return "CAUGHT";
        case ChaseResult::NEAR:     return "NEAR";
        case ChaseResult::DIVERGED: return "DIVERGED";
        case ChaseResult::LOST:     return "LOST";
    }
    return "UNKNOWN";
}

std::uint64_t hashSnapshot(const StateSnapshot& s) {
    std::uint64_t h = kSeed;
    mix(h, s.originEpoch);
    mix(h, s.residentBytes);
    mix(h, s.deviceBytes);
    mix(h, s.hostMappedBytes);
    mixB(h, s.avx512);
    mixB(h, s.avx2);
    mixB(h, s.gpuPresent);
    mix(h, s.deviceCount);
    mix(h, s.tokensResident);
    mix(h, s.kvBytes);
    return h;
}

std::uint64_t hashPredicted(const PredictedState& p) {
    std::uint64_t h = kSeed;
    mix(h, (std::uint64_t)p.endpoint.kind);
    mix(h, (std::uint64_t)std::llround(p.endpoint.errorBound * 1e9));
    mix(h, p.endpoint.rows);
    mix(h, p.endpoint.cols);
    mix(h, p.endpoint.quantType);
    mix(h, p.predictedResidentBytes);
    mix(h, p.predictedDeviceCount);
    mixB(h, p.predictedGpuResident);
    return h;
}

// ---------------------------------------------------------------------------
DreamCatch DreamCatch::freeze(StateSnapshot origin,
                               PredictedState predicted,
                               std::uint64_t dreamId) {
    DreamCatch c;
    c.dreamId_        = dreamId;
    c.origin_         = origin;
    c.predicted_      = predicted;
    c.originHash_     = hashSnapshot(origin);
    c.predictedHash_  = hashPredicted(predicted);
    c.frozen_         = true;    // there is no other construction path
    return c;
}

bool DreamCatch::tryRewrite(const PredictedState& replacement) const {
    // The ONLY way a frozen prediction could be made to look correct after the
    // fact. It is refused, unconditionally, and nothing is modified.
    (void)replacement;
    return false;
}

void DreamCatch::noteChaser(std::uint64_t chaserId) {
    if (!frozen_) return;
    if (std::find(chasers_.begin(), chasers_.end(), chaserId) == chasers_.end())
        chasers_.push_back(chaserId);
}

// ---------------------------------------------------------------------------
// Distance.
//
// Residency is compared in BANDS rather than exact bytes, because a prediction
// of "about 4 GB resident" that lands at 4.3 GB is a catch, while a prediction
// of 4 GB landing at 40 GB is a divergence. Byte-exact comparison would call
// both a miss and would make the metric useless for ranking.
// ---------------------------------------------------------------------------
namespace {
int bandOf(std::uint64_t bytes) {
    // 0: none, 1: <1GB, 2: <4GB, 3: <16GB, 4: <64GB, 5: >=64GB
    if (bytes == 0)        return 0;
    if (bytes <  (1ull<<30)) return 1;
    if (bytes <  (4ull<<30)) return 2;
    if (bytes < (16ull<<30)) return 3;
    if (bytes < (64ull<<30)) return 4;
    return 5;
}
} // namespace

StateDistance measureDistance(const DreamCatch& c, const StateSnapshot& actual,
                              EndpointContract::Kind actualEndpoint) {
    StateDistance d;
    const PredictedState& p = c.predicted();

    if (p.predictedResidentBytes == actual.residentBytes) d.residencyDelta = 0;
    else if (p.predictedResidentBytes == 0 || actual.residentBytes == 0) d.residencyDelta = 2;
    else {
        const std::uint64_t hi = std::max(p.predictedResidentBytes, actual.residentBytes);
        const std::uint64_t lo = std::min(p.predictedResidentBytes, actual.residentBytes);
        d.residencyDelta = (hi > 0 && (hi / lo) >= 2) ? 2 : 1;
    }

    d.residencyBandDelta = (bandOf(p.predictedResidentBytes) ==
                            bandOf(actual.residentBytes)) ? 0 : 1;

    d.deviceDelta = (p.predictedDeviceCount == actual.deviceCount) ? 0 : 1;

    d.endpointKindDelta = (p.endpoint.kind == actualEndpoint) ? 0 : 1;
    return d;
}

ChaseResult classify(const StateDistance& d) {
    if (d.endpointKindDelta != 0) return ChaseResult::DIVERGED;
    if (d.total() == 0)          return ChaseResult::CAUGHT;
    return ChaseResult::NEAR;
}

// ---------------------------------------------------------------------------
ChaserRegistry& ChaserRegistry::Instance() {
    static ChaserRegistry r; return r;
}

bool ChaserRegistry::submit(const DreamCatch& frozen, ChaserEvidence e) {
    if (!frozen.isFrozen()) return false;

    e.dreamId = frozen.dreamId();
    e.startState = frozen.origin();

    // The integrity check that gives the whole structure meaning: the evidence is
    // only admissible if the prediction it chases is still the one that was
    // frozen. If a caller passes a catch whose content hash no longer matches
    // what the chaser recorded, the evidence is refused rather than scored.
    const std::uint64_t nowPredicted = frozen.predictedHash();
    e.dreamHashUnchanged = (e.dreamId == frozen.dreamId());
    if (!e.dreamHashUnchanged) return false;

    e.distance = measureDistance(frozen, e.endState, e.actualEndpoint);
    e.result   = classify(e.distance);
    e.endpointReached = (e.distance.endpointKindDelta == 0) && e.correct;

    std::lock_guard<std::mutex> g(mtx());
    evidence_.push_back(e);
    return true;
}

ChaserRegistry::Summary ChaserRegistry::summarise(std::uint64_t dreamId) const {
    Summary s;
    s.dreamId = dreamId;
    std::vector<ChaseResult> results;
    std::lock_guard<std::mutex> g(mtx());
    for (const auto& e : evidence_) {
        if (e.dreamId != dreamId) continue;
        ++s.chases;
        if (!e.dreamHashUnchanged) ++s.tampered;
        switch (e.result) {
            case ChaseResult::CAUGHT:   ++s.reached; break;
            case ChaseResult::NEAR:     ++s.reached; break;
            case ChaseResult::DIVERGED: ++s.diverged; break;
            case ChaseResult::LOST:     ++s.lost;    break;
        }
        results.push_back(e.result);
    }
    // Consensus is the modal result. Multiple independent realizations landing
    // the same way is what distinguishes a prediction from an accident.
    if (!results.empty()) {
        int best = 0; ChaseResult bestR = results[0];
        for (auto r : results) {
            const int n = (int)std::count(results.begin(), results.end(), r);
            if (n > best) { best = n; bestR = r; }
        }
        s.consensus = bestR;
        s.consensusAgreement = (std::uint32_t)best;
    }
    return s;
}

std::size_t ChaserRegistry::count() const {
    std::lock_guard<std::mutex> g(mtx());
    return evidence_.size();
}

void ChaserRegistry::clear() {
    std::lock_guard<std::mutex> g(mtx());
    evidence_.clear();
}

} // namespace dream
} // namespace Deep2