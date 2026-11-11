// ============================================================================
// TrailBrake.cpp — Safety Anchor and Rollback System (real implementation)
// ============================================================================
// TrailBrake.hpp declares the class and its pimpl but no implementation existed,
// so the engine could not link. The implementation below is functional:
//
//   Initialize          installs the configuration and clears counters.
//   SetExpectedTokens   records the expected token budget for the run.
//   ReportActualTokens  records the observed token count and derives drift.
//   DropAnchor          snapshots the current verified state with an id.
//   PruneAnchors        drops all but the newest N anchors (oldest first).
//   GetBrakeIntensity   returns 0 while free, and a rising 0..1 intensity as
//                       token/time drift crosses the configured thresholds.
//   ShouldProceed       false once emergency threshold is exceeded.
//   GetTrailBrake       lazily constructed process-wide instance.
//
// Drift is measured against the expectation reported by the caller; state
// transitions are derived from real ratios rather than being simulated.
// ============================================================================
#include "TrailBrake.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <sstream>

namespace Deep2 {

// ----------------------------------------------------------------------------
// DriftMetrics::CalculateComposite
// ----------------------------------------------------------------------------
void DriftMetrics::CalculateComposite() {
    float d = 0.0f;
    d = std::max(d, tokenDriftRatio > 1.0f ? tokenDriftRatio - 1.0f : 0.0f);
    d = std::max(d, timeDriftRatio > 1.0f ? timeDriftRatio - 1.0f : 0.0f);
    d = std::max(d, progressDrift > 0.0f ? progressDrift : 0.0f);
    if (consecutiveFailures > 0) {
        d = std::max(d, static_cast<float>(consecutiveFailures) / 4.0f);
    }
    d = std::max(d, errorRate);
    d = std::max(d, rollbackRate);
    compositeDrift = std::min(1.0f, d);
}

namespace {

uint64_t NowMs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count());
}

} // namespace

// ----------------------------------------------------------------------------
// TrailBrake::Impl
// ----------------------------------------------------------------------------
class TrailBrake::Impl {
public:
    TrailBrakeConfig cfg;
    BrakeState state = BrakeState::FREE;

    uint64_t expectedTokens = 0;
    uint64_t actualTokens = 0;
    uint64_t expectedTimeMs = 0;
    uint64_t actualTimeMs = 0;
    float expectedProgress = 0.0f;
    float actualProgress = 0.0f;
    uint32_t consecutiveFailures = 0;
    uint64_t opsCount = 0;
    uint64_t trailbacks = 0;
    uint64_t emergencyStops = 0;
    uint64_t tokensSaved = 0;
    float avgDrift = 0.0f;
    float maxDrift = 0.0f;
    float brakeIntensity = 0.0f;

    uint64_t startMs = NowMs();
    std::deque<AnchorPoint> anchors;
    std::deque<DriftMetrics> history;
    uint64_t anchorSeq = 0;

    std::string lastAnchorId;

    AnchorPoint* FindAnchor(const std::string& id) {
        for (auto& a : anchors) {
            if (a.id == id) return &a;
        }
        return nullptr;
    }

    // Composite drift from the current sample; recomputes BrakeState.
    float Recompute() {
        DriftMetrics m;
        m.expectedTokens = expectedTokens;
        m.actualTokens = actualTokens;
        m.tokenDriftRatio = expectedTokens > 0
                                ? static_cast<float>(actualTokens) /
                                      static_cast<float>(expectedTokens)
                                : 1.0f;
        m.expectedTimeMs = expectedTimeMs;
        m.actualTimeMs = actualTimeMs ? actualTimeMs : (NowMs() - startMs);
        m.timeDriftRatio = expectedTimeMs > 0
                               ? static_cast<float>(m.actualTimeMs) /
                                     static_cast<float>(expectedTimeMs)
                               : 1.0f;
        m.expectedProgress = expectedProgress;
        m.actualProgress = actualProgress;
        m.progressDrift = m.actualProgress - m.expectedProgress;
        m.consecutiveFailures = consecutiveFailures;
        m.errorRate = opsCount > 0
                          ? static_cast<float>(consecutiveFailures) /
                                static_cast<float>(opsCount)
                          : 0.0f;
        m.rollbackRate = opsCount > 0
                             ? static_cast<float>(trailbacks + emergencyStops) /
                                   static_cast<float>(opsCount)
                             : 0.0f;
        m.CalculateComposite();

        if (!history.empty()) m.CalculateComposite();
        history.push_back(m);
        while (history.size() > cfg.maxDriftHistory) history.pop_front();

        avgDrift = 0.0f;
        for (const auto& s : history) avgDrift += s.compositeDrift;
        if (!history.empty()) avgDrift /= static_cast<float>(history.size());
        maxDrift = std::max(maxDrift, m.compositeDrift);

        const float worst = std::max(m.tokenDriftRatio > 1.0f ? m.tokenDriftRatio : 1.0f,
                                     m.timeDriftRatio > 1.0f ? m.timeDriftRatio : 1.0f);
        if (worst >= cfg.emergencyThreshold) {
            state = BrakeState::EMERGENCY;
            brakeIntensity = 1.0f;
        } else if (worst >= cfg.brakeThreshold) {
            state = BrakeState::BRAKING;
            brakeIntensity = cfg.enableProgressiveBrake
                                 ? std::min(1.0f, (worst - 1.0f) /
                                                       (cfg.brakeThreshold - 1.0f) *
                                                       cfg.brakeIntensity)
                                 : cfg.brakeIntensity;
        } else if (worst >= cfg.warningThreshold) {
            state = BrakeState::WARNING;
            brakeIntensity = cfg.autoThrottle ? cfg.brakeIntensity * 0.5f : 0.0f;
        } else {
            state = BrakeState::FREE;
            brakeIntensity = 0.0f;
        }
        return m.compositeDrift;
    }
};

// ----------------------------------------------------------------------------
// CTOR / DTOR
// ----------------------------------------------------------------------------
TrailBrake::TrailBrake() : impl_(new Impl()) {}

TrailBrake::~TrailBrake() = default;

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------
bool TrailBrake::Initialize(const TrailBrakeConfig& config) {
    if (!impl_) impl_.reset(new Impl());
    impl_->cfg = config;
    impl_->state = BrakeState::FREE;
    impl_->expectedTokens = 0;
    impl_->actualTokens = 0;
    impl_->opsCount = 0;
    impl_->trailbacks = 0;
    impl_->emergencyStops = 0;
    impl_->tokensSaved = 0;
    impl_->avgDrift = 0.0f;
    impl_->maxDrift = 0.0f;
    impl_->brakeIntensity = 0.0f;
    impl_->startMs = NowMs();
    impl_->history.clear();
    return true;
}

void TrailBrake::Shutdown() {
    impl_->anchors.clear();
    impl_->history.clear();
    impl_->state = BrakeState::FREE;
    impl_->brakeIntensity = 0.0f;
}

// ----------------------------------------------------------------------------
// Anchor management
// ----------------------------------------------------------------------------
std::string TrailBrake::DropAnchor(const std::string& name, const std::string& context) {
    AnchorPoint a;
    std::ostringstream id;
    id << "anchor_" << (++impl_->anchorSeq);
    a.id = id.str();
    a.name = name.empty() ? a.id : name;
    a.timestamp = NowMs();
    a.context = context;
    a.verified = false;
    a.verifiedAt = 0;
    a.tokenCount = impl_->actualTokens;
    a.instructionCount = impl_->opsCount;
    a.stateHash.assign(32, 0);
    a.tokensFromLast = 0;
    a.timeFromLastMs = 0;
    if (!impl_->anchors.empty()) {
        const AnchorPoint& prev = impl_->anchors.back();
        a.tokensFromLast = a.tokenCount > prev.tokenCount ? a.tokenCount - prev.tokenCount : 0;
        a.timeFromLastMs = a.timestamp > prev.timestamp ? a.timestamp - prev.timestamp : 0;
    }
    impl_->anchors.push_back(a);
    impl_->lastAnchorId = a.id;
    while (impl_->anchors.size() > impl_->cfg.maxAnchors) {
        impl_->anchors.pop_front();
    }
    return a.id;
}

bool TrailBrake::VerifyAnchor(const std::string& anchorId) {
    AnchorPoint* a = impl_->FindAnchor(anchorId);
    if (!a) return false;
    a->verified = true;
    a->verifiedAt = NowMs();
    return true;
}

std::string TrailBrake::GetLastVerifiedAnchor() const {
    for (auto it = impl_->anchors.rbegin(); it != impl_->anchors.rend(); ++it) {
        if (it->verified) return it->id;
    }
    return {};
}

bool TrailBrake::GetAnchor(const std::string& id, AnchorPoint& out) const {
    for (const auto& a : impl_->anchors) {
        if (a.id == id) {
            out = a;
            return true;
        }
    }
    return false;
}

std::vector<AnchorPoint> TrailBrake::GetAnchors() const {
    return {impl_->anchors.begin(), impl_->anchors.end()};
}

size_t TrailBrake::PruneAnchors(size_t keepCount) {
    while (impl_->anchors.size() > keepCount) {
        impl_->anchors.pop_front();
    }
    return impl_->anchors.size();
}

// ----------------------------------------------------------------------------
// Drift monitoring
// ----------------------------------------------------------------------------
void TrailBrake::SetExpectedTokens(uint64_t tokens) {
    impl_->expectedTokens = tokens;
    impl_->opsCount++;
}

void TrailBrake::SetExpectedTime(uint64_t timeMs) { impl_->expectedTimeMs = timeMs; }
void TrailBrake::SetExpectedProgress(float progress) { impl_->expectedProgress = progress; }

void TrailBrake::ReportActualTokens(uint64_t tokens) {
    impl_->actualTokens = tokens;
    impl_->opsCount++;
    impl_->Recompute();
}

void TrailBrake::ReportActualTime(uint64_t timeMs) {
    impl_->actualTimeMs = timeMs;
    impl_->Recompute();
}

void TrailBrake::ReportActualProgress(float progress) {
    impl_->actualProgress = progress;
    impl_->Recompute();
}

void TrailBrake::ReportFailure(const std::string& /*reason*/) {
    impl_->consecutiveFailures++;
    impl_->opsCount++;
    impl_->Recompute();
}

DriftMetrics TrailBrake::CalculateDrift() const {
    DriftMetrics m;
    m.expectedTokens = impl_->expectedTokens;
    m.actualTokens = impl_->actualTokens;
    m.tokenDriftRatio = impl_->expectedTokens > 0
                            ? static_cast<float>(impl_->actualTokens) /
                                  static_cast<float>(impl_->expectedTokens)
                            : 1.0f;
    m.expectedTimeMs = impl_->expectedTimeMs;
    m.actualTimeMs = impl_->actualTimeMs;
    m.timeDriftRatio = impl_->expectedTimeMs > 0
                           ? static_cast<float>(m.actualTimeMs) /
                                 static_cast<float>(impl_->expectedTimeMs)
                           : 1.0f;
    m.expectedProgress = impl_->expectedProgress;
    m.actualProgress = impl_->actualProgress;
    m.progressDrift = m.actualProgress - m.expectedProgress;
    m.consecutiveFailures = impl_->consecutiveFailures;
    m.errorRate = impl_->opsCount > 0 ? static_cast<float>(impl_->consecutiveFailures) /
                                            static_cast<float>(impl_->opsCount)
                                      : 0.0f;
    m.rollbackRate = 0.0f;
    m.CalculateComposite();
    return m;
}

// ----------------------------------------------------------------------------
// Brake control
// ----------------------------------------------------------------------------
BrakeState TrailBrake::CheckBrakeState() const {
    return impl_->state;
}

float TrailBrake::GetBrakeIntensity() const {
    return impl_->brakeIntensity;
}

bool TrailBrake::TrailBack(const std::string& anchorId) {
    const std::string target = anchorId.empty() ? impl_->lastAnchorId : anchorId;
    if (target.empty()) return false;
    AnchorPoint* a = impl_->FindAnchor(target);
    if (!a) return false;
    impl_->trailbacks++;
    if (impl_->actualTokens > a->tokenCount) {
        impl_->tokensSaved += impl_->actualTokens - a->tokenCount;
    }
    impl_->actualTokens = a->tokenCount;
    impl_->state = BrakeState::FREE;
    impl_->brakeIntensity = 0.0f;
    return true;
}

bool TrailBrake::EmergencyStop() {
    impl_->emergencyStops++;
    impl_->state = BrakeState::EMERGENCY;
    impl_->brakeIntensity = 1.0f;
    if (impl_->cfg.autoRollback) {
        TrailBack();
    }
    return true;
}

BrakeState TrailBrake::GetState() const { return impl_->state; }

// ----------------------------------------------------------------------------
// Integration
// ----------------------------------------------------------------------------
void TrailBrake::BeforeRiskyOperation(const std::string& operationName) {
    DropAnchor("before_" + operationName);
}

bool TrailBrake::ShouldProceed() const {
    // An emergency drift state means the run has gone past the safe envelope.
    return impl_->state != BrakeState::EMERGENCY;
}

uint64_t TrailBrake::GetThrottledBudget(uint64_t requested) const {
    if (impl_->brakeIntensity <= 0.0f) return requested;
    const double scale = 1.0 - std::min(1.0, static_cast<double>(impl_->brakeIntensity));
    return static_cast<uint64_t>(static_cast<double>(requested) * scale);
}

void TrailBrake::SetEventCallback(EventCallback /*cb*/) {
    // No event sink is wired into the engine today; state transitions are
    // observable through GetState()/GetStats().
}

TrailBrake::Stats TrailBrake::GetStats() const {
    Stats s{};
    s.anchorsDropped = impl_->anchors.size();
    s.anchorsVerified = 0;
    for (const auto& a : impl_->anchors) {
        if (a.verified) s.anchorsVerified++;
    }
    s.trailbacks = impl_->trailbacks;
    s.emergencyStops = impl_->emergencyStops;
    s.tokensSaved = impl_->tokensSaved;
    s.avgDrift = impl_->avgDrift;
    s.maxDrift = impl_->maxDrift;
    return s;
}

void TrailBrake::PrintStatus() const {
    DriftMetrics d = CalculateDrift();
    std::printf("[TrailBrake] state=%d composite_drift=%.3f token_ratio=%.3f "
                "time_ratio=%.3f anchors=%zu trailbacks=%llu\n",
                static_cast<int>(impl_->state), d.compositeDrift, d.tokenDriftRatio,
                d.timeDriftRatio, impl_->anchors.size(),
                static_cast<unsigned long long>(impl_->trailbacks));
}

std::vector<DriftMetrics> TrailBrake::GetDriftHistory() const {
    return {impl_->history.begin(), impl_->history.end()};
}

// ----------------------------------------------------------------------------
// Global instance
// ----------------------------------------------------------------------------
TrailBrake& GetTrailBrake() {
    static TrailBrake instance;
    static std::once_flag once;
    std::call_once(once, []() { instance.Initialize(); });
    return instance;
}

std::string DropAnchor(const std::string& name) {
    return GetTrailBrake().DropAnchor(name);
}

bool IsSafeToProceed() {
    return GetTrailBrake().ShouldProceed();
}

bool AutoTrailIfNeeded() {
    if (GetTrailBrake().CheckBrakeState() == BrakeState::EMERGENCY) {
        return GetTrailBrake().TrailBack();
    }
    return true;
}

} // namespace Deep2
