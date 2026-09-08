// ============================================================================
// CycloneScheduler.cpp
// Implementation of temporal prediction + deadline-driven prefetch
// ============================================================================

#include "CycloneScheduler.hpp"
#include "ElasticResidencyManager.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {

static uint64_t CycloneNowUs() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// ============================================================================
// CyclonePredictionEngine
// ============================================================================

void CyclonePredictionEngine::RecordLayerExecution(uint32_t layerIndex, uint64_t latencyUs) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& pattern = layerPatterns_[layerIndex];
    pattern.layerIndex = layerIndex;
    pattern.hitCount++;
    // Exponential moving average
    const float alpha = 0.1f;
    pattern.avgLatencyUs = alpha * (float)latencyUs + (1.0f - alpha) * pattern.avgLatencyUs;
    totalSequences_++;
}

void CyclonePredictionEngine::RecordExpertActivation(uint32_t layerIndex, uint32_t expertIndex) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& experts = expertPatterns_[layerIndex];
    auto it = std::find_if(experts.begin(), experts.end(),
        [expertIndex](const ExpertPattern& p) { return p.expertIndex == expertIndex; });
    if (it != experts.end()) {
        it->activationCount++;
    } else {
        ExpertPattern p;
        p.expertIndex = expertIndex;
        p.activationCount = 1;
        experts.push_back(p);
    }
    // Normalize frequencies
    uint32_t total = 0;
    for (auto& e : experts) total += e.activationCount;
    for (auto& e : experts) e.frequency = (float)e.activationCount / (float)total;
}

void CyclonePredictionEngine::RecordPrefetchOutcome(uint32_t layerIndex, bool hit) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& pattern = layerPatterns_[layerIndex];
    if (hit) pattern.hitCount++;
    else pattern.missCount++;
}

std::vector<TensorDemand> CyclonePredictionEngine::PredictNextLayer(
    uint32_t currentLayer,
    uint64_t currentSequence,
    uint64_t deadlineTicks) {

    std::vector<TensorDemand> demands;
    std::lock_guard<std::mutex> lock(mutex_);

    uint32_t nextLayer = currentLayer + 1;
    auto it = layerPatterns_.find(nextLayer);
    float confidence = (it != layerPatterns_.end()) ?
        std::min(1.0f, (float)it->second.hitCount /
                       (float)(it->second.hitCount + it->second.missCount + 1)) : 0.5f;

    // K2 / DeepSeek2 MLA names (legacy attn_q/ffn_* never hit Elastic on stream)
    const char* suffixes[] = {
        "attn_q_a.weight", "attn_q_b.weight", "attn_kv_a_mqa.weight",
        "attn_kv_b.weight", "attn_output.weight",
        "attn_norm.weight", "attn_q_a_norm.weight"
    };
    for (const char* suf : suffixes) {
        TensorDemand d;
        char name[96];
        std::snprintf(name, sizeof(name), "blk.%u.%s", nextLayer, suf);
        d.tensorName = name;
        d.layerIndex = nextLayer;
        d.expertIndex = ~0u;
        d.predictedSequenceNumber = currentSequence + 1;
        d.deadlineTicks = deadlineTicks;
        d.priority = 64;
        d.predictionConfidence = confidence;
        d.fromRouter = false;
        demands.push_back(d);
    }

    return demands;
}

std::vector<TensorDemand> CyclonePredictionEngine::PredictExperts(
    uint32_t layerIndex,
    const float* routerLogits,
    uint32_t numExperts,
    uint64_t currentSequence,
    uint64_t deadlineTicks) {

    std::vector<TensorDemand> demands;
    if (!routerLogits || numExperts == 0) return demands;

    // Find top-K experts by logit
    struct ExpertScore { uint32_t idx; float score; };
    std::vector<ExpertScore> scores;
    scores.reserve(numExperts);
    for (uint32_t i = 0; i < numExperts; i++) {
        scores.push_back({i, routerLogits[i]});
    }
    std::partial_sort(scores.begin(),
                      scores.begin() + std::min((size_t)3, scores.size()),
                      scores.end(),
                      [](const ExpertScore& a, const ExpertScore& b) {
                          return a.score > b.score;
                      });

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = expertPatterns_.find(layerIndex);

    for (size_t i = 0; i < std::min((size_t)3, scores.size()); i++) {
        float confidence = std::min(1.0f, scores[i].score);  // sigmoid would be better
        float historical = 0.0f;
        if (it != expertPatterns_.end()) {
            auto eit = std::find_if(it->second.begin(), it->second.end(),
                [&scores, i](const ExpertPattern& p) { return p.expertIndex == scores[i].idx; });
            if (eit != it->second.end()) historical = eit->frequency;
        }
        // Blend router confidence with historical frequency
        float blended = 0.7f * confidence + 0.3f * historical;

        TensorDemand d;
        char name[96];
        // Expert tensors: blk.L.ffn_gate_exps.<expert>
        std::snprintf(name, sizeof(name), "blk.%u.ffn_gate_exps.%u",
                      layerIndex, scores[i].idx);
        d.tensorName = name;
        d.layerIndex = layerIndex;
        d.expertIndex = scores[i].idx;
        d.predictedSequenceNumber = currentSequence;
        d.deadlineTicks = deadlineTicks;
        d.priority = (i == 0) ? 32 : 96;  // top expert = urgent, others = speculative
        d.predictionConfidence = blended;
        d.fromRouter = true;
        demands.push_back(d);
    }

    return demands;
}

float CyclonePredictionEngine::GetLayerConfidence(uint32_t layerIndex) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = layerPatterns_.find(layerIndex);
    if (it == layerPatterns_.end()) return 0.0f;
    uint32_t total = it->second.hitCount + it->second.missCount;
    return total > 0 ? (float)it->second.hitCount / (float)total : 0.0f;
}

float CyclonePredictionEngine::GetExpertConfidence(uint32_t expertIndex) const {
    // Simplified: global expert confidence
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t totalActivations = 0;
    uint32_t targetActivations = 0;
    for (const auto& [layer, experts] : expertPatterns_) {
        for (const auto& e : experts) {
            totalActivations += e.activationCount;
            if (e.expertIndex == expertIndex) targetActivations += e.activationCount;
        }
    }
    return totalActivations > 0 ? (float)targetActivations / (float)totalActivations : 0.0f;
}

void CyclonePredictionEngine::ResetPatterns() {
    std::lock_guard<std::mutex> lock(mutex_);
    layerPatterns_.clear();
    expertPatterns_.clear();
    totalSequences_ = 0;
}

// ============================================================================
// CycloneScheduler
// ============================================================================

CycloneScheduler::CycloneScheduler(const Config& config)
    : config_(config)
    , predictor_(std::make_unique<CyclonePredictionEngine>()) {
    for (size_t i = 0; i < static_cast<size_t>(BraidLane::Count); i++) {
        laneEnabled_[i].store(true);
    }
}

CycloneScheduler::~CycloneScheduler() {
    Shutdown();
}

bool CycloneScheduler::Initialize(ElasticResidencyManager* elastic) {
    elastic_ = elastic;
    running_ = true;
    schedulerThread_ = std::thread(&CycloneScheduler::SchedulerLoop, this);
    if (config_.enableTelemetry) {
        telemetryThread_ = std::thread(&CycloneScheduler::TelemetryLoop, this);
    }
    return true;
}

void CycloneScheduler::RebindElastic(ElasticResidencyManager* elastic) {
    elastic_ = elastic;
}

void CycloneScheduler::Shutdown() {
    running_ = false;
    if (schedulerThread_.joinable()) schedulerThread_.join();
    if (telemetryThread_.joinable()) telemetryThread_.join();
}

// ------------------------------------------------------------------------
// Deep2 Forward Pass Integration
// ------------------------------------------------------------------------

void CycloneScheduler::OnLayerStart(uint32_t layerIndex,
                                     uint64_t sequenceNumber,
                                     const float* routerLogits,
                                     uint32_t numExperts) {
    currentLayer_.store(layerIndex);
    currentSequence_.store(sequenceNumber);

    // Predict next layer
    auto nextLayerDemands = predictor_->PredictNextLayer(
        layerIndex, sequenceNumber, config_.defaultDeadlineTicks);

    // Predict experts if MoE
    std::vector<TensorDemand> expertDemands;
    if (config_.enableMoEPrefetch && routerLogits && numExperts > 0) {
        expertDemands = predictor_->PredictExperts(
            layerIndex, routerLogits, numExperts,
            sequenceNumber, config_.defaultDeadlineTicks);
    }

    // Enqueue all demands
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        for (auto& d : nextLayerDemands) {
            QueuedDemand qd;
            qd.demand = d;
            qd.enqueueSequence = sequenceNumber;
            qd.enqueueTimeUs = CycloneNowUs();
            prefetchQueue_.push_back(qd);
        }
        for (auto& d : expertDemands) {
            if (d.predictionConfidence < config_.minPrefetchConfidence) continue;
            QueuedDemand qd;
            qd.demand = d;
            qd.enqueueSequence = sequenceNumber;
            qd.enqueueTimeUs = CycloneNowUs();
            prefetchQueue_.push_back(qd);
        }
    }

    accum_.demandsIssued += (uint64_t)nextLayerDemands.size() + (uint64_t)expertDemands.size();

    // Live generate: pump prefetch immediately so cyclone affects residency
    // order on this request — not only the 1ms background scheduler loop.
    ProcessPrefetchQueue();
}

void CycloneScheduler::OnLayerComplete(uint32_t layerIndex,
                                        uint64_t sequenceNumber,
                                        uint64_t computeLatencyUs) {
    predictor_->RecordLayerExecution(layerIndex, computeLatencyUs);

    // Retire demands that were satisfied
    {
        std::lock_guard<std::mutex> lock(activeMutex_);
        for (auto it = activeDemands_.begin(); it != activeDemands_.end();) {
            if (it->second <= sequenceNumber) {
                it = activeDemands_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void CycloneScheduler::OnTensorUsed(const std::string& tensorName,
                                     uint64_t sequenceNumber) {
    currentSequence_.store(sequenceNumber);
    if (!elastic_ || tensorName.empty()) return;
    ElasticResidencyManager::ResidencyHandle handle;
    (void)elastic_->AcquireTensor(tensorName, 200, 0, handle);
}

// ------------------------------------------------------------------------
// Explicit Demand API
// ------------------------------------------------------------------------

bool CycloneScheduler::AcquireTensorNow(const std::string& tensorName,
                                         uint32_t layerIndex,
                                         uint32_t expertIndex) {
    if (!elastic_) return false;
    (void)layerIndex;
    (void)expertIndex;

    ElasticResidencyManager::ResidencyHandle handle;
    auto st = elastic_->AcquireTensor(
        tensorName, 0, config_.urgentDeadlineTicks, handle);
    if (st == ElasticResidencyManager::AcquireStatus::Ready && handle.ready) {
        accum_.demandsSatisfied++;
        return true;
    }
    if (st == ElasticResidencyManager::AcquireStatus::DeadlineMiss)
        accum_.demandsMissed++;
    return false;
}

void CycloneScheduler::PrefetchTensor(const std::string& tensorName,
                                         uint32_t layerIndex,
                                         uint32_t expertIndex,
                                         uint64_t deadlineTicks,
                                         float confidence) {
    if (!elastic_) return;
    if (confidence < config_.minPrefetchConfidence) return;

    TensorDemand d;
    d.tensorName = tensorName;
    d.layerIndex = layerIndex;
    d.expertIndex = expertIndex;
    d.deadlineTicks = deadlineTicks;
    d.priority = 128;
    d.predictionConfidence = confidence;
    d.fromRouter = false;

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        QueuedDemand qd;
        qd.demand = d;
        qd.enqueueSequence = currentSequence_.load();
        qd.enqueueTimeUs = 0;
        prefetchQueue_.push_back(qd);
    }

    accum_.prefetchesIssued++;
}

void CycloneScheduler::ReleaseTensor(const std::string& tensorName) {
    if (!elastic_) return;
    elastic_->ReleaseTensor(tensorName);
}

// ------------------------------------------------------------------------
// Braid Control
// ------------------------------------------------------------------------

void CycloneScheduler::EnableLane(BraidLane lane) {
    laneEnabled_[static_cast<size_t>(lane)].store(true);
}

void CycloneScheduler::DisableLane(BraidLane lane) {
    laneEnabled_[static_cast<size_t>(lane)].store(false);
}

bool CycloneScheduler::IsLaneEnabled(BraidLane lane) const {
    return laneEnabled_[static_cast<size_t>(lane)].load();
}

// ------------------------------------------------------------------------
// Telemetry
// ------------------------------------------------------------------------

CycloneScheduler::TelemetrySnapshot CycloneScheduler::GetTelemetry() const {
    TelemetrySnapshot snap;
    snap.timestampUs = CycloneNowUs();
    snap.currentLayer = currentLayer_.load();
    snap.currentSequence = currentSequence_.load();

    snap.demandsIssued = accum_.demandsIssued.load();
    snap.demandsSatisfied = accum_.demandsSatisfied.load();
    snap.demandsMissed = accum_.demandsMissed.load();
    snap.demandsDropped = accum_.demandsDropped.load();

    snap.prefetchesIssued = accum_.prefetchesIssued.load();
    snap.prefetchHits = accum_.prefetchHits.load();
    snap.prefetchMisses = accum_.prefetchMisses.load();

    uint64_t totalPrefetches = snap.prefetchHits + snap.prefetchMisses;
    snap.prefetchHitRate = totalPrefetches > 0 ?
        (double)snap.prefetchHits / (double)totalPrefetches : 0.0;

    uint64_t totalDemands = snap.demandsSatisfied + snap.demandsMissed;
    snap.avgDemandLatencyUs = totalDemands > 0 ?
        (double)accum_.totalDemandLatencyUs.load() / (double)totalDemands : 0.0;
    snap.maxDemandLatencyUs = (double)accum_.maxDemandLatencyUs.load();

    for (size_t i = 0; i < static_cast<size_t>(BraidLane::Count); i++) {
        snap.laneUtilization[i] = laneTelemetry_[i].Utilization();
        snap.activeCyclesTotal += laneTelemetry_[i].cyclesActive.load();
        snap.stallCyclesTotal += laneTelemetry_[i].cyclesStalled.load();
    }
    snap.queuePeak = queuePeak_.load();
    return snap;
}

void CycloneScheduler::ResetTelemetry() {
    accum_.demandsIssued = 0;
    accum_.demandsSatisfied = 0;
    accum_.demandsMissed = 0;
    accum_.demandsDropped = 0;
    accum_.prefetchesIssued = 0;
    accum_.prefetchHits = 0;
    accum_.prefetchMisses = 0;
    accum_.totalDemandLatencyUs = 0;
    accum_.maxDemandLatencyUs = 0;
    for (auto& lt : laneTelemetry_) lt.Reset();
}

// ------------------------------------------------------------------------
// Internal Callbacks
// ------------------------------------------------------------------------

void CycloneScheduler::OnTransferComplete(const std::string& tensorName,
                                           uint64_t completionSequence) {
    accum_.demandsSatisfied++;
    uint64_t now = CycloneNowUs();
    uint64_t dt = (now > completionSequence) ? (now - completionSequence) : 0;
    accum_.totalDemandLatencyUs += dt;
    uint64_t mx = accum_.maxDemandLatencyUs.load();
    while (dt > mx && !accum_.maxDemandLatencyUs.compare_exchange_weak(mx, dt)) {}
    (void)tensorName;
}

void CycloneScheduler::OnTransferFailed(const std::string& tensorName,
                                         uint64_t sequenceNumber) {
    accum_.demandsMissed++;
}

// ------------------------------------------------------------------------
// Internal Loops
// ------------------------------------------------------------------------

void CycloneScheduler::SchedulerLoop() {
    while (running_) {
        ProcessDemandQueue();
        ProcessPrefetchQueue();
        UpdateLaneStates();
        {
            const char* tick = std::getenv("CYCLONE_FIXED_TICK");
            if (tick && tick[0] == '1')
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            else
                std::this_thread::yield();
        }
    }
}

void CycloneScheduler::TelemetryLoop() {
    while (running_) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.telemetrySampleIntervalMs));
        // Telemetry is polled via GetTelemetry(), not pushed
    }
}

void CycloneScheduler::ProcessDemandQueue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    {
        const uint32_t q = (uint32_t)(urgentQueue_.size() + prefetchQueue_.size());
        uint32_t cur = queuePeak_.load();
        while (q > cur && !queuePeak_.compare_exchange_weak(cur, q)) {}
    }
    std::sort(urgentQueue_.begin(), urgentQueue_.end(),
        [](const QueuedDemand& a, const QueuedDemand& b) {
            return a.demand.deadlineTicks < b.demand.deadlineTicks;
        });

    size_t issued = 0;
    for (auto& qd : urgentQueue_) {
        if (issued >= 4) break;
        if (ShouldDrop(qd.demand)) {
            accum_.demandsDropped++;
            continue;
        }
        if (!elastic_ || qd.demand.tensorName.empty()) continue;
        ElasticResidencyManager::ResidencyHandle handle;
        auto st = elastic_->AcquireTensor(
            qd.demand.tensorName,
            CalculatePriority(qd.demand),
            qd.demand.deadlineTicks,
            handle);
        if (st == ElasticResidencyManager::AcquireStatus::Ready)
            OnTransferComplete(qd.demand.tensorName, qd.enqueueTimeUs);
        else if (st == ElasticResidencyManager::AcquireStatus::DeadlineMiss ||
                 st == ElasticResidencyManager::AcquireStatus::Failed)
            accum_.demandsMissed++;
        issued++;
    }
    urgentQueue_.clear();
}

void CycloneScheduler::ProcessPrefetchQueue() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    {
        const uint32_t q = (uint32_t)(urgentQueue_.size() + prefetchQueue_.size());
        uint32_t cur = queuePeak_.load();
        while (q > cur && !queuePeak_.compare_exchange_weak(cur, q)) {}
    }
    std::sort(prefetchQueue_.begin(), prefetchQueue_.end(),
        [](const QueuedDemand& a, const QueuedDemand& b) {
            return a.demand.predictionConfidence > b.demand.predictionConfidence;
        });

    size_t issued = 0;
    for (auto& qd : prefetchQueue_) {
        if (issued >= config_.maxConcurrentPrefetches) break;
        if (ShouldDrop(qd.demand)) continue;
        if (!elastic_ || qd.demand.tensorName.empty()) continue;
        ElasticResidencyManager::ResidencyHandle handle;
        auto st = elastic_->AcquireTensor(
            qd.demand.tensorName,
            CalculatePriority(qd.demand),
            qd.demand.deadlineTicks,
            handle);
        if (st == ElasticResidencyManager::AcquireStatus::Ready ||
            st == ElasticResidencyManager::AcquireStatus::Pending) {
            accum_.prefetchHits++;
            if (st == ElasticResidencyManager::AcquireStatus::Ready)
                OnTransferComplete(qd.demand.tensorName, qd.enqueueTimeUs);
        }
        else
            accum_.prefetchMisses++;
        issued++;
    }
    prefetchQueue_.clear();
}

void CycloneScheduler::UpdateLaneStates() {
    for (size_t i = 0; i < static_cast<size_t>(BraidLane::Count); i++) {
        if (laneEnabled_[i].load())
            laneTelemetry_[i].cyclesActive.fetch_add(1, std::memory_order_relaxed);
        else
            laneTelemetry_[i].cyclesStalled.fetch_add(1, std::memory_order_relaxed);
    }
}

uint32_t CycloneScheduler::CalculatePriority(const TensorDemand& demand) const {
    // Lower number = higher priority
    uint32_t base = demand.priority;
    if (demand.fromRouter) base -= 16;  // boost router-confirmed
    if (demand.predictionConfidence > 0.9f) base -= 8;
    return base;
}

bool CycloneScheduler::ShouldDrop(const TensorDemand& demand) const {
    // Drop if deadline already passed
    uint64_t now = currentSequence_.load();
    if (demand.predictedSequenceNumber < now) return true;
    // Drop very low confidence speculative requests under pressure
    if (demand.predictionConfidence < 0.1f && demand.priority > 200) return true;
    return false;
}

} // namespace Deep2
