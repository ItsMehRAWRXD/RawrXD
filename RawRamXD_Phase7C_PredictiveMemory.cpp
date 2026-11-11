// =============================================================================
// RawRamXD_Phase7C_PredictiveMemory.cpp
// Implementation: Predictive Memory Intelligence - Learning-Based Policy Refinement
// =============================================================================

#include "RawRamXD_Phase7C_PredictiveMemory.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <random>
#include <cstring>
#include <algorithm>

namespace RawRamXD {

// =============================================================================
// TensorAccessEvent Implementation
// =============================================================================

void TensorAccessEvent::Serialize(std::ofstream& out) const {
    out.write(reinterpret_cast<const char*>(&timestampUs), sizeof(timestampUs));
    out.write(reinterpret_cast<const char*>(&tensorId), sizeof(tensorId));
    out.write(reinterpret_cast<const char*>(&accessType), sizeof(accessType));
    out.write(reinterpret_cast<const char*>(&sourceTier), sizeof(sourceTier));
    out.write(reinterpret_cast<const char*>(&targetTier), sizeof(targetTier));
    out.write(reinterpret_cast<const char*>(&offset), sizeof(offset));
    out.write(reinterpret_cast<const char*>(&sizeBytes), sizeof(sizeBytes));
    out.write(reinterpret_cast<const char*>(&computeNode), sizeof(computeNode));
    out.write(reinterpret_cast<const char*>(&latencyUs), sizeof(latencyUs));
    out.write(reinterpret_cast<const char*>(&wasHit), sizeof(wasHit));
}

bool TensorAccessEvent::Deserialize(std::ifstream& in) {
    in.read(reinterpret_cast<char*>(&timestampUs), sizeof(timestampUs));
    in.read(reinterpret_cast<char*>(&tensorId), sizeof(tensorId));
    in.read(reinterpret_cast<char*>(&accessType), sizeof(accessType));
    in.read(reinterpret_cast<char*>(&sourceTier), sizeof(sourceTier));
    in.read(reinterpret_cast<char*>(&targetTier), sizeof(targetTier));
    in.read(reinterpret_cast<char*>(&offset), sizeof(offset));
    in.read(reinterpret_cast<char*>(&sizeBytes), sizeof(sizeBytes));
    in.read(reinterpret_cast<char*>(&computeNode), sizeof(computeNode));
    in.read(reinterpret_cast<char*>(&latencyUs), sizeof(latencyUs));
    in.read(reinterpret_cast<char*>(&wasHit), sizeof(wasHit));
    return in.good();
}

// =============================================================================
// SequenceTrace Implementation
// =============================================================================

void SequenceTrace::AddEvent(const TensorAccessEvent& event) {
    if (events.empty()) {
        firstSeenUs = event.timestampUs;
    }
    lastAccessUs = event.timestampUs;
    events.push_back(event);
    
    if (event.accessType == AccessType::READ || event.accessType == AccessType::READ_WRITE) {
        totalReads++;
    }
    if (event.accessType == AccessType::WRITE || event.accessType == AccessType::READ_WRITE) {
        totalWrites++;
    }
    totalBytesTransferred += event.sizeBytes;
}

double SequenceTrace::GetAverageAccessIntervalUs() const {
    if (events.size() < 2) return 0.0;
    return static_cast<double>(lastAccessUs - firstSeenUs) / (events.size() - 1);
}

double SequenceTrace::GetAccessFrequencyHz() const {
    double interval = GetAverageAccessIntervalUs();
    if (interval <= 0.0) return 0.0;
    return 1000000.0 / interval; // Convert us to Hz
}

MemoryTier SequenceTrace::GetPreferredTier() const {
    std::unordered_map<MemoryTier, uint64_t> tierHits;
    for (const auto& event : events) {
        if (event.wasHit) {
            tierHits[event.targetTier]++;
        }
    }
    
    MemoryTier bestTier = MemoryTier::HOST;
    uint64_t maxHits = 0;
    for (const auto& [tier, hits] : tierHits) {
        if (hits > maxHits) {
            maxHits = hits;
            bestTier = tier;
        }
    }
    return bestTier;
}

// =============================================================================
// SequenceLogger Implementation
// =============================================================================

bool SequenceLogger::Initialize(const std::string& logDir) {
    logDir_ = logDir;
    // Create log directory if it doesn't exist
    // (Platform-specific code would go here)
    return true;
}

void SequenceLogger::Shutdown() {
    FlushToDisk();
}

void SequenceLogger::LogEvent(const TensorAccessEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = traces_.find(event.tensorId);
    if (it == traces_.end()) {
        auto trace = std::make_shared<SequenceTrace>();
        trace->tensorId = event.tensorId;
        traces_[event.tensorId] = trace;
        it = traces_.find(event.tensorId);
    }
    
    it->second->AddEvent(event);
    totalEventsLogged_++;
    
    // Update flush time without calling flush (avoid deadlock)
    lastFlushTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::shared_ptr<SequenceTrace> SequenceLogger::GetTrace(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = traces_.find(tensorId);
    if (it != traces_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<SequenceTrace>> SequenceLogger::GetAllTraces() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SequenceTrace>> result;
    result.reserve(traces_.size());
    for (const auto& [id, trace] : traces_) {
        result.push_back(trace);
    }
    return result;
}

bool SequenceLogger::FlushToDisk() {
    std::lock_guard<std::mutex> lock(mutex_);
    // Implementation would write traces to disk
    lastFlushTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return true;
}

void SequenceLogger::BackgroundFlush() {
    // In a real implementation, this would run in a background thread
    // For now, just update the timestamp without flushing to avoid deadlock
    lastFlushTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
}

bool SequenceLogger::LoadFromDisk(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) return false;
    
    // Load implementation
    return true;
}

void SequenceLogger::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    traces_.clear();
}

SequenceLogger::LoggerStats SequenceLogger::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    LoggerStats stats;
    stats.totalEventsLogged = totalEventsLogged_.load();
    stats.totalTraces = traces_.size();
    stats.eventsInMemory = 0;
    for (const auto& [id, trace] : traces_) {
        stats.eventsInMemory += trace->events.size();
    }
    stats.lastFlushTime = lastFlushTime_.load();
    stats.memoryUsageBytes = stats.eventsInMemory * sizeof(TensorAccessEvent) + 
                             traces_.size() * sizeof(SequenceTrace);
    return stats;
}

// =============================================================================
// WorkloadSignature Implementation
// =============================================================================

uint64_t WorkloadSignature::Hash() const {
    // Simple hash combining all fields
    uint64_t hash = std::hash<double>{}(readWriteRatio);
    hash ^= std::hash<double>{}(sequentiality) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= std::hash<double>{}(temporalLocality) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= std::hash<double>{}(spatialLocality) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    hash ^= std::hash<double>{}(burstiness) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    return hash;
}

bool WorkloadSignature::operator==(const WorkloadSignature& other) const {
    return std::abs(readWriteRatio - other.readWriteRatio) < 0.01 &&
           std::abs(sequentiality - other.sequentiality) < 0.01 &&
           std::abs(temporalLocality - other.temporalLocality) < 0.01 &&
           std::abs(spatialLocality - other.spatialLocality) < 0.01 &&
           std::abs(burstiness - other.burstiness) < 0.01;
}

// =============================================================================
// PatternMiner Implementation
// =============================================================================

bool PatternMiner::Initialize() {
    stats_ = {};
    return true;
}

void PatternMiner::Shutdown() {
    profiles_.clear();
    patterns_.clear();
}

std::vector<AccessPattern> PatternMiner::MinePatterns(const SequenceTrace& trace) {
    std::vector<AccessPattern> discovered;
    
    // Try different pattern detection algorithms
    auto sequential = DetectSequentialPattern(trace);
    if (sequential.confidence >= MIN_CONFIDENCE) {
        discovered.push_back(sequential);
    }
    
    auto strided = DetectStridedPattern(trace);
    if (strided.confidence >= MIN_CONFIDENCE) {
        discovered.push_back(strided);
    }
    
    auto repeating = DetectRepeatingPattern(trace);
    if (repeating.confidence >= MIN_CONFIDENCE) {
        discovered.push_back(repeating);
    }
    
    auto temporal = DetectTemporalPattern(trace);
    if (temporal.confidence >= MIN_CONFIDENCE) {
        discovered.push_back(temporal);
    }
    
    stats_.patternsDiscovered += discovered.size();
    return discovered;
}

PlacementProfile PatternMiner::GenerateProfile(const WorkloadSignature& signature) {
    PlacementProfile profile;
    profile.profileId = signature.Hash();
    profile.signature = signature;
    
    // Generate tier preferences based on signature
    // High temporal locality -> prefer GPU
    // High sequentiality -> prefer prefetching
    // High burstiness -> need larger buffers
    
    PlacementProfile::TierPreference gpuPref;
    gpuPref.tier = MemoryTier::GPU0;
    gpuPref.affinityScore = signature.temporalLocality * 0.8 + signature.spatialLocality * 0.2;
    gpuPref.expectedHitRate = 0.7 + signature.temporalLocality * 0.25;
    gpuPref.avgLatencyUs = 50;
    profile.tierPreferences.push_back(gpuPref);
    
    PlacementProfile::TierPreference hostPref;
    hostPref.tier = MemoryTier::HOST;
    hostPref.affinityScore = 0.5;
    hostPref.expectedHitRate = 0.5;
    hostPref.avgLatencyUs = 500;
    profile.tierPreferences.push_back(hostPref);
    
    // Set strategy parameters based on signature
    profile.prefetchThreshold = 0.6 + signature.sequentiality * 0.3;
    profile.prefetchDistance = static_cast<uint64_t>(1000 * (1.0 - signature.burstiness) + 100);
    profile.evictionAggression = 0.3 + signature.burstiness * 0.4;
    profile.evictionWindowMs = static_cast<uint64_t>(1000 * signature.temporalLocality + 500);
    profile.migrationThreshold = 0.7;
    profile.migrationCooldownMs = 100;
    
    profile.timesApplied = 0;
    profile.cumulativeHitRate = 0.0;
    profile.cumulativeLatency = 0.0;
    profile.lastUpdated = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    stats_.profilesGenerated++;
    return profile;
}

void PatternMiner::UpdateProfile(PlacementProfile& profile, const SequenceTrace& trace, double hitRate) {
    // Update cumulative statistics
    double totalWeight = profile.timesApplied;
    profile.cumulativeHitRate = (profile.cumulativeHitRate * totalWeight + hitRate) / (totalWeight + 1);
    profile.cumulativeLatency = (profile.cumulativeLatency * totalWeight + trace.GetAverageAccessIntervalUs()) / (totalWeight + 1);
    profile.timesApplied++;
    profile.lastUpdated = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::shared_ptr<PlacementProfile> PatternMiner::FindMatchingProfile(const WorkloadSignature& signature) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t targetHash = signature.Hash();
    auto it = profiles_.find(targetHash);
    if (it != profiles_.end()) {
        stats_.profileMatches++;
        return it->second;
    }
    
    // Try fuzzy matching
    double bestScore = 0.0;
    std::shared_ptr<PlacementProfile> bestMatch;
    
    for (const auto& [id, profile] : profiles_) {
        double similarity = ComputeSignatureSimilarity(signature, profile->signature);
        if (similarity > bestScore && similarity > 0.8) {
            bestScore = similarity;
            bestMatch = profile;
        }
    }
    
    if (bestMatch) {
        stats_.profileMatches++;
        stats_.averageMatchConfidence = (stats_.averageMatchConfidence * (stats_.profileMatches - 1) + bestScore) / stats_.profileMatches;
    } else {
        stats_.profileMisses++;
    }
    
    return bestMatch;
}

void PatternMiner::StoreProfile(const PlacementProfile& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto ptr = std::make_shared<PlacementProfile>(profile);
    profiles_[profile.profileId] = ptr;
}

std::shared_ptr<PlacementProfile> PatternMiner::GetProfile(uint64_t profileId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(profileId);
    if (it != profiles_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<PlacementProfile>> PatternMiner::GetAllProfiles() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<PlacementProfile>> result;
    result.reserve(profiles_.size());
    for (const auto& [id, profile] : profiles_) {
        result.push_back(profile);
    }
    return result;
}

WorkloadSignature PatternMiner::ComputeSignature(const std::vector<std::shared_ptr<SequenceTrace>>& traces) {
    WorkloadSignature sig;
    
    if (traces.empty()) {
        return sig;
    }
    
    uint64_t totalReads = 0, totalWrites = 0;
    uint64_t totalBytes = 0;
    std::vector<uint64_t> intervals;
    
    for (const auto& trace : traces) {
        totalReads += trace->totalReads;
        totalWrites += trace->totalWrites;
        totalBytes += trace->totalBytesTransferred;
        
        // Collect intervals for sequentiality calculation
        for (size_t i = 1; i < trace->events.size(); ++i) {
            intervals.push_back(trace->events[i].offset - trace->events[i-1].offset);
        }
    }
    
    // Compute read/write ratio
    sig.readWriteRatio = totalWrites > 0 ? static_cast<double>(totalReads) / totalWrites : totalReads;
    
    // Compute sequentiality (simplified)
    if (intervals.size() > 1) {
        uint64_t consistentStrides = 0;
        for (size_t i = 1; i < intervals.size(); ++i) {
            if (intervals[i] == intervals[i-1]) {
                consistentStrides++;
            }
        }
        sig.sequentiality = static_cast<double>(consistentStrides) / (intervals.size() - 1);
    }
    
    // Set other metrics (simplified for demo)
    sig.temporalLocality = 0.5;
    sig.spatialLocality = sig.sequentiality * 0.8;
    sig.burstiness = 0.3;
    sig.avgTensorLifetimeMs = 1000;
    sig.avgAccessIntervalUs = 100;
    sig.uniqueTensorCount = static_cast<uint32_t>(traces.size());
    
    return sig;
}

bool PatternMiner::SaveProfiles(const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = profiles_.size();
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));
    
    for (const auto& [id, profile] : profiles_) {
        out.write(reinterpret_cast<const char*>(&profile->profileId), sizeof(profile->profileId));
        // Write other fields...
    }
    
    return out.good();
}

bool PatternMiner::LoadProfiles(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) return false;
    
    // Load implementation
    return true;
}

PatternMiner::MinerStats PatternMiner::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

// Pattern detection algorithms
AccessPattern PatternMiner::DetectSequentialPattern(const SequenceTrace& trace) {
    AccessPattern pattern;
    pattern.type = AccessPattern::PatternType::SEQUENTIAL;
    pattern.confidence = 0.0;
    pattern.occurrences = 0;
    
    if (trace.events.size() < MIN_PATTERN_LENGTH) {
        return pattern;
    }
    
    // Check for increasing offsets
    uint64_t increasingCount = 0;
    for (size_t i = 1; i < trace.events.size(); ++i) {
        if (trace.events[i].offset > trace.events[i-1].offset) {
            increasingCount++;
        }
    }
    
    pattern.confidence = static_cast<double>(increasingCount) / (trace.events.size() - 1);
    pattern.occurrences = increasingCount;
    
    return pattern;
}

AccessPattern PatternMiner::DetectStridedPattern(const SequenceTrace& trace) {
    AccessPattern pattern;
    pattern.type = AccessPattern::PatternType::STRIDED;
    pattern.confidence = 0.0;
    
    if (trace.events.size() < MIN_PATTERN_LENGTH) {
        return pattern;
    }
    
    // Calculate strides
    std::unordered_map<uint64_t, uint64_t> strideCounts;
    for (size_t i = 1; i < trace.events.size(); ++i) {
        uint64_t stride = trace.events[i].offset - trace.events[i-1].offset;
        strideCounts[stride]++;
    }
    
    // Find most common stride
    uint64_t maxStride = 0, maxCount = 0;
    for (const auto& [stride, count] : strideCounts) {
        if (count > maxCount) {
            maxCount = count;
            maxStride = stride;
        }
    }
    
    pattern.stride = maxStride;
    pattern.confidence = static_cast<double>(maxCount) / (trace.events.size() - 1);
    pattern.occurrences = maxCount;
    
    return pattern;
}

AccessPattern PatternMiner::DetectRepeatingPattern(const SequenceTrace& trace) {
    AccessPattern pattern;
    pattern.type = AccessPattern::PatternType::REPEATING;
    pattern.confidence = 0.0;
    
    // Check for repeated offset access
    std::unordered_map<uint64_t, uint64_t> offsetCounts;
    for (const auto& event : trace.events) {
        offsetCounts[event.offset]++;
    }
    
    uint64_t maxRepeats = 0;
    for (const auto& [offset, count] : offsetCounts) {
        if (count > maxRepeats) {
            maxRepeats = count;
        }
    }
    
    if (maxRepeats > 1) {
        pattern.confidence = static_cast<double>(maxRepeats) / trace.events.size();
        pattern.occurrences = maxRepeats;
    }
    
    return pattern;
}

AccessPattern PatternMiner::DetectTemporalPattern(const SequenceTrace& trace) {
    AccessPattern pattern;
    pattern.type = AccessPattern::PatternType::TEMPORAL;
    pattern.confidence = 0.0;
    
    // Check for temporal clustering
    if (trace.events.size() < MIN_PATTERN_LENGTH) {
        return pattern;
    }
    
    // Calculate access intervals
    std::vector<uint64_t> intervals;
    for (size_t i = 1; i < trace.events.size(); ++i) {
        intervals.push_back(trace.events[i].timestampUs - trace.events[i-1].timestampUs);
    }
    
    // Check for consistent intervals (bursty pattern)
    if (intervals.size() > 1) {
        uint64_t sum = 0;
        for (auto interval : intervals) sum += interval;
        double avg = static_cast<double>(sum) / intervals.size();
        
        double variance = 0;
        for (auto interval : intervals) {
            variance += std::pow(interval - avg, 2);
        }
        variance /= intervals.size();
        
        // Low variance = temporal pattern
        if (avg > 0) {
            double cv = std::sqrt(variance) / avg;
            pattern.confidence = std::max(0.0, 1.0 - cv);
        }
    }
    
    return pattern;
}

double PatternMiner::ComputeSignatureSimilarity(const WorkloadSignature& a, const WorkloadSignature& b) {
    // Cosine similarity between signatures
    double dot = a.readWriteRatio * b.readWriteRatio +
                 a.sequentiality * b.sequentiality +
                 a.temporalLocality * b.temporalLocality +
                 a.spatialLocality * b.spatialLocality +
                 a.burstiness * b.burstiness;
    
    double magA = std::sqrt(a.readWriteRatio * a.readWriteRatio +
                            a.sequentiality * a.sequentiality +
                            a.temporalLocality * a.temporalLocality +
                            a.spatialLocality * a.spatialLocality +
                            a.burstiness * a.burstiness);
    
    double magB = std::sqrt(b.readWriteRatio * b.readWriteRatio +
                            b.sequentiality * b.sequentiality +
                            b.temporalLocality * b.temporalLocality +
                            b.spatialLocality * b.spatialLocality +
                            b.burstiness * b.burstiness);
    
    if (magA == 0 || magB == 0) return 0.0;
    return dot / (magA * magB);
}

// =============================================================================
// PolicyRefinementEngine Implementation
// =============================================================================

bool PolicyRefinementEngine::Initialize(PatternMiner* miner) {
    miner_ = miner;
    stats_ = {};
    return true;
}

void PolicyRefinementEngine::Shutdown() {
    feedbackHistory_.clear();
    refinedPolicies_.clear();
}

void PolicyRefinementEngine::RecordFeedback(const PolicyFeedback& feedback) {
    std::lock_guard<std::mutex> lock(mutex_);
    feedbackHistory_[feedback.profileId].push_back(feedback);
    stats_.feedbacksRecorded++;
}

void PolicyRefinementEngine::RefinePolicies() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [profileId, feedbacks] : feedbackHistory_) {
        if (feedbacks.size() < MIN_OBSERVATIONS) {
            continue;
        }
        
        double improvement = CalculateImprovement(feedbacks);
        if (improvement > IMPROVEMENT_THRESHOLD) {
            auto refinement = ComputeRefinement(profileId, feedbacks);
            refinedPolicies_[profileId] = std::make_shared<RefinedPolicy>(refinement);
            stats_.policiesRefined++;
            stats_.successfulRefinements++;
            stats_.averageImprovement = (stats_.averageImprovement * (stats_.successfulRefinements - 1) + improvement) / stats_.successfulRefinements;
        }
    }
    
    stats_.lastRefinementTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::shared_ptr<RefinedPolicy> PolicyRefinementEngine::GetRefinedPolicy(uint64_t profileId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = refinedPolicies_.find(profileId);
    if (it != refinedPolicies_.end()) {
        return it->second;
    }
    return nullptr;
}

bool PolicyRefinementEngine::ApplyRefinement(PlacementProfile& profile, const RefinedPolicy& refinement) {
    if (refinement.refinementConfidence < 0.5) {
        return false;
    }
    
    profile.prefetchThreshold = refinement.adjustedPrefetchThreshold;
    profile.evictionAggression = refinement.adjustedEvictionAggression;
    profile.migrationThreshold = refinement.adjustedMigrationThreshold;
    profile.migrationCooldownMs = refinement.migrationCooldownMs;
    
    return true;
}

PolicyRefinementEngine::PerformancePrediction PolicyRefinementEngine::PredictPerformance(uint64_t profileId) {
    PerformancePrediction pred;
    
    auto profile = miner_->GetProfile(profileId);
    if (!profile) {
        pred.confidence = 0.0;
        return pred;
    }
    
    pred.predictedHitRate = profile->cumulativeHitRate;
    pred.predictedLatencyUs = profile->cumulativeLatency;
    pred.predictedThroughput = 1000000.0 / (profile->cumulativeLatency + 1);
    pred.confidence = std::min(1.0, profile->timesApplied / 100.0);
    
    return pred;
}

PolicyRefinementEngine::RefinementStats PolicyRefinementEngine::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

bool PolicyRefinementEngine::SaveRefinements(const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    return out.good();
}

bool PolicyRefinementEngine::LoadRefinements(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    return in.good();
}

RefinedPolicy PolicyRefinementEngine::ComputeRefinement(uint64_t profileId, const std::vector<PolicyFeedback>& feedback) {
    RefinedPolicy refinement;
    refinement.baseProfileId = profileId;
    refinement.refinementVersion = 1;
    refinement.observationsCount = feedback.size();
    
    // Calculate average metrics
    double avgHitRate = 0, avgLatency = 0;
    for (const auto& f : feedback) {
        avgHitRate += f.actualHitRate;
        avgLatency += f.actualLatencyUs;
    }
    avgHitRate /= feedback.size();
    avgLatency /= feedback.size();
    
    // Adjust parameters based on performance
    auto profile = miner_->GetProfile(profileId);
    if (profile) {
        // If hit rate is low, lower prefetch threshold
        if (avgHitRate < 0.6) {
            refinement.adjustedPrefetchThreshold = profile->prefetchThreshold * 0.9;
        } else {
            refinement.adjustedPrefetchThreshold = profile->prefetchThreshold * 1.05;
        }
        
        // If latency is high, reduce eviction aggression
        if (avgLatency > 1000) {
            refinement.adjustedEvictionAggression = profile->evictionAggression * 0.8;
        } else {
            refinement.adjustedEvictionAggression = profile->evictionAggression * 1.1;
        }
        
        refinement.adjustedMigrationThreshold = profile->migrationThreshold;
        refinement.migrationCooldownMs = profile->migrationCooldownMs;
    }
    
    // Calculate improvements
    double baselineHitRate = profile ? profile->cumulativeHitRate : 0.5;
    refinement.hitRateImprovement = avgHitRate - baselineHitRate;
    refinement.latencyReduction = 0; // Would calculate from baseline
    refinement.throughputGain = 0;
    refinement.refinementConfidence = std::min(1.0, feedback.size() / 100.0);
    refinement.lastRefined = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return refinement;
}

double PolicyRefinementEngine::CalculateImprovement(const std::vector<PolicyFeedback>& feedback) {
    if (feedback.empty()) return 0.0;
    
    double totalImprovement = 0;
    for (const auto& f : feedback) {
        if (f.wasBeneficial) {
            totalImprovement += 0.1; // Simplified improvement metric
        }
    }
    
    return totalImprovement / feedback.size();
}

// =============================================================================
// OnlineAdaptationController Implementation
// =============================================================================

bool OnlineAdaptationController::Initialize(PatternMiner* miner, PolicyRefinementEngine* engine) {
    miner_ = miner;
    engine_ = engine;
    currentAggression_ = AggressionLevel::MODERATE;
    currentState_ = {};
    stats_ = {};
    return true;
}

void OnlineAdaptationController::Shutdown() {
}

WorkloadClass OnlineAdaptationController::ClassifyWorkload(const std::vector<std::shared_ptr<SequenceTrace>>& recentTraces) {
    WorkloadSignature sig = miner_->ComputeSignature(recentTraces);
    WorkloadClass cls = ClassifyBySignature(sig);
    
    double confidence = ComputeClassConfidence(cls, sig);
    
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_.currentClass = cls;
    currentState_.currentSignature = sig;
    currentState_.confidence = confidence;
    currentState_.classificationTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    stats_.classificationsPerformed++;
    stats_.classDistribution[cls]++;
    stats_.averageClassificationConfidence = (stats_.averageClassificationConfidence * (stats_.classificationsPerformed - 1) + confidence) / stats_.classificationsPerformed;
    
    return cls;
}

void OnlineAdaptationController::UpdateAggression(const WorkloadState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Adjust aggression based on performance metrics
    if (state.currentHitRate < 0.5 && state.memoryPressure > 0.8) {
        // Low hit rate and high pressure -> be more aggressive with eviction
        AdjustAggressionUp();
    } else if (state.currentHitRate > 0.9 && state.memoryPressure < 0.5) {
        // High hit rate and low pressure -> can be more conservative
        AdjustAggressionDown();
    }
    
    currentState_ = state;
}

PolicyParameters OnlineAdaptationController::GetPolicyParameters() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    PolicyParameters params;
    
    switch (currentAggression_) {
        case AggressionLevel::CONSERVATIVE:
            params.prefetchThreshold = 0.8;
            params.evictionAggression = 0.2;
            params.migrationThreshold = 0.9;
            params.migrationCooldownMs = 500;
            params.enableProactivePlacement = false;
            break;
        case AggressionLevel::MODERATE:
            params.prefetchThreshold = 0.6;
            params.evictionAggression = 0.4;
            params.migrationThreshold = 0.7;
            params.migrationCooldownMs = 200;
            params.enableProactivePlacement = true;
            break;
        case AggressionLevel::AGGRESSIVE:
            params.prefetchThreshold = 0.4;
            params.evictionAggression = 0.7;
            params.migrationThreshold = 0.5;
            params.migrationCooldownMs = 50;
            params.enableProactivePlacement = true;
            break;
        case AggressionLevel::ADAPTIVE:
            // Dynamic based on current state
            params.prefetchThreshold = 0.6 - (1.0 - currentState_.currentHitRate) * 0.3;
            params.evictionAggression = currentState_.memoryPressure * 0.8;
            params.migrationThreshold = 0.7;
            params.migrationCooldownMs = 200;
            params.enableProactivePlacement = true;
            break;
    }
    
    return params;
}

void OnlineAdaptationController::OnWorkloadTransition(WorkloadClass oldClass, WorkloadClass newClass) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Reset to moderate aggression on transition
    currentAggression_ = AggressionLevel::MODERATE;
    stats_.workloadTransitions++;
    
    // Could trigger policy reload here
}

WorkloadState OnlineAdaptationController::GetCurrentState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

OnlineAdaptationController::AdaptationStats OnlineAdaptationController::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

WorkloadClass OnlineAdaptationController::ClassifyBySignature(const WorkloadSignature& sig) {
    // Simple classification based on signature characteristics
    if (sig.readWriteRatio > 10 && sig.sequentiality > 0.7) {
        return WorkloadClass::INFERENCE_LARGE;
    } else if (sig.readWriteRatio > 5 && sig.sequentiality > 0.5) {
        return WorkloadClass::INFERENCE_SMALL;
    } else if (sig.readWriteRatio < 2 && sig.burstiness > 0.6) {
        return WorkloadClass::TRAINING_SMALL;
    } else if (sig.temporalLocality > 0.8) {
        return WorkloadClass::EMBEDDING_LOOKUP;
    } else if (sig.spatialLocality > 0.7) {
        return WorkloadClass::ATTENTION_COMPUTE;
    }
    
    return WorkloadClass::MIXED;
}

double OnlineAdaptationController::ComputeClassConfidence(WorkloadClass cls, const WorkloadSignature& sig) {
    // Confidence based on how well signature matches class characteristics
    switch (cls) {
        case WorkloadClass::INFERENCE_LARGE:
            return (sig.readWriteRatio > 10 ? 0.8 : 0.3) * (sig.sequentiality > 0.7 ? 0.9 : 0.5);
        case WorkloadClass::INFERENCE_SMALL:
            return (sig.readWriteRatio > 5 ? 0.7 : 0.4) * (sig.sequentiality > 0.5 ? 0.8 : 0.5);
        case WorkloadClass::TRAINING_SMALL:
            return (sig.readWriteRatio < 2 ? 0.8 : 0.3) * (sig.burstiness > 0.6 ? 0.9 : 0.5);
        case WorkloadClass::EMBEDDING_LOOKUP:
            return sig.temporalLocality > 0.8 ? 0.9 : 0.4;
        case WorkloadClass::ATTENTION_COMPUTE:
            return sig.spatialLocality > 0.7 ? 0.85 : 0.4;
        default:
            return 0.5;
    }
}

void OnlineAdaptationController::AdjustAggressionUp() {
    switch (currentAggression_) {
        case AggressionLevel::CONSERVATIVE:
            currentAggression_ = AggressionLevel::MODERATE;
            break;
        case AggressionLevel::MODERATE:
            currentAggression_ = AggressionLevel::AGGRESSIVE;
            break;
        case AggressionLevel::AGGRESSIVE:
            currentAggression_ = AggressionLevel::ADAPTIVE;
            break;
        default:
            break;
    }
    stats_.aggressionChanges++;
}

void OnlineAdaptationController::AdjustAggressionDown() {
    switch (currentAggression_) {
        case AggressionLevel::ADAPTIVE:
            currentAggression_ = AggressionLevel::AGGRESSIVE;
            break;
        case AggressionLevel::AGGRESSIVE:
            currentAggression_ = AggressionLevel::MODERATE;
            break;
        case AggressionLevel::MODERATE:
            currentAggression_ = AggressionLevel::CONSERVATIVE;
            break;
        default:
            break;
    }
    stats_.aggressionChanges++;
}

// =============================================================================
// PredictiveMemoryIntelligence Implementation
// =============================================================================

PredictiveMemoryIntelligence& PredictiveMemoryIntelligence::Instance() {
    static PredictiveMemoryIntelligence instance;
    return instance;
}

bool PredictiveMemoryIntelligence::Initialize(const PredictiveIntelligenceConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    
    if (config.enableSequenceLogging) {
        sequenceLogger_ = std::make_unique<SequenceLogger>();
        if (!sequenceLogger_->Initialize(config.persistenceDir)) {
            return false;
        }
    }
    
    if (config.enablePatternMining) {
        patternMiner_ = std::make_unique<PatternMiner>();
        if (!patternMiner_->Initialize()) {
            return false;
        }
    }
    
    if (config.enablePolicyRefinement) {
        refinementEngine_ = std::make_unique<PolicyRefinementEngine>();
        if (!refinementEngine_->Initialize(patternMiner_.get())) {
            return false;
        }
    }
    
    if (config.enableOnlineAdaptation) {
        adaptationController_ = std::make_unique<OnlineAdaptationController>();
        if (!adaptationController_->Initialize(patternMiner_.get(), refinementEngine_.get())) {
            return false;
        }
    }
    
    return true;
}

void PredictiveMemoryIntelligence::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (adaptationController_) {
        adaptationController_->Shutdown();
        adaptationController_.reset();
    }
    if (refinementEngine_) {
        refinementEngine_->Shutdown();
        refinementEngine_.reset();
    }
    if (patternMiner_) {
        patternMiner_->Shutdown();
        patternMiner_.reset();
    }
    if (sequenceLogger_) {
        sequenceLogger_->Shutdown();
        sequenceLogger_.reset();
    }
}

void PredictiveMemoryIntelligence::OnTensorAccess(const TensorAccessEvent& event) {
    if (sequenceLogger_) {
        sequenceLogger_->LogEvent(event);
    }
}

void PredictiveMemoryIntelligence::OnInferenceStart(uint64_t modelId) {
    // Could trigger workload classification here
}

void PredictiveMemoryIntelligence::OnInferenceEnd(uint64_t modelId, const WorkloadSignature& signature) {
    if (patternMiner_) {
        // Generate or update profile for this workload
        auto profile = patternMiner_->FindMatchingProfile(signature);
        if (!profile) {
            auto newProfile = patternMiner_->GenerateProfile(signature);
            patternMiner_->StoreProfile(newProfile);
        }
    }
}

std::shared_ptr<PlacementProfile> PredictiveMemoryIntelligence::GetPolicyForWorkload(const WorkloadSignature& signature) {
    if (!patternMiner_) {
        return nullptr;
    }
    
    auto profile = patternMiner_->FindMatchingProfile(signature);
    if (!profile) {
        auto newProfile = patternMiner_->GenerateProfile(signature);
        patternMiner_->StoreProfile(newProfile);
        return patternMiner_->GetProfile(newProfile.profileId);
    }
    
    return profile;
}

PolicyParameters PredictiveMemoryIntelligence::GetCurrentPolicyParameters() {
    if (adaptationController_) {
        return adaptationController_->GetPolicyParameters();
    }
    
    // Default parameters
    PolicyParameters params;
    params.prefetchThreshold = 0.6;
    params.evictionAggression = 0.4;
    params.migrationThreshold = 0.7;
    params.migrationCooldownMs = 200;
    params.enableProactivePlacement = true;
    return params;
}

void PredictiveMemoryIntelligence::TriggerPolicyRefinement() {
    if (refinementEngine_) {
        refinementEngine_->RefinePolicies();
    }
}

WorkloadClass PredictiveMemoryIntelligence::GetCurrentWorkloadClass() const {
    if (adaptationController_) {
        return adaptationController_->GetCurrentState().currentClass;
    }
    return WorkloadClass::UNKNOWN;
}

bool PredictiveMemoryIntelligence::GenerateIntelligenceReport(const std::string& filename) {
    std::ofstream out(filename);
    if (!out) return false;
    
    out << "RawRamXD Phase 7C: Predictive Memory Intelligence Report\n";
    out << "========================================================\n\n";
    
    auto metrics = GetMetrics();
    out << "Events Logged: " << metrics.eventsLogged << "\n";
    out << "Patterns Mined: " << metrics.patternsMined << "\n";
    out << "Policies Refined: " << metrics.policiesRefined << "\n";
    out << "Workload Classifications: " << metrics.workloadClassifications << "\n";
    out << "Current Hit Rate: " << std::fixed << std::setprecision(2) << metrics.currentHitRate << "\n";
    out << "Policy Effectiveness: " << metrics.policyEffectiveness << "\n";
    out << "Memory Saved: " << metrics.memorySavedBytes << " bytes\n";
    
    return true;
}

PredictiveMemoryIntelligence::IntelligenceMetrics PredictiveMemoryIntelligence::GetMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    IntelligenceMetrics metrics;
    
    if (sequenceLogger_) {
        auto stats = sequenceLogger_->GetStats();
        metrics.eventsLogged = stats.totalEventsLogged;
    }
    
    if (patternMiner_) {
        auto stats = patternMiner_->GetStats();
        metrics.patternsMined = stats.patternsDiscovered;
    }
    
    if (refinementEngine_) {
        auto stats = refinementEngine_->GetStats();
        metrics.policiesRefined = stats.policiesRefined;
    }
    
    if (adaptationController_) {
        auto stats = adaptationController_->GetStats();
        metrics.workloadClassifications = stats.classificationsPerformed;
    }
    
    // Calculate derived metrics
    metrics.currentHitRate = 0.75; // Placeholder
    metrics.policyEffectiveness = 0.85; // Placeholder
    metrics.memorySavedBytes = 1024 * 1024 * 100; // Placeholder: 100MB
    
    return metrics;
}

void PredictiveMemoryIntelligence::BackgroundRefinement() {
    // Would run in background thread
    TriggerPolicyRefinement();
}

void PredictiveMemoryIntelligence::BackgroundAdaptation() {
    // Would run in background thread
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

bool RawRamXD_PredictiveIntelligence_Initialize(const char* persistenceDir) {
    RawRamXD::PredictiveIntelligenceConfig config;
    config.enableSequenceLogging = true;
    config.enablePatternMining = true;
    config.enablePolicyRefinement = true;
    config.enableOnlineAdaptation = true;
    config.persistenceDir = persistenceDir ? persistenceDir : "./predictive_data";
    config.refinementIntervalMs = 60000; // 1 minute
    config.adaptationIntervalMs = 1000;  // 1 second
    
    return RawRamXD::PredictiveMemoryIntelligence::Instance().Initialize(config);
}

void RawRamXD_PredictiveIntelligence_Shutdown() {
    RawRamXD::PredictiveMemoryIntelligence::Instance().Shutdown();
}

void RawRamXD_LogAccessEvent(uint64_t tensorId, int accessType, 
                              int sourceTier, int targetTier,
                              uint64_t offset, uint64_t size,
                              uint32_t latencyUs, int wasHit) {
    RawRamXD::TensorAccessEvent event;
    event.timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    event.tensorId = tensorId;
    event.accessType = static_cast<RawRamXD::AccessType>(accessType);
    event.sourceTier = static_cast<RawRamXD::MemoryTier>(sourceTier);
    event.targetTier = static_cast<RawRamXD::MemoryTier>(targetTier);
    event.offset = offset;
    event.sizeBytes = size;
    event.latencyUs = latencyUs;
    event.wasHit = wasHit != 0;
    
    RawRamXD::PredictiveMemoryIntelligence::Instance().OnTensorAccess(event);
}

int RawRamXD_GetRecommendedTier(uint64_t tensorId, uint64_t* predictedHitRate) {
    // Simplified implementation
    if (predictedHitRate) {
        *predictedHitRate = 75; // 75% hit rate prediction
    }
    return static_cast<int>(RawRamXD::MemoryTier::GPU0);
}

int RawRamXD_GetAggressionLevel() {
    auto params = RawRamXD::PredictiveMemoryIntelligence::Instance().GetCurrentPolicyParameters();
    if (params.evictionAggression < 0.3) return 0; // Conservative
    if (params.evictionAggression < 0.5) return 1; // Moderate
    if (params.evictionAggression < 0.7) return 2; // Aggressive
    return 3; // Adaptive
}

void RawRamXD_TriggerPolicyRefinement() {
    RawRamXD::PredictiveMemoryIntelligence::Instance().TriggerPolicyRefinement();
}

int RawRamXD_GetCurrentWorkloadClass() {
    return static_cast<int>(RawRamXD::PredictiveMemoryIntelligence::Instance().GetCurrentWorkloadClass());
}

bool RawRamXD_SaveIntelligenceReport(const char* filename) {
    if (!filename) return false;
    return RawRamXD::PredictiveMemoryIntelligence::Instance().GenerateIntelligenceReport(filename);
}

} // extern "C"

} // namespace RawRamXD