/**
 * OscillationDampener.cpp
 *
 * Phase C.4 Batch 2/5: Oscillation Detection & Dampening
 */

#include "OscillationDampener.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <math>

namespace Autonomy {

// ============================================================================
// Oscillation Type Conversions
// ============================================================================

std::string OscillationTypeToString(OscillationType type) {
    switch (type) {
        case OscillationType::DECISION_FLIP_FLOP: return "DECISION_FLIP_FLOP";
        case OscillationType::MUTATION_BURST: return "MUTATION_BURST";
        case OscillationType::STATE_UNSTABLE: return "STATE_UNSTABLE";
        case OscillationType::RESOURCE_THRASHING: return "RESOURCE_THRASHING";
        case OscillationType::ROLE_CHURN: return "ROLE_CHURN";
        case OscillationType::PATTERN_CYCLIC: return "PATTERN_CYCLIC";
        default: return "UNKNOWN";
    }
}

std::string OscillationSeverityToString(OscillationSeverity severity) {
    switch (severity) {
        case OscillationSeverity::NONE: return "NONE";
        case OscillationSeverity::MILD: return "MILD";
        case OscillationSeverity::MODERATE: return "MODERATE";
        case OscillationSeverity::SEVERE: return "SEVERE";
        case OscillationSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// OscillationDetection Implementation
// ============================================================================

std::string OscillationDetection::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"detectionId\":\"" << detectionId << "\",";
    json << "\"type\":\"" << OscillationTypeToString(type) << "\",";
    json << "\"severity\":\"" << OscillationSeverityToString(severity) << "\",";
    json << "\"source\":\"" << source << "\",";
    json << "\"frequencyHz\":" << frequencyHz << ",";
    json << "\"amplitude\":" << amplitude << ",";
    json << "\"dampingRatio\":" << dampingRatio << ",";
    json << "\"detectedAtMs\":" << detectedAtMs << ",";
    json << "\"durationMs\":" << durationMs;
    json << "}";
    return json.str();
}

void OscillationDetection::Print() const {
    const char* severityColor = "\033[0m";
    if (severity == OscillationSeverity::CRITICAL) severityColor = "\033[31m";
    else if (severity == OscillationSeverity::SEVERE) severityColor = "\033[33m";
    else if (severity == OscillationSeverity::MODERATE) severityColor = "\033[35m";
    
    std::cout << severityColor;
    std::cout << "[" << OscillationSeverityToString(severity) << "] ";
    std::cout << OscillationTypeToString(type) << "\n";
    std::cout << "  Source: " << source << "\n";
    std::cout << "  Frequency: " << std::fixed << std::setprecision(2) << frequencyHz << " Hz\n";
    std::cout << "  Amplitude: " << amplitude << "\n";
    std::cout << "\033[0m";
}

// ============================================================================
// DampeningAction Implementation
// ============================================================================

std::string DampeningAction::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"actionId\":\"" << actionId << "\",";
    json << "\"detectionId\":\"" << detectionId << "\",";
    json << "\"type\":\"" << type << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"intensity\":" << intensity << ",";
    json << "\"appliedAtMs\":" << appliedAtMs << ",";
    json << "\"durationMs\":" << durationMs << ",";
    json << "\"reversible\":" << (reversible ? "true" : "false");
    json << "}";
    return json.str();
}

// ============================================================================
// Config Implementations
// ============================================================================

std::string OscillationDetectorConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"decisionHistorySize\":" << decisionHistorySize << ",";
    json << "\"decisionFlipThreshold\":" << decisionFlipThreshold << ",";
    json << "\"mutationBurstThreshold\":" << mutationBurstThreshold << ",";
    json << "\"stateHistorySize\":" << stateHistorySize << ",";
    json << "\"stateVarianceThreshold\":" << stateVarianceThreshold;
    json << "}";
    return json.str();
}

std::string DampenerConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"hysteresisSamples\":" << hysteresisSamples << ",";
    json << "\"smoothingAlpha\":" << smoothingAlpha << ",";
    json << "\"deadbandThreshold\":" << deadbandThreshold << ",";
    json << "\"mildDampening\":" << mildDampening;
    json << "}";
    return json.str();
}

// ============================================================================
// OscillationDetector Implementation
// ============================================================================

OscillationDetector::OscillationDetector() = default;
OscillationDetector::~OscillationDetector() = default;

bool OscillationDetector::Initialize(const OscillationDetectorConfig& config) {
    config_ = config;
    initialized_ = true;
    
    std::cout << "[OscillationDetector] Initialized\n";
    std::cout << "  Decision history: " << config.decisionHistorySize << "\n";
    std::cout << "  State history: " << config.stateHistorySize << "\n";
    
    return true;
}

void OscillationDetector::SampleDecision(const Decision& decision) {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    decisionHistory_.push_back(decision);
    
    // Prune old decisions
    auto cutoff = GetCurrentTimeMs() - config_.decisionTimeWindowMs;
    while (!decisionHistory_.empty() && 
           decisionHistory_.front().timestampMs < cutoff) {
        decisionHistory_.pop_front();
    }
    
    // Limit size
    while (decisionHistory_.size() > static_cast<size_t>(config_.decisionHistorySize)) {
        decisionHistory_.pop_front();
    }
}

void OscillationDetector::SampleMutation(const std::string& mutationType,
                                          const std::map<std::string, std::string>& details) {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    mutationHistory_.push_back({GetCurrentTimeMs(), mutationType});
    
    // Prune old mutations
    auto cutoff = GetCurrentTimeMs() - config_.mutationWindowMs;
    while (!mutationHistory_.empty() && mutationHistory_.front().first < cutoff) {
        mutationHistory_.pop_front();
    }
}

void OscillationDetector::SampleState(const std::string& stateName, double value) {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    StateSample sample;
    sample.timestampMs = GetCurrentTimeMs();
    sample.value = value;
    
    stateHistories_[stateName].push_back(sample);
    
    // Prune old samples
    auto cutoff = GetCurrentTimeMs() - config_.stateWindowMs;
    auto& history = stateHistories_[stateName];
    while (!history.empty() && history.front().timestampMs < cutoff) {
        history.pop_front();
    }
    
    // Limit size
    while (history.size() > static_cast<size_t>(config_.stateHistorySize)) {
        history.pop_front();
    }
}

void OscillationDetector::SampleResource(const std::string& resourceName, double usage) {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    StateSample sample;
    sample.timestampMs = GetCurrentTimeMs();
    sample.value = usage;
    
    resourceHistories_[resourceName].push_back(sample);
    
    // Limit size
    auto& history = resourceHistories_[resourceName];
    while (history.size() > static_cast<size_t>(config_.resourceHistorySize)) {
        history.pop_front();
    }
}

void OscillationDetector::SampleRoleChange(const std::string& workerId,
                                           const std::string& oldRole,
                                           const std::string& newRole) {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    roleChangeHistory_.push_back({GetCurrentTimeMs(), workerId});
    
    // Prune old changes
    auto cutoff = GetCurrentTimeMs() - config_.roleWindowMs;
    while (!roleChangeHistory_.empty() && roleChangeHistory_.front().first < cutoff) {
        roleChangeHistory_.pop_front();
    }
}

void OscillationDetector::SamplePattern(const std::string& patternId, double strength) {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    patternHistory_.push_back({GetCurrentTimeMs(), patternId});
    
    // Limit size
    while (patternHistory_.size() > static_cast<size_t>(config_.patternHistorySize)) {
        patternHistory_.pop_front();
    }
}

std::vector<OscillationDetection> OscillationDetector::DetectOscillations() {
    std::vector<OscillationDetection> newDetections;
    
    // Run all detection methods
    auto decisionOsc = DetectDecisionFlipFlop();
    if (decisionOsc.severity != OscillationSeverity::NONE) {
        newDetections.push_back(decisionOsc);
    }
    
    auto mutationOsc = DetectMutationBurst();
    if (mutationOsc.severity != OscillationSeverity::NONE) {
        newDetections.push_back(mutationOsc);
    }
    
    auto stateOsc = DetectStateOscillation();
    if (stateOsc.severity != OscillationSeverity::NONE) {
        newDetections.push_back(stateOsc);
    }
    
    auto resourceOsc = DetectResourceThrashing();
    if (resourceOsc.severity != OscillationSeverity::NONE) {
        newDetections.push_back(resourceOsc);
    }
    
    auto roleOsc = DetectRoleChurn();
    if (roleOsc.severity != OscillationSeverity::NONE) {
        newDetections.push_back(roleOsc);
    }
    
    auto patternOsc = DetectPatternCyclic();
    if (patternOsc.severity != OscillationSeverity::NONE) {
        newDetections.push_back(patternOsc);
    }
    
    // Store detections
    {
        std::lock_guard<std::mutex> lock(detectionsMutex_);
        for (const auto& det : newDetections) {
            detections_.push_back(det);
        }
    }
    
    return newDetections;
}

std::vector<OscillationDetection> OscillationDetector::GetRecentDetections(int limit) const {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    std::vector<OscillationDetection> recent;
    int count = 0;
    for (auto it = detections_.rbegin(); it != detections_.rend() && count < limit; ++it, ++count) {
        recent.push_back(*it);
    }
    
    return recent;
}

void OscillationDetector::ClearHistory() {
    std::lock_guard<std::mutex> lock(detectionsMutex_);
    
    decisionHistory_.clear();
    mutationHistory_.clear();
    stateHistories_.clear();
    resourceHistories_.clear();
    roleChangeHistory_.clear();
    patternHistory_.clear();
    detections_.clear();
}

void OscillationDetector::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     OSCILLATION DETECTOR STATUS                                  ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Decision History:   " << std::setw(38) << decisionHistory_.size() << " ║\n";
    std::cout << "║  Mutation History:   " << std::setw(38) << mutationHistory_.size() << " ║\n";
    std::cout << "║  State Histories:    " << std::setw(38) << stateHistories_.size() << " ║\n";
    std::cout << "║  Resource Histories: " << std::setw(38) << resourceHistories_.size() << " ║\n";
    std::cout << "║  Role Changes:       " << std::setw(37) << roleChangeHistory_.size() << " ║\n";
    std::cout << "║  Pattern History:    " << std::setw(38) << patternHistory_.size() << " ║\n";
    std::cout << "║  Total Detections:   " << std::setw(38) << detections_.size() << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// Detection methods
OscillationDetection OscillationDetector::DetectDecisionFlipFlop() {
    OscillationDetection detection;
    detection.type = OscillationType::DECISION_FLIP_FLOP;
    detection.source = "decisions";
    
    if (decisionHistory_.size() < 4) {
        detection.severity = OscillationSeverity::NONE;
        return detection;
    }
    
    // Count flips
    int flips = 0;
    std::string lastType = "";
    for (const auto& decision : decisionHistory_) {
        std::string currentType = DecisionTypeToString(decision.type);
        if (!lastType.empty() && currentType != lastType) {
            flips++;
        }
        lastType = currentType;
    }
    
    if (flips >= config_.decisionFlipThreshold) {
        detection.detectionId = GenerateDetectionId();
        detection.detectedAtMs = GetCurrentTimeMs();
        detection.frequencyHz = flips / (config_.decisionTimeWindowMs / 1000.0);
        detection.amplitude = static_cast<double>(flips) / decisionHistory_.size();
        
        // Determine severity
        if (flips >= config_.decisionFlipThreshold * 3) {
            detection.severity = OscillationSeverity::CRITICAL;
        } else if (flips >= config_.decisionFlipThreshold * 2) {
            detection.severity = OscillationSeverity::SEVERE;
        } else if (flips >= static_cast<int>(config_.decisionFlipThreshold * 1.5)) {
            detection.severity = OscillationSeverity::MODERATE;
        } else {
            detection.severity = OscillationSeverity::MILD;
        }
    } else {
        detection.severity = OscillationSeverity::NONE;
    }
    
    return detection;
}

OscillationDetection OscillationDetector::DetectMutationBurst() {
    OscillationDetection detection;
    detection.type = OscillationType::MUTATION_BURST;
    detection.source = "mutations";
    
    int mutationCount = static_cast<int>(mutationHistory_.size());
    
    if (mutationCount >= config_.mutationBurstThreshold) {
        detection.detectionId = GenerateDetectionId();
        detection.detectedAtMs = GetCurrentTimeMs();
        detection.frequencyHz = mutationCount / (config_.mutationWindowMs / 1000.0);
        detection.amplitude = static_cast<double>(mutationCount) / config_.mutationBurstThreshold;
        
        // Determine severity
        if (mutationCount >= config_.mutationBurstThreshold * 3) {
            detection.severity = OscillationSeverity::CRITICAL;
        } else if (mutationCount >= config_.mutationBurstThreshold * 2) {
            detection.severity = OscillationSeverity::SEVERE;
        } else if (mutationCount >= static_cast<int>(config_.mutationBurstThreshold * 1.5)) {
            detection.severity = OscillationSeverity::MODERATE;
        } else {
            detection.severity = OscillationSeverity::MILD;
        }
    } else {
        detection.severity = OscillationSeverity::NONE;
    }
    
    return detection;
}

OscillationDetection OscillationDetector::DetectStateOscillation() {
    OscillationDetection detection;
    detection.type = OscillationType::STATE_UNSTABLE;
    detection.source = "state";
    
    // Check all state histories
    for (const auto& [name, history] : stateHistories_) {
        if (history.size() < 10) continue;
        
        double variance = CalculateVariance(history);
        
        if (variance > config_.stateVarianceThreshold) {
            detection.detectionId = GenerateDetectionId();
            detection.detectedAtMs = GetCurrentTimeMs();
            detection.source = "state." + name;
            detection.frequencyHz = CalculateFrequency(history);
            detection.amplitude = variance;
            
            // Determine severity based on variance
            if (variance > config_.stateVarianceThreshold * 4) {
                detection.severity = OscillationSeverity::CRITICAL;
            } else if (variance > config_.stateVarianceThreshold * 2) {
                detection.severity = OscillationSeverity::SEVERE;
            } else if (variance > config_.stateVarianceThreshold * 1.5) {
                detection.severity = OscillationSeverity::MODERATE;
            } else {
                detection.severity = OscillationSeverity::MILD;
            }
            
            return detection;
        }
    }
    
    detection.severity = OscillationSeverity::NONE;
    return detection;
}

OscillationDetection OscillationDetector::DetectResourceThrashing() {
    OscillationDetection detection;
    detection.type = OscillationType::RESOURCE_THRASHING;
    detection.source = "resources";
    
    // Check all resource histories
    for (const auto& [name, history] : resourceHistories_) {
        if (history.size() < 10) continue;
        
        double variance = CalculateVariance(history);
        
        if (variance > config_.resourceVarianceThreshold) {
            detection.detectionId = GenerateDetectionId();
            detection.detectedAtMs = GetCurrentTimeMs();
            detection.source = "resource." + name;
            detection.frequencyHz = CalculateFrequency(history);
            detection.amplitude = variance;
            
            // Determine severity
            if (variance > config_.resourceVarianceThreshold * 4) {
                detection.severity = OscillationSeverity::CRITICAL;
            } else if (variance > config_.resourceVarianceThreshold * 2) {
                detection.severity = OscillationSeverity::SEVERE;
            } else if (variance > config_.resourceVarianceThreshold * 1.5) {
                detection.severity = OscillationSeverity::MODERATE;
            } else {
                detection.severity = OscillationSeverity::MILD;
            }
            
            return detection;
        }
    }
    
    detection.severity = OscillationSeverity::NONE;
    return detection;
}

OscillationDetection OscillationDetector::DetectRoleChurn() {
    OscillationDetection detection;
    detection.type = OscillationType::ROLE_CHURN;
    detection.source = "roles";
    
    int changeCount = static_cast<int>(roleChangeHistory_.size());
    
    if (changeCount >= config_.roleChangeThreshold) {
        detection.detectionId = GenerateDetectionId();
        detection.detectedAtMs = GetCurrentTimeMs();
        detection.frequencyHz = changeCount / (config_.roleWindowMs / 1000.0);
        detection.amplitude = static_cast<double>(changeCount) / config_.roleChangeThreshold;
        
        // Determine severity
        if (changeCount >= config_.roleChangeThreshold * 3) {
            detection.severity = OscillationSeverity::CRITICAL;
        } else if (changeCount >= config_.roleChangeThreshold * 2) {
            detection.severity = OscillationSeverity::SEVERE;
        } else if (changeCount >= static_cast<int>(config_.roleChangeThreshold * 1.5)) {
            detection.severity = OscillationSeverity::MODERATE;
        } else {
            detection.severity = OscillationSeverity::MILD;
        }
    } else {
        detection.severity = OscillationSeverity::NONE;
    }
    
    return detection;
}

OscillationDetection OscillationDetector::DetectPatternCyclic() {
    OscillationDetection detection;
    detection.type = OscillationType::PATTERN_CYCLIC;
    detection.source = "patterns";
    
    // Simple cycle detection - look for repeating sequences
    if (patternHistory_.size() >= 20) {
        // Check for cycles of length 3-10
        for (int cycleLen = 3; cycleLen <= 10 && cycleLen < static_cast<int>(patternHistory_.size()) / 2; ++cycleLen) {
            if (DetectCycle(patternHistory_, cycleLen, cycleLen)) {
                detection.detectionId = GenerateDetectionId();
                detection.detectedAtMs = GetCurrentTimeMs();
                detection.frequencyHz = 1.0 / (cycleLen * 100); // Approximate
                detection.amplitude = 1.0;
                detection.severity = OscillationSeverity::MODERATE;
                return detection;
            }
        }
    }
    
    detection.severity = OscillationSeverity::NONE;
    return detection;
}

// Helpers
double OscillationDetector::CalculateVariance(const std::deque<StateSample>& samples) const {
    if (samples.size() < 2) return 0.0;
    
    // Calculate mean
    double sum = 0.0;
    for (const auto& sample : samples) {
        sum += sample.value;
    }
    double mean = sum / samples.size();
    
    // Calculate variance
    double variance = 0.0;
    for (const auto& sample : samples) {
        variance += (sample.value - mean) * (sample.value - mean);
    }
    
    return variance / samples.size();
}

double OscillationDetector::CalculateFrequency(const std::deque<StateSample>& samples) const {
    if (samples.size() < 2) return 0.0;
    
    // Count zero crossings
    int crossings = 0;
    double mean = 0.0;
    for (const auto& sample : samples) {
        mean += sample.value;
    }
    mean /= samples.size();
    
    double lastValue = samples.front().value;
    for (size_t i = 1; i < samples.size(); ++i) {
        if ((lastValue < mean && samples[i].value >= mean) ||
            (lastValue > mean && samples[i].value <= mean)) {
            crossings++;
        }
        lastValue = samples[i].value;
    }
    
    // Frequency in Hz
    int64_t durationMs = samples.back().timestampMs - samples.front().timestampMs;
    if (durationMs <= 0) return 0.0;
    
    return crossings / 2.0 / (durationMs / 1000.0);
}

bool OscillationDetector::DetectCycle(const std::deque<std::pair<int64_t, std::string>>& samples,
                                       int minCycleLength, int maxCycleLength) const {
    if (samples.size() < static_cast<size_t>(maxCycleLength * 2)) return false;
    
    // Simple string-based cycle detection
    std::vector<std::string> pattern;
    for (int i = 0; i < minCycleLength; ++i) {
        pattern.push_back(samples[samples.size() - 1 - i].second);
    }
    
    // Check if pattern repeats
    bool match = true;
    for (int i = 0; i < minCycleLength && match; ++i) {
        if (samples[samples.size() - 1 - i].second != samples[samples.size() - 1 - i - minCycleLength].second) {
            match = false;
        }
    }
    
    return match;
}

int64_t OscillationDetector::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string OscillationDetector::GenerateDetectionId() {
    return "osc_" + std::to_string(++detectionCounter_) + "_" + std::to_string(GetCurrentTimeMs());
}

// ============================================================================
// OscillationDampener Implementation
// ============================================================================

OscillationDampener::OscillationDampener() = default;
OscillationDampener::~OscillationDampener() = default;

bool OscillationDampener::Initialize(const DampenerConfig& config) {
    config_ = config;
    initialized_ = true;
    
    std::cout << "[OscillationDampener] Initialized\n";
    std::cout << "  Hysteresis samples: " << config.hysteresisSamples << "\n";
    std::cout << "  Smoothing alpha: " << config.smoothingAlpha << "\n";
    
    return true;
}

DampeningAction OscillationDampener::Dampen(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.appliedAtMs = GetCurrentTimeMs();
    action.intensity = GetDampeningIntensity(detection.severity);
    
    // Generate specific dampening based on type
    switch (detection.type) {
        case OscillationType::DECISION_FLIP_FLOP:
            action = GenerateDecisionDampening(detection);
            break;
        case OscillationType::MUTATION_BURST:
            action = GenerateMutationDampening(detection);
            break;
        case OscillationType::STATE_UNSTABLE:
            action = GenerateStateDampening(detection);
            break;
        case OscillationType::RESOURCE_THRASHING:
            action = GenerateResourceDampening(detection);
            break;
        case OscillationType::ROLE_CHURN:
            action = GenerateRoleDampening(detection);
            break;
        case OscillationType::PATTERN_CYCLIC:
            action = GeneratePatternDampening(detection);
            break;
        default:
            action.type = "unknown";
            action.description = "Unknown oscillation type";
            break;
    }
    
    // Store action
    {
        std::lock_guard<std::mutex> lock(actionsMutex_);
        activeActions_.push_back(action);
    }
    
    return action;
}

double OscillationDampener::ApplyHysteresis(const std::string& signalName,
                                               double newValue,
                                               double previousValue) {
    std::lock_guard<std::mutex> lock(hysteresisMutex_);
    
    double diff = std::abs(newValue - previousValue);
    
    if (diff < config_.hysteresisThreshold) {
        // Within hysteresis band - increment counter
        hysteresisCounters_[signalName]++;
        
        if (hysteresisCounters_[signalName] >= config_.hysteresisSamples) {
            // Sustained change - update value
            hysteresisLastValues_[signalName] = newValue;
            hysteresisCounters_[signalName] = 0;
            return newValue;
        }
        
        // Not sustained enough - return previous
        return hysteresisLastValues_[signalName];
    }
    
    // Outside hysteresis band - reset and accept
    hysteresisCounters_[signalName] = 0;
    hysteresisLastValues_[signalName] = newValue;
    return newValue;
}

bool OscillationDampener::ApplyRateLimit(const std::string& actionType) {
    std::lock_guard<std::mutex> lock(rateLimitMutex_);
    
    int64_t now = GetCurrentTimeMs();
    auto& window = rateLimitWindows_[actionType];
    
    // Remove old entries (older than 1 second)
    while (!window.empty() && window.front() < now - 1000) {
        window.pop_front();
    }
    
    // Check limit
    int maxPerSecond = 10;  // Default
    if (actionType == "decision") maxPerSecond = config_.maxDecisionsPerSecond;
    else if (actionType == "mutation") maxPerSecond = config_.maxMutationsPerSecond;
    else if (actionType == "state_change") maxPerSecond = config_.maxStateChangesPerSecond;
    
    if (static_cast<int>(window.size()) >= maxPerSecond) {
        return false;  // Rate limited
    }
    
    // Allow action
    window.push_back(now);
    return true;
}

double OscillationDampener::ApplySmoothing(const std::string& signalName, double newValue) {
    std::lock_guard<std::mutex> lock(smoothingMutex_);
    
    auto it = smoothedValues_.find(signalName);
    if (it == smoothedValues_.end()) {
        // First sample
        smoothedValues_[signalName] = newValue;
        return newValue;
    }
    
    // Apply exponential moving average
    double smoothed = config_.smoothingAlpha * newValue + (1.0 - config_.smoothingAlpha) * it->second;
    smoothedValues_[signalName] = smoothed;
    
    return smoothed;
}

double OscillationDampener::ApplyDeadband(double value, double center) {
    double diff = std::abs(value - center);
    if (diff < config_.deadbandThreshold) {
        return center;  // Within deadband - return center
    }
    return value;  // Outside deadband - return actual value
}

std::vector<DampeningAction> OscillationDampener::GetActiveActions() const {
    std::lock_guard<std::mutex> lock(actionsMutex_);
    return activeActions_;
}

bool OscillationDampener::CancelAction(const std::string& actionId) {
    std::lock_guard<std::mutex> lock(actionsMutex_);
    
    auto it = std::find_if(activeActions_.begin(), activeActions_.end(),
                          [&actionId](const DampeningAction& a) { return a.actionId == actionId; });
    
    if (it != activeActions_.end()) {
        activeActions_.erase(it);
        return true;
    }
    
    return false;
}

void OscillationDampener::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     OSCILLATION DAMPENER STATUS                                  ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Active Actions:    " << std::setw(38) << activeActions_.size() << " ║\n";
    std::cout << "║  Smoothed Signals:   " << std::setw(38) << smoothedValues_.size() << " ║\n";
    std::cout << "║  Rate Limited:       " << std::setw(38) << rateLimitWindows_.size() << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// Action generators
DampeningAction OscillationDampener::GenerateDecisionDampening(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.type = "decision_rate_limit";
    action.description = "Rate limit decision frequency";
    action.intensity = GetDampeningIntensity(detection.severity);
    action.appliedAtMs = GetCurrentTimeMs();
    action.durationMs = 5000;  // 5 seconds
    action.reversible = true;
    action.parameters["max_decisions_per_second"] = std::to_string(config_.maxDecisionsPerSecond / 2);
    
    return action;
}

DampeningAction OscillationDampener::GenerateMutationDampening(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.type = "mutation_cooldown";
    action.description = "Apply cooldown between mutations";
    action.intensity = GetDampeningIntensity(detection.severity);
    action.appliedAtMs = GetCurrentTimeMs();
    action.durationMs = 10000;  // 10 seconds
    action.reversible = true;
    action.parameters["cooldown_ms"] = "100";
    
    return action;
}

DampeningAction OscillationDampener::GenerateStateDampening(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.type = "state_smoothing";
    action.description = "Increase state smoothing";
    action.intensity = GetDampeningIntensity(detection.severity);
    action.appliedAtMs = GetCurrentTimeMs();
    action.durationMs = 15000;  // 15 seconds
    action.reversible = true;
    action.parameters["smoothing_alpha"] = std::to_string(config_.smoothingAlpha * 0.5);
    
    return action;
}

DampeningAction OscillationDampener::GenerateResourceDampening(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.type = "resource_throttle";
    action.description = "Throttle resource-intensive operations";
    action.intensity = GetDampeningIntensity(detection.severity);
    action.appliedAtMs = GetCurrentTimeMs();
    action.durationMs = 20000;  // 20 seconds
    action.reversible = true;
    action.parameters["throttle_factor"] = std::to_string(1.0 - action.intensity);
    
    return action;
}

DampeningAction OscillationDampener::GenerateRoleDampening(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.type = "role_stabilization";
    action.description = "Stabilize role assignments";
    action.intensity = GetDampeningIntensity(detection.severity);
    action.appliedAtMs = GetCurrentTimeMs();
    action.durationMs = 30000;  // 30 seconds
    action.reversible = true;
    action.parameters["min_role_duration_ms"] = "5000";
    
    return action;
}

DampeningAction OscillationDampener::GeneratePatternDampening(const OscillationDetection& detection) {
    DampeningAction action;
    action.actionId = GenerateActionId();
    action.detectionId = detection.detectionId;
    action.type = "pattern_dampening";
    action.description = "Dampen cyclic pattern detection";
    action.intensity = GetDampeningIntensity(detection.severity);
    action.appliedAtMs = GetCurrentTimeMs();
    action.durationMs = 10000;  // 10 seconds
    action.reversible = true;
    action.parameters["pattern_threshold"] = "0.9";
    
    return action;
}

// Helpers
double OscillationDampener::GetDampeningIntensity(OscillationSeverity severity) const {
    switch (severity) {
        case OscillationSeverity::MILD: return config_.mildDampening;
        case OscillationSeverity::MODERATE: return config_.moderateDampening;
        case OscillationSeverity::SEVERE: return config_.severeDampening;
        case OscillationSeverity::CRITICAL: return config_.criticalDampening;
        default: return 0.0;
    }
}

int64_t OscillationDampener::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string OscillationDampener::GenerateActionId() {
    return "damp_" + std::to_string(++actionCounter_) + "_" + std::to_string(GetCurrentTimeMs());
}

// ============================================================================
// OscillationManager Implementation
// ============================================================================

OscillationManager::OscillationManager() = default;
OscillationManager::~OscillationManager() = default;

bool OscillationManager::Initialize(const OscillationDetectorConfig& detectorConfig,
                                     const DampenerConfig& dampenerConfig) {
    if (!detector_.Initialize(detectorConfig)) {
        return false;
    }
    
    if (!dampener_.Initialize(dampenerConfig)) {
        return false;
    }
    
    initialized_ = true;
    lastUpdateMs_ = GetCurrentTimeMs();
    
    std::cout << "[OscillationManager] Initialized\n";
    
    return true;
}

void OscillationManager::ProcessSample(const std::string& sampleType,
                                       const std::map<std::string, std::string>& data) {
    if (!initialized_) return;
    
    if (sampleType == "decision") {
        // Parse decision from data
        Decision decision;
        // ... parse logic
        detector_.SampleDecision(decision);
    } else if (sampleType == "mutation") {
        std::string mutationType = data.count("type") ? data.at("type") : "unknown";
        detector_.SampleMutation(mutationType, data);
    } else if (sampleType == "state") {
        std::string stateName = data.count("name") ? data.at("name") : "unknown";
        double value = data.count("value") ? std::stod(data.at("value")) : 0.0;
        detector_.SampleState(stateName, value);
    } else if (sampleType == "resource") {
        std::string resourceName = data.count("name") ? data.at("name") : "unknown";
        double usage = data.count("usage") ? std::stod(data.at("usage")) : 0.0;
        detector_.SampleResource(resourceName, usage);
    } else if (sampleType == "role_change") {
        std::string workerId = data.count("worker_id") ? data.at("worker_id") : "unknown";
        std::string oldRole = data.count("old_role") ? data.at("old_role") : "";
        std::string newRole = data.count("new_role") ? data.at("new_role") : "";
        detector_.SampleRoleChange(workerId, oldRole, newRole);
    } else if (sampleType == "pattern") {
        std::string patternId = data.count("pattern_id") ? data.at("pattern_id") : "unknown";
        double strength = data.count("strength") ? std::stod(data.at("strength")) : 0.0;
        detector_.SamplePattern(patternId, strength);
    }
}

void OscillationManager::Update() {
    if (!initialized_) return;
    
    int64_t now = GetCurrentTimeMs();
    if (now - lastUpdateMs_ < updateIntervalMs_) {
        return;  // Not time to update yet
    }
    
    lastUpdateMs_ = now;
    
    // Detect oscillations
    auto detections = detector_.DetectOscillations();
    
    // Apply dampening for each detection
    for (const auto& detection : detections) {
        if (detection.severity >= OscillationSeverity::MODERATE) {
            dampener_.Dampen(detection);
        }
    }
}

std::vector<OscillationDetection> OscillationManager::GetCurrentOscillations() const {
    return detector_.GetRecentDetections(100);
}

std::vector<DampeningAction> OscillationManager::GetActiveDampening() const {
    return dampener_.GetActiveActions();
}

bool OscillationManager::IsOscillating() const {
    auto detections = detector_.GetRecentDetections(10);
    for (const auto& det : detections) {
        if (det.severity >= OscillationSeverity::MODERATE) {
            return true;
        }
    }
    return false;
}

double OscillationManager::GetStabilityScore() const {
    auto detections = detector_.GetRecentDetections(20);
    
    if (detections.empty()) {
        return 1.0;  // Perfectly stable
    }
    
    double totalSeverity = 0.0;
    for (const auto& det : detections) {
        switch (det.severity) {
            case OscillationSeverity::MILD: totalSeverity += 0.25; break;
            case OscillationSeverity::MODERATE: totalSeverity += 0.5; break;
            case OscillationSeverity::SEVERE: totalSeverity += 0.75; break;
            case OscillationSeverity::CRITICAL: totalSeverity += 1.0; break;
            default: break;
        }
    }
    
    double avgSeverity = totalSeverity / detections.size();
    return std::max(0.0, 1.0 - avgSeverity);
}

void OscillationManager::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     OSCILLATION MANAGER STATUS                                   ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:      " << std::setw(44) << (initialized_ ? "YES" : "NO") << " ║\n";
    std::cout << "║  Is Oscillating:   " << std::setw(44) << (IsOscillating() ? "YES" : "NO") << " ║\n";
    std::cout << "║  Stability Score:  " << std::setw(42) << std::fixed << std::setprecision(2) 
              << GetStabilityScore() << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
    
    detector_.PrintStatus();
    dampener_.PrintStatus();
}

int64_t OscillationManager::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// CLI Implementation
// ============================================================================

void OscillationManagerCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     OSCILLATION MANAGER - Phase C.4 Batch 2/5                     ║\n";
    std::cout << "║     Detection & Dampening System                                   ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void OscillationManagerCLI::PrintUsage() {
    std::cout << "Usage: oscillation-manager [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --simulate <type>    Simulate oscillation type\n";
    std::cout << "  --help               Show this help\n\n";
    std::cout << "Oscillation types:\n";
    std::cout << "  decision_flip      Decision flip-flopping\n";
    std::cout << "  mutation_burst     Mutation burst\n";
    std::cout << "  state_unstable     State oscillation\n";
    std::cout << "  resource_thrash    Resource thrashing\n";
}

void OscillationManagerCLI::InteractiveMode(OscillationManager& manager) {
    std::cout << "\nInteractive Oscillation Manager\n";
    std::cout << "Commands: status, detect, dampen, simulate <type>, clear, quit\n\n";
    
    std::string command;
    while (true) {
        std::cout << "osc> ";
        std::getline(std::cin, command);
        
        if (command == "quit" || command == "exit") {
            break;
        }
        
        if (command == "status") {
            manager.PrintStatus();
        } else if (command == "detect") {
            auto detections = manager.GetCurrentOscillations();
            std::cout << "\nRecent detections:\n";
            for (const auto& det : detections) {
                det.Print();
            }
        } else if (command == "dampen") {
            auto actions = manager.GetActiveDampening();
            std::cout << "\nActive dampening actions:\n";
            for (const auto& action : actions) {
                std::cout << "  " << action.actionId << ": " << action.description << "\n";
            }
        } else if (command.substr(0, 8) == "simulate") {
            std::string type = command.substr(9);
            std::cout << "Simulating " << type << "...\n";
            // Simulation logic would go here
        } else if (command == "clear") {
            manager.GetDetector().ClearHistory();
            std::cout << "History cleared.\n";
        } else if (!command.empty()) {
            std::cout << "Unknown command: " << command << "\n";
        }
    }
}

void OscillationManagerCLI::SimulateOscillation(OscillationManager& manager,
                                                   OscillationType type,
                                                   int durationMs) {
    // Simulation implementation
    std::cout << "Simulating oscillation for " << durationMs << "ms...\n";
}

int OscillationManagerCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    OscillationDetectorConfig detectorConfig;
    DampenerConfig dampenerConfig;
    
    OscillationManager manager;
    if (!manager.Initialize(detectorConfig, dampenerConfig)) {
        std::cerr << "Failed to initialize oscillation manager\n";
        return 1;
    }
    
    // Check for --interactive
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(manager);
        return 0;
    }
    
    // Default: print status
    manager.PrintStatus();
    return 0;
}

} // namespace Autonomy
