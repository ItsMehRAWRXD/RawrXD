// Orchestration Telemetry
// Tracks time spent in each phase of Sovereign execution
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <map>
#include <string>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Orchestration Phase Types
// ============================================================================
enum class OrchestrationPhase {
    PROMPT_PARSE = 0,
    TOKENIZATION = 1,
    PLANNING = 2,
    SEG_BUILD = 3,
    SCHEDULING = 4,
    INFERENCE = 5,
    POST_PROCESSING = 6,
    TELEMETRY = 7,
    NARRATIVE = 8,
    LEARNING = 9,
    CHECKPOINT = 10,
    TOTAL = 11
};

inline const char* OrchestrationPhaseToString(OrchestrationPhase phase) {
    switch (phase) {
        case OrchestrationPhase::PROMPT_PARSE: return "prompt_parse";
        case OrchestrationPhase::TOKENIZATION: return "tokenization";
        case OrchestrationPhase::PLANNING: return "planning";
        case OrchestrationPhase::SEG_BUILD: return "seg_build";
        case OrchestrationPhase::SCHEDULING: return "scheduling";
        case OrchestrationPhase::INFERENCE: return "inference";
        case OrchestrationPhase::POST_PROCESSING: return "post_processing";
        case OrchestrationPhase::TELEMETRY: return "telemetry";
        case OrchestrationPhase::NARRATIVE: return "narrative";
        case OrchestrationPhase::LEARNING: return "learning";
        case OrchestrationPhase::CHECKPOINT: return "checkpoint";
        case OrchestrationPhase::TOTAL: return "total";
        default: return "unknown";
    }
}

// ============================================================================
// Phase Timing
// ============================================================================
struct PhaseTiming {
    double duration_ms = 0.0;
    double percentage = 0.0;  // Of total time
    int call_count = 0;
    double min_ms = 0.0;
    double max_ms = 0.0;
    double mean_ms = 0.0;
    double p95_ms = 0.0;
    
    std::vector<double> samples;
    
    void AddSample(double ms) {
        samples.push_back(ms);
        call_count++;
        
        if (samples.size() == 1) {
            min_ms = max_ms = mean_ms = ms;
        } else {
            min_ms = std::min(min_ms, ms);
            max_ms = std::max(max_ms, ms);
            
            // Update mean
            mean_ms = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        }
    }
    
    void CalculatePercentiles() {
        if (samples.empty()) return;
        
        auto sorted = samples;
        std::sort(sorted.begin(), sorted.end());
        
        // P95
        size_t p95_idx = static_cast<size_t>(sorted.size() * 0.95);
        if (p95_idx >= sorted.size()) p95_idx = sorted.size() - 1;
        p95_ms = sorted[p95_idx];
    }
};

// ============================================================================
// Orchestration Telemetry
// ============================================================================
class OrchestrationTelemetry {
public:
    struct TelemetrySnapshot {
        std::map<OrchestrationPhase, PhaseTiming> phases;
        double total_time_ms = 0.0;
        std::string timestamp;
        
        std::string ToJson() const {
            JsonWriter writer;
            writer.BeginObject();
            writer.WriteString("timestamp", timestamp);
            writer.WriteDouble("total_time_ms", total_time_ms);
            
            writer.BeginObject("phases");
            for (const auto& [phase, timing] : phases) {
                writer.BeginObject(OrchestrationPhaseToString(phase));
                writer.WriteDouble("duration_ms", timing.duration_ms);
                writer.WriteDouble("percentage", timing.percentage);
                writer.WriteInt("call_count", timing.call_count);
                writer.WriteDouble("min_ms", timing.min_ms);
                writer.WriteDouble("max_ms", timing.max_ms);
                writer.WriteDouble("mean_ms", timing.mean_ms);
                writer.WriteDouble("p95_ms", timing.p95_ms);
                writer.EndObject();
            }
            writer.EndObject();
            
            writer.EndObject();
            return writer.Str();
        }
    };
    
    // Start timing a phase
    void StartPhase(OrchestrationPhase phase) {
        active_phases_[phase] = Clock::now();
    }
    
    // End timing a phase
    void EndPhase(OrchestrationPhase phase) {
        auto it = active_phases_.find(phase);
        if (it == active_phases_.end()) return;
        
        auto end_time = Clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - it->second).count() / 1000.0;
        
        timings_[phase].AddSample(duration);
        active_phases_.erase(it);
    }
    
    // Get timing for a phase
    PhaseTiming GetTiming(OrchestrationPhase phase) const {
        auto it = timings_.find(phase);
        if (it != timings_.end()) {
            return it->second;
        }
        return PhaseTiming{};
    }
    
    // Calculate percentages and create snapshot
    TelemetrySnapshot CreateSnapshot() {
        TelemetrySnapshot snapshot;
        snapshot.timestamp = GetTimestamp();
        
        // Calculate total time
        double total = 0.0;
        for (auto& [phase, timing] : timings_) {
            timing.CalculatePercentiles();
            total += timing.mean_ms * timing.call_count;
        }
        snapshot.total_time_ms = total;
        
        // Calculate percentages
        for (auto& [phase, timing] : timings_) {
            if (total > 0) {
                timing.percentage = (timing.mean_ms * timing.call_count / total) * 100.0;
            }
            snapshot.phases[phase] = timing;
        }
        
        return snapshot;
    }
    
    // Get overhead breakdown
    struct OverheadBreakdown {
        double orchestration_overhead_ms = 0.0;  // Non-inference time
        double inference_time_ms = 0.0;
        double total_time_ms = 0.0;
        double overhead_percentage = 0.0;
        
        std::string ToJson() const {
            JsonWriter writer;
            writer.BeginObject();
            writer.WriteDouble("orchestration_overhead_ms", orchestration_overhead_ms);
            writer.WriteDouble("inference_time_ms", inference_time_ms);
            writer.WriteDouble("total_time_ms", total_time_ms);
            writer.WriteDouble("overhead_percentage", overhead_percentage);
            writer.EndObject();
            return writer.Str();
        }
    };
    
    OverheadBreakdown CalculateOverhead() {
        OverheadBreakdown breakdown;
        
        auto snapshot = CreateSnapshot();
        breakdown.total_time_ms = snapshot.total_time_ms;
        
        // Inference time
        auto inference_it = timings_.find(OrchestrationPhase::INFERENCE);
        if (inference_it != timings_.end()) {
            breakdown.inference_time_ms = inference_it->second.mean_ms * inference_it->second.call_count;
        }
        
        // Orchestration overhead = total - inference
        breakdown.orchestration_overhead_ms = breakdown.total_time_ms - breakdown.inference_time_ms;
        
        if (breakdown.total_time_ms > 0) {
            breakdown.overhead_percentage = (breakdown.orchestration_overhead_ms / breakdown.total_time_ms) * 100.0;
        }
        
        return breakdown;
    }
    
    // Reset all timings
    void Reset() {
        timings_.clear();
        active_phases_.clear();
    }
    
    // Get all timings
    const std::map<OrchestrationPhase, PhaseTiming>& GetTimings() const {
        return timings_;
    }
    
private:
    std::map<OrchestrationPhase, PhaseTiming> timings_;
    std::map<OrchestrationPhase, TimePoint> active_phases_;
    
    static std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

// ============================================================================
// Scoped Phase Timer (RAII)
// ============================================================================
class ScopedPhaseTimer {
public:
    ScopedPhaseTimer(OrchestrationTelemetry& telemetry, OrchestrationPhase phase)
        : telemetry_(telemetry), phase_(phase) {
        telemetry_.StartPhase(phase_);
    }
    
    ~ScopedPhaseTimer() {
        telemetry_.EndPhase(phase_);
    }
    
private:
    OrchestrationTelemetry& telemetry_;
    OrchestrationPhase phase_;
};

// Convenience macro
#define SOVEREIGN_TELEMETRY_SCOPE(telemetry, phase) \
    ScopedPhaseTimer _telemetry_timer_##__LINE__(telemetry, phase)

} // namespace rawrxd::benchmark
