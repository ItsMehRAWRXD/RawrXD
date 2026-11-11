// Chaos Injection Framework
// Simulates failure storms, mutation storms, oscillation storms, and resource pressure
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <random>
#include <functional>
#include <map>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Chaos Event Types
// ============================================================================
enum class ChaosEventType {
    NONE = 0,
    AGENT_CRASH = 1,           // Random agent crashes
    MEMORY_PRESSURE = 2,       // Simulate memory exhaustion
    CPU_SATURATION = 3,        // CPU throttling
    GPU_ERROR = 4,             // GPU kernel failure
    NETWORK_LATENCY = 5,         // Network delays
    MUTATION_STORM = 6,          // Rapid mutation injection
    OSCILLATION_STORM = 7,       // Decision oscillation
    CHECKPOINT_CORRUPTION = 8,   // Corrupt saved state
    PARTIAL_FAILURE = 9,         // Subsystem degradation
    RESOURCE_STARVATION = 10     // Starve resources
};

inline const char* ChaosEventTypeToString(ChaosEventType type) {
    switch (type) {
        case ChaosEventType::AGENT_CRASH: return "agent_crash";
        case ChaosEventType::MEMORY_PRESSURE: return "memory_pressure";
        case ChaosEventType::CPU_SATURATION: return "cpu_saturation";
        case ChaosEventType::GPU_ERROR: return "gpu_error";
        case ChaosEventType::NETWORK_LATENCY: return "network_latency";
        case ChaosEventType::MUTATION_STORM: return "mutation_storm";
        case ChaosEventType::OSCILLATION_STORM: return "oscillation_storm";
        case ChaosEventType::CHECKPOINT_CORRUPTION: return "checkpoint_corruption";
        case ChaosEventType::PARTIAL_FAILURE: return "partial_failure";
        case ChaosEventType::RESOURCE_STARVATION: return "resource_starvation";
        default: return "none";
    }
}

// ============================================================================
// Chaos Event
// ============================================================================
struct ChaosEvent {
    ChaosEventType type = ChaosEventType::NONE;
    double timestamp_ms = 0.0;
    std::string description;
    std::string target;          // Target agent/subsystem
    double severity = 0.5;       // 0.0 - 1.0
    bool recovered = false;
    double recovery_time_ms = 0.0;
    
    std::string ToJson() const {
        JsonWriter writer;
        writer.BeginObject();
        writer.WriteString("type", ChaosEventTypeToString(type));
        writer.WriteDouble("timestamp_ms", timestamp_ms);
        writer.WriteString("description", description);
        writer.WriteString("target", target);
        writer.WriteDouble("severity", severity);
        writer.WriteBool("recovered", recovered);
        writer.WriteDouble("recovery_time_ms", recovery_time_ms);
        writer.EndObject();
        return writer.Str();
    }
};

// ============================================================================
// Chaos Configuration
// ============================================================================
struct ChaosConfig {
    // Event frequencies (events per minute)
    double agent_crash_rate = 0.5;
    double memory_pressure_rate = 0.3;
    double cpu_saturation_rate = 0.2;
    double gpu_error_rate = 0.1;
    double network_latency_rate = 0.4;
    double mutation_storm_rate = 0.2;
    double oscillation_storm_rate = 0.15;
    double checkpoint_corruption_rate = 0.1;
    double partial_failure_rate = 0.3;
    double resource_starvation_rate = 0.25;
    
    // Severity ranges
    double min_severity = 0.3;
    double max_severity = 0.9;
    
    // Duration
    int duration_minutes = 10;
    
    // Seed for reproducibility
    int seed = 42;
    
    // Enable/disable specific events
    bool enable_agent_crash = true;
    bool enable_memory_pressure = true;
    bool enable_cpu_saturation = true;
    bool enable_gpu_error = true;
    bool enable_network_latency = true;
    bool enable_mutation_storm = true;
    bool enable_oscillation_storm = true;
    bool enable_checkpoint_corruption = true;
    bool enable_partial_failure = true;
    bool enable_resource_starvation = true;
};

// ============================================================================
// Chaos Injection Engine
// ============================================================================
class ChaosEngine {
public:
    ChaosEngine(const ChaosConfig& config = ChaosConfig{}) 
        : config_(config), rng_(config.seed) {}
    
    // Start chaos injection
    void Start() {
        start_time_ = Clock::now();
        events_.clear();
        is_running_ = true;
    }
    
    // Stop chaos injection
    void Stop() {
        is_running_ = false;
    }
    
    // Check if chaos should inject an event now
    std::optional<ChaosEvent> MaybeInjectEvent() {
        if (!is_running_) return std::nullopt;
        
        auto now = Clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - start_time_).count();
        
        // Check if duration exceeded
        if (elapsed > config_.duration_minutes * 60 * 1000) {
            is_running_ = false;
            return std::nullopt;
        }
        
        // Try each event type
        std::vector<ChaosEventType> possible_events;
        
        if (config_.enable_agent_crash && ShouldTrigger(config_.agent_crash_rate)) {
            possible_events.push_back(ChaosEventType::AGENT_CRASH);
        }
        if (config_.enable_memory_pressure && ShouldTrigger(config_.memory_pressure_rate)) {
            possible_events.push_back(ChaosEventType::MEMORY_PRESSURE);
        }
        if (config_.enable_cpu_saturation && ShouldTrigger(config_.cpu_saturation_rate)) {
            possible_events.push_back(ChaosEventType::CPU_SATURATION);
        }
        if (config_.enable_gpu_error && ShouldTrigger(config_.gpu_error_rate)) {
            possible_events.push_back(ChaosEventType::GPU_ERROR);
        }
        if (config_.enable_network_latency && ShouldTrigger(config_.network_latency_rate)) {
            possible_events.push_back(ChaosEventType::NETWORK_LATENCY);
        }
        if (config_.enable_mutation_storm && ShouldTrigger(config_.mutation_storm_rate)) {
            possible_events.push_back(ChaosEventType::MUTATION_STORM);
        }
        if (config_.enable_oscillation_storm && ShouldTrigger(config_.oscillation_storm_rate)) {
            possible_events.push_back(ChaosEventType::OSCILLATION_STORM);
        }
        if (config_.enable_checkpoint_corruption && ShouldTrigger(config_.checkpoint_corruption_rate)) {
            possible_events.push_back(ChaosEventType::CHECKPOINT_CORRUPTION);
        }
        if (config_.enable_partial_failure && ShouldTrigger(config_.partial_failure_rate)) {
            possible_events.push_back(ChaosEventType::PARTIAL_FAILURE);
        }
        if (config_.enable_resource_starvation && ShouldTrigger(config_.resource_starvation_rate)) {
            possible_events.push_back(ChaosEventType::RESOURCE_STARVATION);
        }
        
        if (possible_events.empty()) return std::nullopt;
        
        // Select random event
        std::uniform_int_distribution<size_t> dist(0, possible_events.size() - 1);
        auto event_type = possible_events[dist(rng_)];
        
        return CreateEvent(event_type, elapsed);
    }
    
    // Inject a specific event
    ChaosEvent InjectEvent(ChaosEventType type) {
        auto now = Clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - start_time_).count();
        return CreateEvent(type, elapsed);
    }
    
    // Get all events
    const std::vector<ChaosEvent>& GetEvents() const { return events_; }
    
    // Calculate resilience metrics
    struct ResilienceMetrics {
        double total_events = 0;
        double recovered_events = 0;
        double mean_recovery_time_ms = 0;
        double max_recovery_time_ms = 0;
        double resilience_score = 0.0;  // 0-100
        double stability_score = 0.0;   // 0-100
        
        std::string ToJson() const {
            JsonWriter writer;
            writer.BeginObject();
            writer.WriteDouble("total_events", total_events);
            writer.WriteDouble("recovered_events", recovered_events);
            writer.WriteDouble("recovery_rate", total_events > 0 ? recovered_events / total_events : 0);
            writer.WriteDouble("mean_recovery_time_ms", mean_recovery_time_ms);
            writer.WriteDouble("max_recovery_time_ms", max_recovery_time_ms);
            writer.WriteDouble("resilience_score", resilience_score);
            writer.WriteDouble("stability_score", stability_score);
            writer.EndObject();
            return writer.Str();
        }
    };
    
    ResilienceMetrics CalculateResilience() const {
        ResilienceMetrics metrics;
        metrics.total_events = events_.size();
        
        if (events_.empty()) return metrics;
        
        double total_recovery_time = 0.0;
        metrics.max_recovery_time_ms = 0.0;
        
        for (const auto& event : events_) {
            if (event.recovered) {
                metrics.recovered_events++;
                total_recovery_time += event.recovery_time_ms;
                metrics.max_recovery_time_ms = std::max(
                    metrics.max_recovery_time_ms, event.recovery_time_ms);
            }
        }
        
        metrics.mean_recovery_time_ms = metrics.recovered_events > 0 
            ? total_recovery_time / metrics.recovered_events 
            : 0.0;
        
        // Calculate resilience score
        double recovery_rate = metrics.total_events > 0 
            ? metrics.recovered_events / metrics.total_events 
            : 0.0;
        
        // Faster recovery = higher score
        double recovery_speed_score = metrics.mean_recovery_time_ms > 0 
            ? std::max(0.0, 100.0 - (metrics.mean_recovery_time_ms / 100.0)) 
            : 100.0;
        
        metrics.resilience_score = (recovery_rate * 70.0) + (recovery_speed_score * 0.3);
        
        // Calculate stability score (fewer events = more stable)
        double event_rate = metrics.total_events / (config_.duration_minutes * 60.0);
        metrics.stability_score = std::max(0.0, 100.0 - (event_rate * 10.0));
        
        return metrics;
    }
    
private:
    ChaosConfig config_;
    std::mt19937 rng_;
    TimePoint start_time_;
    std::vector<ChaosEvent> events_;
    bool is_running_ = false;
    
    bool ShouldTrigger(double rate_per_minute) {
        // Convert rate to probability per check (assuming checks every 100ms)
        double probability = rate_per_minute / (60.0 * 10.0); // 10 checks per second
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(rng_) < probability;
    }
    
    ChaosEvent CreateEvent(ChaosEventType type, double timestamp_ms) {
        ChaosEvent event;
        event.type = type;
        event.timestamp_ms = timestamp_ms;
        
        // Generate severity
        std::uniform_real_distribution<double> severity_dist(
            config_.min_severity, config_.max_severity);
        event.severity = severity_dist(rng_);
        
        // Generate description and target
        switch (type) {
            case ChaosEventType::AGENT_CRASH:
                event.description = "Random agent crash during execution";
                event.target = "agent_" + std::to_string(rng_() % 16);
                break;
            case ChaosEventType::MEMORY_PRESSURE:
                event.description = "Memory pressure exceeding threshold";
                event.target = "system_memory";
                break;
            case ChaosEventType::CPU_SATURATION:
                event.description = "CPU saturation detected";
                event.target = "system_cpu";
                break;
            case ChaosEventType::GPU_ERROR:
                event.description = "GPU kernel execution error";
                event.target = "gpu_compute";
                break;
            case ChaosEventType::NETWORK_LATENCY:
                event.description = "Network latency spike";
                event.target = "network_io";
                break;
            case ChaosEventType::MUTATION_STORM:
                event.description = "Rapid mutation injection storm";
                event.target = "mutation_engine";
                break;
            case ChaosEventType::OSCILLATION_STORM:
                event.description = "Decision oscillation storm";
                event.target = "decision_engine";
                break;
            case ChaosEventType::CHECKPOINT_CORRUPTION:
                event.description = "Checkpoint data corruption";
                event.target = "checkpoint_store";
                break;
            case ChaosEventType::PARTIAL_FAILURE:
                event.description = "Partial subsystem failure";
                event.target = "subsystem_" + std::to_string(rng_() % 4);
                break;
            case ChaosEventType::RESOURCE_STARVATION:
                event.description = "Resource starvation condition";
                event.target = "resource_scheduler";
                break;
            default:
                event.description = "Unknown chaos event";
                event.target = "unknown";
        }
        
        events_.push_back(event);
        return event;
    }
};

} // namespace rawrxd::benchmark
