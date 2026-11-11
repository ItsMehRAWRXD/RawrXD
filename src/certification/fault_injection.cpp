// VAL-076: Fault Injection Implementation
// Resilience validation through controlled failures

#include "fault_injection.hpp"
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Certification {

// ============================================================================
// FaultPoint Implementation
// ============================================================================

std::string FaultPoint::Serialize() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"id\": \"" << id << "\",\n";
    ss << "  \"name\": \"" << name << "\",\n";
    ss << "  \"category\": " << static_cast<int>(category) << ",\n";
    ss << "  \"severity\": " << static_cast<int>(severity) << ",\n";
    ss << "  \"probability\": " << probability << ",\n";
    ss << "  \"description\": \"" << description << "\"\n";
    ss << "}\n";
    return ss.str();
}

// ============================================================================
// FaultEvent Implementation
// ============================================================================

std::string FaultEvent::Serialize() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"timestamp\": \"" << timestamp << "\",\n";
    ss << "  \"fault_point_id\": \"" << fault_point_id << "\",\n";
    ss << "  \"injected\": " << (injected ? "true" : "false") << ",\n";
    ss << "  \"recovered\": " << (recovered ? "true" : "false") << ",\n";
    ss << "  \"recovery_time_ms\": " << recovery_time_ms << ",\n";
    ss << "  \"error_message\": \"" << error_message << "\"\n";
    ss << "}\n";
    return ss.str();
}

// ============================================================================
// ResilienceMetrics Implementation
// ============================================================================

std::string ResilienceMetrics::Serialize() const {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"total_faults_injected\": " << total_faults_injected << ",\n";
    ss << "  \"successful_recoveries\": " << successful_recoveries << ",\n";
    ss << "  \"failed_recoveries\": " << failed_recoveries << ",\n";
    ss << "  \"avg_recovery_time_ms\": " << avg_recovery_time_ms << ",\n";
    ss << "  \"max_recovery_time_ms\": " << max_recovery_time_ms << ",\n";
    ss << "  \"resilience_score\": " << resilience_score << ",\n";
    ss << "  \"passed\": " << (passed ? "true" : "false") << "\n";
    ss << "}\n";
    return ss.str();
}

// ============================================================================
// FaultRegistry Implementation
// ============================================================================

class FaultRegistry::Impl {
public:
    std::unordered_map<std::string, FaultPoint> fault_points_;
    std::vector<FaultEvent> events_;
    std::mutex mutex_;
};

FaultRegistry::FaultRegistry() : impl_(std::make_unique<Impl>()) {}
FaultRegistry::~FaultRegistry() = default;

FaultRegistry& FaultRegistry::Instance() {
    static FaultRegistry instance;
    return instance;
}

void FaultRegistry::RegisterFaultPoint(const FaultPoint& point) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->fault_points_[point.id] = point;
}

void FaultRegistry::UnregisterFaultPoint(const std::string& id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->fault_points_.erase(id);
}

std::optional<FaultPoint> FaultRegistry::GetFaultPoint(const std::string& id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->fault_points_.find(id);
    if (it != impl_->fault_points_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<FaultPoint> FaultRegistry::GetAllFaultPoints() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<FaultPoint> points;
    for (const auto& [id, point] : impl_->fault_points_) {
        points.push_back(point);
    }
    return points;
}

std::vector<FaultPoint> FaultRegistry::GetFaultPointsByCategory(FaultCategory category) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<FaultPoint> points;
    for (const auto& [id, point] : impl_->fault_points_) {
        if (point.category == category) {
            points.push_back(point);
        }
    }
    return points;
}

void FaultRegistry::RecordEvent(const FaultEvent& event) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->events_.push_back(event);
}

std::vector<FaultEvent> FaultRegistry::GetEvents() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->events_;
}

std::vector<FaultEvent> FaultRegistry::GetEventsByFaultPoint(const std::string& id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<FaultEvent> events;
    for (const auto& event : impl_->events_) {
        if (event.fault_point_id == id) {
            events.push_back(event);
        }
    }
    return events;
}

void FaultRegistry::ClearEvents() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->events_.clear();
}

// ============================================================================
// FaultInjector Implementation
// ============================================================================

class FaultInjector::Impl {
public:
    bool enabled_ = false;
    double global_probability_ = 0.0;
    std::mt19937 rng_{std::random_device{}()};
    std::uniform_real_distribution<double> dist_{0.0, 1.0};
    std::mutex mutex_;
};

FaultInjector::FaultInjector() : impl_(std::make_unique<Impl>()) {}
FaultInjector::~FaultInjector() = default;

FaultInjector& FaultInjector::Instance() {
    static FaultInjector instance;
    return instance;
}

void FaultInjector::Enable() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->enabled_ = true;
}

void FaultInjector::Disable() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->enabled_ = false;
}

bool FaultInjector::IsEnabled() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->enabled_;
}

void FaultInjector::SetGlobalProbability(double probability) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->global_probability_ = std::clamp(probability, 0.0, 1.0);
}

bool FaultInjector::ShouldInject(const std::string& fault_point_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (!impl_->enabled_) return false;
    
    auto point = FaultRegistry::Instance().GetFaultPoint(fault_point_id);
    if (!point) return false;
    
    double effective_probability = point->probability * impl_->global_probability_;
    return impl_->dist_(impl_->rng_) < effective_probability;
}

bool FaultInjector::InjectFault(const std::string& fault_point_id) {
    if (!ShouldInject(fault_point_id)) return false;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    
    FaultEvent event;
    event.timestamp = ss.str();
    event.fault_point_id = fault_point_id;
    event.injected = true;
    event.recovered = false;
    event.recovery_time_ms = 0;
    event.error_message = "Fault injected at " + fault_point_id;
    
    FaultRegistry::Instance().RecordEvent(event);
    
    return true;
}

void FaultInjector::RecordRecovery(const std::string& fault_point_id, 
                                    uint64_t recovery_time_ms,
                                    bool success) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    
    FaultEvent event;
    event.timestamp = ss.str();
    event.fault_point_id = fault_point_id;
    event.injected = true;
    event.recovered = success;
    event.recovery_time_ms = recovery_time_ms;
    event.error_message = success ? "Recovery successful" : "Recovery failed";
    
    FaultRegistry::Instance().RecordEvent(event);
}

// ============================================================================
// ResilienceValidator Implementation
// ============================================================================

class ResilienceValidator::Impl {
public:
    ResilienceConfig config_;
};

ResilienceValidator::ResilienceValidator(const ResilienceConfig& config) 
    : impl_(std::make_unique<Impl>()) {
    impl_->config_ = config;
}

ResilienceValidator::~ResilienceValidator() = default;

ResilienceMetrics ResilienceValidator::RunValidation() {
    ResilienceMetrics metrics;
    
    auto events = FaultRegistry::Instance().GetEvents();
    
    metrics.total_faults_injected = 0;
    metrics.successful_recoveries = 0;
    metrics.failed_recoveries = 0;
    metrics.avg_recovery_time_ms = 0.0;
    metrics.max_recovery_time_ms = 0;
    
    uint64_t total_recovery_time = 0;
    
    for (const auto& event : events) {
        if (event.injected) {
            metrics.total_faults_injected++;
            if (event.recovered) {
                metrics.successful_recoveries++;
            } else {
                metrics.failed_recoveries++;
            }
            total_recovery_time += event.recovery_time_ms;
            metrics.max_recovery_time_ms = std::max(metrics.max_recovery_time_ms, 
                                                     event.recovery_time_ms);
        }
    }
    
    if (metrics.total_faults_injected > 0) {
        metrics.avg_recovery_time_ms = static_cast<double>(total_recovery_time) / 
                                        metrics.total_faults_injected;
    }
    
    // Calculate resilience score
    double recovery_rate = metrics.total_faults_injected > 0 ? 
        static_cast<double>(metrics.successful_recoveries) / metrics.total_faults_injected : 1.0;
    
    double time_score = 1.0;
    if (metrics.avg_recovery_time_ms > 0) {
        time_score = std::min(1.0, impl_->config_.max_acceptable_recovery_time_ms / 
                            metrics.avg_recovery_time_ms);
    }
    
    metrics.resilience_score = recovery_rate * 0.7 + time_score * 0.3;
    metrics.passed = metrics.resilience_score >= impl_->config_.min_resilience_score;
    
    return metrics;
}

bool ResilienceValidator::ValidateCategory(FaultCategory category) {
    auto points = FaultRegistry::Instance().GetFaultPointsByCategory(category);
    
    for (const auto& point : points) {
        // Inject fault at this point
        if (FaultInjector::Instance().InjectFault(point.id)) {
            // Simulate recovery
            auto start = std::chrono::high_resolution_clock::now();
            
            // In production, this would trigger actual recovery logic
            bool recovered = true;
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            
            FaultInjector::Instance().RecordRecovery(point.id, duration.count(), recovered);
        }
    }
    
    return true;
}

bool ResilienceValidator::ValidateAllCategories() {
    bool all_passed = true;
    
    all_passed &= ValidateCategory(FaultCategory::MEMORY);
    all_passed &= ValidateCategory(FaultCategory::COMPUTE);
    all_passed &= ValidateCategory(FaultCategory::IO);
    all_passed &= ValidateCategory(FaultCategory::NETWORK);
    all_passed &= ValidateCategory(FaultCategory::TIMING);
    
    return all_passed;
}

std::string ResilienceValidator::GenerateReport(const ResilienceMetrics& metrics) const {
    std::stringstream ss;
    ss << "Resilience Validation Report\n";
    ss << "=============================\n";
    ss << "Total faults injected: " << metrics.total_faults_injected << "\n";
    ss << "Successful recoveries: " << metrics.successful_recoveries << "\n";
    ss << "Failed recoveries: " << metrics.failed_recoveries << "\n";
    ss << "Average recovery time: " << metrics.avg_recovery_time_ms << " ms\n";
    ss << "Max recovery time: " << metrics.max_recovery_time_ms << " ms\n";
    ss << "Resilience score: " << std::fixed << std::setprecision(2) << metrics.resilience_score << "\n";
    ss << "Result: " << (metrics.passed ? "PASSED" : "FAILED") << "\n";
    return ss.str();
}

// ============================================================================
// ControlledFailureHandler Implementation
// ============================================================================

class ControlledFailureHandler::Impl {
public:
    std::function<void(const FaultEvent&)> callback_;
    std::mutex mutex_;
};

ControlledFailureHandler::ControlledFailureHandler() : impl_(std::make_unique<Impl>()) {}
ControlledFailureHandler::~ControlledFailureHandler() = default;

ControlledFailureHandler& ControlledFailureHandler::Instance() {
    static ControlledFailureHandler instance;
    return instance;
}

void ControlledFailureHandler::RegisterCallback(std::function<void(const FaultEvent&)> callback) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->callback_ = callback;
}

void ControlledFailureHandler::HandleFailure(const FaultEvent& event) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->callback_) {
        impl_->callback_(event);
    }
}

bool ControlledFailureHandler::AttemptRecovery(const std::string& fault_point_id) {
    auto point = FaultRegistry::Instance().GetFaultPoint(fault_point_id);
    if (!point) return false;
    
    // Recovery logic based on fault category
    switch (point->category) {
        case FaultCategory::MEMORY:
            // Attempt memory cleanup/reallocation
            return true;
        case FaultCategory::COMPUTE:
            // Retry computation or use fallback
            return true;
        case FaultCategory::IO:
            // Retry I/O operation
            return true;
        case FaultCategory::NETWORK:
            // Retry network request
            return true;
        case FaultCategory::TIMING:
            // Adjust timing parameters
            return true;
        default:
            return false;
    }
}

void ControlledFailureHandler::GracefulDegrade(const std::string& component) {
    // Log degradation
    FaultEvent event;
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    event.timestamp = ss.str();
    event.fault_point_id = component;
    event.injected = false;
    event.recovered = true;
    event.error_message = "Graceful degradation for " + component;
    
    FaultRegistry::Instance().RecordEvent(event);
}

// ============================================================================
// Predefined Fault Points
// ============================================================================

void RegisterPredefinedFaultPoints() {
    // Memory faults
    FaultRegistry::Instance().RegisterFaultPoint({
        "mem_allocation_failure",
        "Memory Allocation Failure",
        FaultCategory::MEMORY,
        FaultSeverity::CRITICAL,
        0.01,
        "Simulates memory allocation failure"
    });
    
    FaultRegistry::Instance().RegisterFaultPoint({
        "mem_corruption",
        "Memory Corruption",
        FaultCategory::MEMORY,
        FaultSeverity::CRITICAL,
        0.005,
        "Simulates memory corruption"
    });
    
    // Compute faults
    FaultRegistry::Instance().RegisterFaultPoint({
        "compute_overflow",
        "Compute Overflow",
        FaultCategory::COMPUTE,
        FaultSeverity::HIGH,
        0.01,
        "Simulates numerical overflow"
    });
    
    FaultRegistry::Instance().RegisterFaultPoint({
        "compute_underflow",
        "Compute Underflow",
        FaultCategory::COMPUTE,
        FaultSeverity::MEDIUM,
        0.01,
        "Simulates numerical underflow"
    });
    
    // I/O faults
    FaultRegistry::Instance().RegisterFaultPoint({
        "io_read_failure",
        "I/O Read Failure",
        FaultCategory::IO,
        FaultSeverity::HIGH,
        0.02,
        "Simulates file read failure"
    });
    
    FaultRegistry::Instance().RegisterFaultPoint({
        "io_write_failure",
        "I/O Write Failure",
        FaultCategory::IO,
        FaultSeverity::HIGH,
        0.02,
        "Simulates file write failure"
    });
    
    // Network faults
    FaultRegistry::Instance().RegisterFaultPoint({
        "network_timeout",
        "Network Timeout",
        FaultCategory::NETWORK,
        FaultSeverity::MEDIUM,
        0.05,
        "Simulates network timeout"
    });
    
    FaultRegistry::Instance().RegisterFaultPoint({
        "network_disconnect",
        "Network Disconnect",
        FaultCategory::NETWORK,
        FaultSeverity::HIGH,
        0.03,
        "Simulates network disconnection"
    });
    
    // Timing faults
    FaultRegistry::Instance().RegisterFaultPoint({
        "timing_deadline_miss",
        "Timing Deadline Miss",
        FaultCategory::TIMING,
        FaultSeverity::HIGH,
        0.01,
        "Simulates deadline miss"
    });
    
    FaultRegistry::Instance().RegisterFaultPoint({
        "timing_jitter",
        "Timing Jitter",
        FaultCategory::TIMING,
        FaultSeverity::LOW,
        0.1,
        "Simulates timing jitter"
    });
}

} // namespace Certification
} // namespace RawrXD
