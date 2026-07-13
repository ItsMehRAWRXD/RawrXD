#include "rawrxd/deployment/ABTesting.hpp"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace rawrxd {
namespace deployment {

ABTestingManager::ABTestingManager() : rng_(std::random_device{}()) {}

ABTestingManager::~ABTestingManager() = default;

bool ABTestingManager::Initialize(const std::string& storagePath) {
    storagePath_ = storagePath;
    LoadTests();
    return true;
}

bool ABTestingManager::CreateTest(const ABTestConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (tests_.find(config.testId) != tests_.end()) {
        return false; // Test already exists
    }
    
    // Validate traffic split
    float totalTraffic = 0.0f;
    for (const auto& variant : config.variants) {
        totalTraffic += variant.trafficPercentage;
    }
    
    if (std::abs(totalTraffic - 1.0f) > 0.001f) {
        return false; // Traffic doesn't sum to 100%
    }
    
    tests_[config.testId] = config;
    testStatus_[config.testId] = TestStatus::DRAFT;
    
    SaveTest(config);
    return true;
}

bool ABTestingManager::StartTest(const std::string& testId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = tests_.find(testId);
    if (it == tests_.end()) {
        return false;
    }
    
    testStatus_[testId] = TestStatus::RUNNING;
    it->second.startTime = std::chrono::system_clock::now();
    
    return true;
}

bool ABTestingManager::StopTest(const std::string& testId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = tests_.find(testId);
    if (it == tests_.end()) {
        return false;
    }
    
    testStatus_[testId] = TestStatus::COMPLETED;
    it->second.endTime = std::chrono::system_clock::now();
    
    return true;
}

std::string ABTestingManager::GetVariantForUser(const std::string& testId, 
                                                 const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto testIt = tests_.find(testId);
    if (testIt == tests_.end()) {
        return ""; // Test not found
    }
    
    // Check if user already assigned
    auto userIt = userAssignments_.find(testId);
    if (userIt != userAssignments_.end()) {
        auto assignmentIt = userIt->second.find(userId);
        if (assignmentIt != userIt->second.end() && assignmentIt->second.sticky) {
            return assignmentIt->second.variantId;
        }
    }
    
    // Check targeting
    const auto& config = testIt->second;
    
    // Check user targeting
    if (!config.targetUsers.empty()) {
        if (std::find(config.targetUsers.begin(), config.targetUsers.end(), userId) 
            == config.targetUsers.end()) {
            return ""; // User not targeted
        }
    }
    
    // Check traffic allocation
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    if (dist(rng_) > config.trafficAllocation) {
        return ""; // User not in test
    }
    
    // Assign variant
    std::string variantId = HashUserToVariant(userId, config.variants);
    
    // Store assignment
    UserAssignment assignment;
    assignment.userId = userId;
    assignment.testId = testId;
    assignment.variantId = variantId;
    assignment.assignmentTime = std::chrono::system_clock::now();
    assignment.sticky = true;
    
    userAssignments_[testId][userId] = assignment;
    
    return variantId;
}

void ABTestingManager::RecordEvent(const std::string& testId, const std::string& variantId,
                                    const std::string& userId, const std::string& metricName,
                                    double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = testId + "/" + variantId + "/" + metricName;
    metricData_[key].push_back(value);
}

ExperimentResult ABTestingManager::GetTestResults(const std::string& testId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ExperimentResult result;
    result.testId = testId;
    
    auto testIt = tests_.find(testId);
    if (testIt == tests_.end()) {
        return result;
    }
    
    const auto& config = testIt->second;
    
    // Compute metrics for each variant
    for (const auto& variant : config.variants) {
        result.variantId = variant.variantId;
        
        for (const auto& metric : config.primaryMetrics) {
            std::string key = testId + "/" + variant.variantId + "/" + metric;
            auto it = metricData_.find(key);
            
            if (it != metricData_.end() && !it->second.empty()) {
                const auto& values = it->second;
                
                ExperimentResult::MetricStats stats;
                stats.metricName = metric;
                stats.mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
                stats.min = *std::min_element(values.begin(), values.end());
                stats.max = *std::max_element(values.begin(), values.end());
                
                // Compute standard deviation
                double variance = 0.0;
                for (double v : values) {
                    variance += (v - stats.mean) * (v - stats.mean);
                }
                stats.stdDev = std::sqrt(variance / values.size());
                
                // Compute percentiles
                std::vector<double> sorted = values;
                std::sort(sorted.begin(), sorted.end());
                stats.p50 = sorted[sorted.size() * 0.5];
                stats.p95 = sorted[sorted.size() * 0.95];
                stats.p99 = sorted[sorted.size() * 0.99];
                
                result.metrics[metric] = stats;
            }
        }
    }
    
    // Statistical tests
    if (config.variants.size() >= 2) {
        const auto& controlVariant = config.variants[0];
        
        for (size_t i = 1; i < config.variants.size(); ++i) {
            const auto& treatmentVariant = config.variants[i];
            
            for (const auto& metric : config.primaryMetrics) {
                std::string controlKey = testId + "/" + controlVariant.variantId + "/" + metric;
                std::string treatmentKey = testId + "/" + treatmentVariant.variantId + "/" + metric;
                
                auto controlIt = metricData_.find(controlKey);
                auto treatmentIt = metricData_.find(treatmentKey);
                
                if (controlIt != metricData_.end() && treatmentIt != metricData_.end()) {
                    ExperimentResult::StatisticalTest test;
                    test.metricName = metric;
                    test.controlMean = std::accumulate(controlIt->second.begin(), 
                                                       controlIt->second.end(), 0.0) 
                                     / controlIt->second.size();
                    test.treatmentMean = std::accumulate(treatmentIt->second.begin(),
                                                          treatmentIt->second.end(), 0.0)
                                        / treatmentIt->second.size();
                    test.relativeDifference = (test.treatmentMean - test.controlMean) / test.controlMean;
                    test.pValue = ComputePValue(controlIt->second, treatmentIt->second);
                    test.isSignificant = test.pValue < config.significanceLevel;
                    test.confidenceIntervalLower = ComputeConfidenceInterval(treatmentIt->second, 0.95, false);
                    test.confidenceIntervalUpper = ComputeConfidenceInterval(treatmentIt->second, 0.95, true);
                    
                    result.testResults.push_back(test);
                }
            }
        }
    }
    
    return result;
}

std::vector<ABTestConfig> ABTestingManager::GetActiveTests() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ABTestConfig> activeTests;
    
    for (const auto& pair : testStatus_) {
        if (pair.second == TestStatus::RUNNING) {
            auto it = tests_.find(pair.first);
            if (it != tests_.end()) {
                activeTests.push_back(it->second);
            }
        }
    }
    
    return activeTests;
}

ABTestingManager::TestStatus ABTestingManager::GetTestStatus(const std::string& testId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = testStatus_.find(testId);
    if (it != testStatus_.end()) {
        return it->second;
    }
    
    return TestStatus::DRAFT;
}

std::string ABTestingManager::GenerateReport(const std::string& testId) {
    auto result = GetTestResults(testId);
    auto testIt = tests_.find(testId);
    
    if (testIt == tests_.end()) {
        return "Test not found";
    }
    
    const auto& config = testIt->second;
    
    std::stringstream report;
    report << "A/B Test Report: " << config.testName << "\n";
    report << "================================\n\n";
    report << "Test ID: " << testId << "\n";
    report << "Description: " << config.description << "\n\n";
    
    report << "Variants:\n";
    for (const auto& variant : config.variants) {
        report << "  - " << variant.name << " (" << variant.variantId << "): "
               << variant.trafficPercentage * 100 << "%\n";
    }
    
    report << "\nMetrics:\n";
    for (const auto& pair : result.metrics) {
        report << "  " << pair.first << ":\n";
        report << "    Mean: " << std::fixed << std::setprecision(4) << pair.second.mean << "\n";
        report << "    StdDev: " << pair.second.stdDev << "\n";
        report << "    P95: " << pair.second.p95 << "\n";
    }
    
    report << "\nStatistical Tests:\n";
    for (const auto& test : result.testResults) {
        report << "  " << test.metricName << ":\n";
        report << "    Control: " << test.controlMean << "\n";
        report << "    Treatment: " << test.treatmentMean << "\n";
        report << "    Relative Difference: " << test.relativeDifference * 100 << "%\n";
        report << "    P-value: " << test.pValue << "\n";
        report << "    Significant: " << (test.isSignificant ? "Yes" : "No") << "\n";
    }
    
    return report.str();
}

void ABTestingManager::CheckAndAutoStopTests() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    for (auto& pair : tests_) {
        const auto& config = pair.second;
        auto status = testStatus_[pair.first];
        
        if (status != TestStatus::RUNNING) continue;
        
        // Check if end time reached
        if (now > config.endTime) {
            testStatus_[pair.first] = TestStatus::COMPLETED;
            continue;
        }
        
        // Check if minimum sample size reached and significant
        // ... implementation
    }
}

void ABTestingManager::SaveTest(const ABTestConfig& config) {
    // Save to file
    std::string filename = storagePath_ + "/" + config.testId + ".json";
    // ... JSON serialization
}

void ABTestingManager::LoadTests() {
    // Load from directory
    // ... JSON deserialization
}

std::string ABTestingManager::HashUserToVariant(const std::string& userId,
                                                 const std::vector<ABTestConfig::Variant>& variants) {
    // Simple hash-based assignment
    std::hash<std::string> hasher;
    size_t hash = hasher(userId);
    
    float cumulative = 0.0f;
    float normalizedHash = static_cast<float>(hash % 10000) / 10000.0f;
    
    for (const auto& variant : variants) {
        cumulative += variant.trafficPercentage;
        if (normalizedHash <= cumulative) {
            return variant.variantId;
        }
    }
    
    return variants.empty() ? "" : variants.back().variantId;
}

double ABTestingManager::ComputePValue(const std::vector<double>& control,
                                        const std::vector<double>& treatment) {
    // Simplified t-test
    double controlMean = std::accumulate(control.begin(), control.end(), 0.0) / control.size();
    double treatmentMean = std::accumulate(treatment.begin(), treatment.end(), 0.0) / treatment.size();
    
    double controlVar = 0.0;
    for (double v : control) {
        controlVar += (v - controlMean) * (v - controlMean);
    }
    controlVar /= control.size();
    
    double treatmentVar = 0.0;
    for (double v : treatment) {
        treatmentVar += (v - treatmentMean) * (v - treatmentMean);
    }
    treatmentVar /= treatment.size();
    
    double pooledStd = std::sqrt((controlVar + treatmentVar) / 2);
    double tStat = (treatmentMean - controlMean) / (pooledStd * std::sqrt(2.0 / control.size()));
    
    // Approximate p-value (simplified)
    return std::min(1.0, std::abs(tStat) / 3.0);
}

double ABTestingManager::ComputeConfidenceInterval(const std::vector<double>& data,
                                                      double confidenceLevel, bool upper) {
    if (data.empty()) return 0.0;
    
    double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
    
    double variance = 0.0;
    for (double v : data) {
        variance += (v - mean) * (v - mean);
    }
    variance /= data.size();
    
    double stdDev = std::sqrt(variance);
    double zScore = 1.96; // 95% confidence
    
    double margin = zScore * stdDev / std::sqrt(data.size());
    
    return upper ? mean + margin : mean - margin;
}

// FeatureFlags implementation
FeatureFlags& FeatureFlags::GetInstance() {
    static FeatureFlags instance;
    return instance;
}

bool FeatureFlags::Initialize(const std::string& configPath) {
    configPath_ = configPath;
    LoadFromFile();
    return true;
}

bool FeatureFlags::IsEnabled(const std::string& flagName, const std::string& userId,
                              const std::string& region) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = flags_.find(flagName);
    if (it == flags_.end()) {
        return false; // Flag doesn't exist
    }
    
    const auto& flag = it->second;
    
    // Check if explicitly enabled for user
    if (!userId.empty() && 
        std::find(flag.enabledForUsers.begin(), flag.enabledForUsers.end(), userId) 
        != flag.enabledForUsers.end()) {
        return true;
    }
    
    // Check if enabled for region
    if (!region.empty() &&
        std::find(flag.enabledForRegions.begin(), flag.enabledForRegions.end(), region)
        != flag.enabledForRegions.end()) {
        return true;
    }
    
    // Check rollout percentage
    if (flag.rolloutPercentage >= 100.0f) {
        return flag.enabled;
    }
    
    if (!userId.empty()) {
        std::hash<std::string> hasher;
        size_t hash = hasher(userId + flagName);
        float userPercent = static_cast<float>(hash % 10000) / 100.0f;
        return userPercent < flag.rolloutPercentage && flag.enabled;
    }
    
    return flag.enabled;
}

void FeatureFlags::SetFlag(const std::string& flagName, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    flags_[flagName].name = flagName;
    flags_[flagName].enabled = enabled;
    flags_[flagName].updatedAt = std::chrono::system_clock::now();
    
    SaveToFile();
}

void FeatureFlags::SetFlagRollout(const std::string& flagName, float percentage) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    flags_[flagName].name = flagName;
    flags_[flagName].rolloutPercentage = percentage;
    flags_[flagName].updatedAt = std::chrono::system_clock::now();
    
    SaveToFile();
}

void FeatureFlags::EnableForUser(const std::string& flagName, const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& flag = flags_[flagName];
    flag.name = flagName;
    
    if (std::find(flag.enabledForUsers.begin(), flag.enabledForUsers.end(), userId)
        == flag.enabledForUsers.end()) {
        flag.enabledForUsers.push_back(userId);
    }
    
    flag.updatedAt = std::chrono::system_clock::now();
    SaveToFile();
}

void FeatureFlags::EnableForRegion(const std::string& flagName, const std::string& region) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& flag = flags_[flagName];
    flag.name = flagName;
    
    if (std::find(flag.enabledForRegions.begin(), flag.enabledForRegions.end(), region)
        == flag.enabledForRegions.end()) {
        flag.enabledForRegions.push_back(region);
    }
    
    flag.updatedAt = std::chrono::system_clock::now();
    SaveToFile();
}

std::vector<FeatureFlags::Flag> FeatureFlags::GetAllFlags() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Flag> result;
    for (const auto& pair : flags_) {
        result.push_back(pair.second);
    }
    return result;
}

void FeatureFlags::SaveToFile() {
    // JSON serialization
}

void FeatureFlags::LoadFromFile() {
    // JSON deserialization
}

// CanaryDeployment implementation
CanaryDeployment::CanaryDeployment() = default;

CanaryDeployment::~CanaryDeployment() {
    if (running_) {
        running_ = false;
        if (evaluationThread_.joinable()) {
            evaluationThread_.join();
        }
    }
}

bool CanaryDeployment::Start(const CanaryConfig& config) {
    config_ = config;
    status_ = Status::RUNNING;
    running_ = true;
    
    evaluationThread_ = std::thread(&CanaryDeployment::EvaluationLoop, this);
    
    return true;
}

bool CanaryDeployment::ShouldUseCanary(const std::string& requestId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (status_ != Status::RUNNING) {
        return false;
    }
    
    // Check if already assigned
    auto it = canaryAssignments_.find(requestId);
    if (it != canaryAssignments_.end()) {
        return it->second;
    }
    
    // Assign based on percentage
    std::hash<std::string> hasher;
    size_t hash = hasher(requestId);
    float normalized = static_cast<float>(hash % 10000) / 100.0f;
    
    bool useCanary = normalized < config_.canaryPercentage;
    canaryAssignments_[requestId] = useCanary;
    
    return useCanary;
}

void CanaryDeployment::RecordCanaryMetrics(const std::string& requestId, bool success, float latencyMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    canaryLatencies_.push_back(latencyMs);
    canaryTotal_++;
    if (!success) {
        canaryErrors_++;
    }
}

void CanaryDeployment::RecordBaselineMetrics(const std::string& requestId, bool success, float latencyMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    baselineLatencies_.push_back(latencyMs);
    baselineTotal_++;
    if (!success) {
        baselineErrors_++;
    }
}

void CanaryDeployment::Evaluate() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (canaryTotal_ < config_.minSamples) {
        return;
    }
    
    if (ShouldPromote()) {
        Promote();
    } else if (ShouldRollback()) {
        Rollback();
    } else {
        // Increase canary percentage
        config_.canaryPercentage = std::min(config_.canaryPercentage + 5.0f, 
                                               config_.maxCanaryPercentage);
    }
}

void CanaryDeployment::Promote() {
    status_ = Status::PROMOTED;
    running_ = false;
}

void CanaryDeployment::Rollback() {
    status_ = Status::ROLLED_BACK;
    running_ = false;
}

CanaryDeployment::Status CanaryDeployment::GetStatus() const {
    return status_;
}

CanaryDeployment::CanaryMetrics CanaryDeployment::GetCanaryMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    CanaryMetrics metrics;
    if (canaryTotal_ > 0) {
        metrics.errorRate = static_cast<float>(canaryErrors_) / canaryTotal_;
        metrics.totalRequests = canaryTotal_;
    }
    
    if (!canaryLatencies_.empty()) {
        std::vector<float> sorted = canaryLatencies_;
        std::sort(sorted.begin(), sorted.end());
        metrics.latencyP95 = sorted[sorted.size() * 0.95];
        metrics.latencyP99 = sorted[sorted.size() * 0.99];
    }
    
    return metrics;
}

CanaryDeployment::CanaryMetrics CanaryDeployment::GetBaselineMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    CanaryMetrics metrics;
    if (baselineTotal_ > 0) {
        metrics.errorRate = static_cast<float>(baselineErrors_) / baselineTotal_;
        metrics.totalRequests = baselineTotal_;
    }
    
    if (!baselineLatencies_.empty()) {
        std::vector<float> sorted = baselineLatencies_;
        std::sort(sorted.begin(), sorted.end());
        metrics.latencyP95 = sorted[sorted.size() * 0.95];
        metrics.latencyP99 = sorted[sorted.size() * 0.99];
    }
    
    return metrics;
}

void CanaryDeployment::EvaluationLoop() {
    while (running_) {
        std::this_thread::sleep_for(config_.evaluationInterval);
        Evaluate();
    }
}

bool CanaryDeployment::ShouldPromote() {
    if (canaryTotal_ == 0) return false;
    
    float errorRate = static_cast<float>(canaryErrors_) / canaryTotal_;
    return errorRate <= config_.autoPromotionThreshold;
}

bool CanaryDeployment::ShouldRollback() {
    if (canaryTotal_ == 0) return false;
    
    float errorRate = static_cast<float>(canaryErrors_) / canaryTotal_;
    return errorRate >= config_.autoRollbackThreshold;
}

} // namespace deployment
} // namespace rawrxd
