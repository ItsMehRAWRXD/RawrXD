// RawrXD A/B Testing Framework Implementation
// Phase V.3: A/B testing and experimentation platform

#include "ABTestingFramework.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <math>

namespace RawrXD {
namespace Monitoring {

// ============================================================================
// ABTestingFramework Implementation
// ============================================================================

ABTestingFramework::ABTestingFramework() = default;

ABTestingFramework::~ABTestingFramework() {
    if (running_) {
        shutdown();
    }
}

bool ABTestingFramework::initialize(const std::string& configPath) {
    if (running_) {
        return true;
    }
    
    running_ = true;
    
    // Start scheduler thread for auto-start/stop
    schedulerThread_ = std::thread([this]() {
        while (running_) {
            checkExperimentSchedule();
            autoStopExperiments();
            std::this_thread::sleep_for(std::chrono::seconds(60));
        }
    });
    
    return true;
}

bool ABTestingFramework::shutdown() {
    if (!running_) {
        return true;
    }
    
    running_ = false;
    
    if (schedulerThread_.joinable()) {
        schedulerThread_.join();
    }
    
    return true;
}

// ============================================================================
// Experiment Management
// ============================================================================

std::string ABTestingFramework::createExperiment(const Experiment& experiment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = experiment.id.empty() ? generateExperimentId() : experiment.id;
    
    Experiment exp = experiment;
    exp.id = id;
    exp.createdAt = std::chrono::system_clock::now();
    exp.updatedAt = exp.createdAt;
    
    if (exp.status == ExperimentStatus::DRAFT) {
        // Validate experiment
        if (exp.variants.size() < 2) {
            return "";  // Need at least 2 variants
        }
        
        // Ensure one control variant
        bool hasControl = false;
        for (auto& variant : exp.variants) {
            if (variant.isControl) {
                hasControl = true;
                break;
            }
        }
        if (!hasControl && !exp.variants.empty()) {
            exp.variants[0].isControl = true;
        }
    }
    
    experiments_[id] = exp;
    return id;
}

bool ABTestingFramework::updateExperiment(const std::string& experimentId, const Experiment& experiment) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it == experiments_.end()) {
        return false;
    }
    
    // Only allow updates to draft experiments
    if (it->second.status != ExperimentStatus::DRAFT) {
        return false;
    }
    
    Experiment updated = experiment;
    updated.id = experimentId;
    updated.updatedAt = std::chrono::system_clock::now();
    it->second = updated;
    
    return true;
}

bool ABTestingFramework::deleteExperiment(const std::string& experimentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it == experiments_.end()) {
        return false;
    }
    
    // Only allow deletion of draft or cancelled experiments
    if (it->second.status != ExperimentStatus::DRAFT && 
        it->second.status != ExperimentStatus::CANCELLED) {
        return false;
    }
    
    experiments_.erase(it);
    userAssignments_.erase(experimentId);
    metricData_.erase(experimentId);
    
    return true;
}

Experiment ABTestingFramework::getExperiment(const std::string& experimentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it != experiments_.end()) {
        return it->second;
    }
    
    return Experiment{};
}

std::vector<Experiment> ABTestingFramework::listExperiments() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Experiment> result;
    for (const auto& [id, exp] : experiments_) {
        result.push_back(exp);
    }
    
    // Sort by creation time (newest first)
    std::sort(result.begin(), result.end(), [](const Experiment& a, const Experiment& b) {
        return a.createdAt > b.createdAt;
    });
    
    return result;
}

std::vector<Experiment> ABTestingFramework::listExperimentsByStatus(ExperimentStatus status) const {
    auto all = listExperiments();
    std::vector<Experiment> result;
    
    for (const auto& exp : all) {
        if (exp.status == status) {
            result.push_back(exp);
        }
    }
    
    return result;
}

// ============================================================================
// Experiment Lifecycle
// ============================================================================

bool ABTestingFramework::startExperiment(const std::string& experimentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it == experiments_.end()) {
        return false;
    }
    
    if (it->second.status != ExperimentStatus::DRAFT &&
        it->second.status != ExperimentStatus::SCHEDULED &&
        it->second.status != ExperimentStatus::PAUSED) {
        return false;
    }
    
    it->second.status = ExperimentStatus::RUNNING;
    it->second.updatedAt = std::chrono::system_clock::now();
    
    return true;
}

bool ABTestingFramework::pauseExperiment(const std::string& experimentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it == experiments_.end()) {
        return false;
    }
    
    if (it->second.status != ExperimentStatus::RUNNING) {
        return false;
    }
    
    it->second.status = ExperimentStatus::PAUSED;
    it->second.updatedAt = std::chrono::system_clock::now();
    
    return true;
}

bool ABTestingFramework::resumeExperiment(const std::string& experimentId) {
    return startExperiment(experimentId);
}

bool ABTestingFramework::stopExperiment(const std::string& experimentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it == experiments_.end()) {
        return false;
    }
    
    if (it->second.status != ExperimentStatus::RUNNING &&
        it->second.status != ExperimentStatus::PAUSED) {
        return false;
    }
    
    it->second.status = ExperimentStatus::COMPLETED;
    it->second.updatedAt = std::chrono::system_clock::now();
    
    return true;
}

bool ABTestingFramework::cancelExperiment(const std::string& experimentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(experimentId);
    if (it == experiments_.end()) {
        return false;
    }
    
    it->second.status = ExperimentStatus::CANCELLED;
    it->second.updatedAt = std::chrono::system_clock::now();
    
    return true;
}

// ============================================================================
// User Assignment
// ============================================================================

std::optional<UserAssignment> ABTestingFramework::assignUser(
    const std::string& experimentId,
    const std::string& userId,
    const std::map<std::string, std::string>& userAttributes) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto expIt = experiments_.find(experimentId);
    if (expIt == experiments_.end()) {
        return std::nullopt;
    }
    
    const auto& exp = expIt->second;
    
    // Check if experiment is running
    if (exp.status != ExperimentStatus::RUNNING) {
        return std::nullopt;
    }
    
    // Check if user already assigned
    auto& assignments = userAssignments_[experimentId];
    auto assignIt = assignments.find(userId);
    if (assignIt != assignments.end()) {
        return assignIt->second;
    }
    
    // Check targeting rules
    if (!matchesTargeting(userAttributes, exp.audience.includeRules)) {
        return std::nullopt;
    }
    if (matchesTargeting(userAttributes, exp.audience.excludeRules)) {
        return std::nullopt;
    }
    
    // Check traffic percentage
    std::uniform_int_distribution<int> dist(0, 99);
    if (dist(rng_) >= static_cast<int>(exp.audience.trafficPercentage)) {
        return std::nullopt;
    }
    
    // Assign to variant
    std::string variantId = hashUserToVariant(experimentId, userId, exp.variants);
    
    UserAssignment assignment;
    assignment.experimentId = experimentId;
    assignment.variantId = variantId;
    assignment.userId = userId;
    assignment.assignedAt = std::chrono::system_clock::now();
    assignment.isEnrolled = true;
    
    assignments[userId] = assignment;
    
    return assignment;
}

std::optional<std::string> ABTestingFramework::getUserVariant(
    const std::string& experimentId,
    const std::string& userId) const {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto expIt = userAssignments_.find(experimentId);
    if (expIt == userAssignments_.end()) {
        return std::nullopt;
    }
    
    auto userIt = expIt->second.find(userId);
    if (userIt == expIt->second.end()) {
        return std::nullopt;
    }
    
    return userIt->second.variantId;
}

bool ABTestingFramework::isUserEnrolled(const std::string& experimentId, 
                                       const std::string& userId) const {
    auto variant = getUserVariant(experimentId, userId);
    return variant.has_value();
}

bool ABTestingFramework::unenrollUser(const std::string& experimentId, 
                                     const std::string& userId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto expIt = userAssignments_.find(experimentId);
    if (expIt == userAssignments_.end()) {
        return false;
    }
    
    auto userIt = expIt->second.find(userId);
    if (userIt == expIt->second.end()) {
        return false;
    }
    
    userIt->second.isEnrolled = false;
    return true;
}

// ============================================================================
// Feature Flags
// ============================================================================

bool ABTestingFramework::isFeatureEnabled(const std::string& featureKey,
                                         const std::string& userId,
                                         const std::map<std::string, std::string>& userAttributes) {
    auto exp = getExperiment(featureKey);
    if (exp.id.empty()) {
        return false;
    }
    
    auto assignment = assignUser(featureKey, userId, userAttributes);
    return assignment.has_value() && assignment->.variantId != exp.variants[0].id;
}

std::map<std::string, std::string> ABTestingFramework::getFeatureConfig(
    const std::string& featureKey,
    const std::string& userId) {
    
    auto variantId = getUserVariant(featureKey, userId);
    if (!variantId) {
        return {};
    }
    
    auto exp = getExperiment(featureKey);
    for (const auto& variant : exp.variants) {
        if (variant.id == *variantId) {
            return variant.config;
        }
    }
    
    return {};
}

// ============================================================================
// Event Tracking
// ============================================================================

void ABTestingFramework::trackEvent(const std::string& experimentId,
                                   const std::string& userId,
                                   const std::string& eventName,
                                   const std::map<std::string, double>& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto expIt = experiments_.find(experimentId);
    if (expIt == experiments_.end()) {
        return;
    }
    
    // Store metric data
    for (const auto& [metricName, value] : metrics) {
        metricData_[experimentId][metricName].push_back(value);
    }
}

void ABTestingFramework::trackConversion(const std::string& experimentId, 
                                        const std::string& userId) {
    std::map<std::string, double> metrics;
    metrics["conversion"] = 1.0;
    trackEvent(experimentId, userId, "conversion", metrics);
}

void ABTestingFramework::trackRevenue(const std::string& experimentId,
                                     const std::string& userId,
                                     double amount) {
    std::map<std::string, double> metrics;
    metrics["revenue"] = amount;
    trackEvent(experimentId, userId, "revenue", metrics);
}

// ============================================================================
// Results and Analysis
// ============================================================================

ExperimentResults ABTestingFramework::getResults(const std::string& experimentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ExperimentResults results;
    results.experimentId = experimentId;
    results.generatedAt = std::chrono::system_clock::now();
    
    auto expIt = experiments_.find(experimentId);
    if (expIt == experiments_.end()) {
        return results;
    }
    
    const auto& exp = expIt->second;
    
    // Calculate variant results
    auto assignIt = userAssignments_.find(experimentId);
    if (assignIt != userAssignments_.end()) {
        std::map<std::string, uint64_t> variantUsers;
        std::map<std::string, uint64_t> variantConversions;
        
        for (const auto& [userId, assignment] : assignIt->second) {
            variantUsers[assignment.variantId]++;
        }
        
        for (const auto& variant : exp.variants) {
            ExperimentResults::VariantResult vr;
            vr.variantId = variant.id;
            vr.variantName = variant.name;
            vr.usersEnrolled = variantUsers[variant.id];
            vr.usersConverted = variantConversions[variant.id];
            vr.conversionRate = vr.usersEnrolled > 0 
                ? static_cast<double>(vr.usersConverted) / vr.usersEnrolled * 100.0 
                : 0.0;
            results.variantResults.push_back(vr);
        }
    }
    
    // Calculate duration
    if (exp.status == ExperimentStatus::COMPLETED && exp.schedule.endTime) {
        results.duration = std::chrono::duration_cast<std::chrono::hours>(
            *exp.schedule.endTime - exp.schedule.startTime);
    } else {
        results.duration = std::chrono::duration_cast<std::chrono::hours>(
            std::chrono::system_clock::now() - exp.schedule.startTime);
    }
    
    // Determine winner (simplified)
    if (!results.variantResults.empty()) {
        auto winner = std::max_element(results.variantResults.begin(), 
                                       results.variantResults.end(),
            [](const auto& a, const auto& b) { return a.conversionRate < b.conversionRate; });
        
        if (winner != results.variantResults.end() && !winner->isControl) {
            results.winningVariantId = winner->variantId;
            results.hasWinner = true;
            results.winnerConfidence = 0.95;  // Placeholder
        }
    }
    
    // Generate recommendation
    if (results.hasWinner) {
        results.recommendation = "rollout";
    } else if (exp.status == ExperimentStatus::COMPLETED) {
        results.recommendation = "inconclusive";
    } else {
        results.recommendation = "continue";
    }
    
    return results;
}

ExperimentResults ABTestingFramework::getResultsRealtime(const std::string& experimentId) const {
    return getResults(experimentId);
}

bool ABTestingFramework::exportResults(const std::string& experimentId, 
                                      const std::string& outputPath) const {
    auto results = getResults(experimentId);
    
    std::ofstream file(outputPath);
    if (!file) return false;
    
    file << "{\n";
    file << "  \"experimentId\": \"" << results.experimentId << "\",\n";
    file << "  \"hasWinner\": " << (results.hasWinner ? "true" : "false") << ",\n";
    file << "  \"winningVariantId\": \"" << results.winningVariantId << "\",\n";
    file << "  \"recommendation\": \"" << results.recommendation << "\"\n";
    file << "}\n";
    
    return true;
}

// ============================================================================
// Statistical Calculations
// ============================================================================

SampleSizeCalculation ABTestingFramework::calculateRequiredSampleSize(
    double baselineRate,
    double minimumDetectableEffect,
    double statisticalPower,
    double significanceLevel) const {
    
    SampleSizeCalculation calc;
    calc.baselineConversionRate = baselineRate;
    calc.minimumDetectableEffect = minimumDetectableEffect;
    calc.statisticalPower = statisticalPower;
    calc.significanceLevel = significanceLevel;
    
    // Simplified sample size calculation using normal approximation
    double zAlpha = 1.96;  // For 95% confidence
    double zBeta = 0.84;   // For 80% power
    
    double p1 = baselineRate;
    double p2 = baselineRate * (1.0 + minimumDetectableEffect);
    double p = (p1 + p2) / 2.0;
    
    double n = (2.0 * p * (1.0 - p) * std::pow(zAlpha + zBeta, 2)) / std::pow(p2 - p1, 2);
    
    calc.requiredPerVariant = static_cast<uint64_t>(std::ceil(n));
    calc.totalRequired = calc.requiredPerVariant * 2;  // Control + treatment
    
    // Estimate duration (assuming 100 users/day)
    calc.estimatedDuration = std::chrono::hours(
        static_cast<int>((calc.totalRequired / 100.0) * 24));
    
    return calc;
}

double ABTestingFramework::calculatePValue(const std::vector<double>& controlValues,
                                          const std::vector<double>& treatmentValues) const {
    // Simplified - would use proper statistical test
    if (controlValues.empty() || treatmentValues.empty()) {
        return 1.0;
    }
    
    double controlMean = std::accumulate(controlValues.begin(), controlValues.end(), 0.0) / controlValues.size();
    double treatmentMean = std::accumulate(treatmentValues.begin(), treatmentValues.end(), 0.0) / treatmentValues.size();
    
    // Calculate p-value using Welch's t-test
    double controlVar = 0.0, treatmentVar = 0.0;
    for (double v : controlValues) {
        controlVar += std::pow(v - controlMean, 2);
    }
    for (double v : treatmentValues) {
        treatmentVar += std::pow(v - treatmentMean, 2);
    }
    controlVar /= controlValues.size();
    treatmentVar /= treatmentValues.size();
    
    // Welch-Satterthwaite equation for degrees of freedom
    double se = std::sqrt(controlVar / controlValues.size() + treatmentVar / treatmentValues.size());
    if (se == 0.0) return 1.0; // No variance
    
    double t = (treatmentMean - controlMean) / se;
    
    // Approximate p-value (two-tailed)
    // Using normal approximation for large samples
    double pValue = 2.0 * (1.0 - std::erf(std::abs(t) / std::sqrt(2.0)));
    return std::min(pValue, 1.0);
}
}

double ABTestingFramework::calculateConfidenceInterval(const std::vector<double>& values,
                                                      double confidenceLevel) const {
    if (values.empty()) return 0.0;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    
    double variance = 0.0;
    for (double v : values) {
        variance += std::pow(v - mean, 2);
    }
    variance /= values.size();
    
    double stdDev = std::sqrt(variance);
    double zScore = 1.96;  // For 95% confidence
    
    return zScore * stdDev / std::sqrt(values.size());
}

bool ABTestingFramework::isStatisticallySignificant(const MetricResult& result) const {
    return result.pValue < 0.05;
}

// ============================================================================
// Sample Size Validation
// ============================================================================

bool ABTestingFramework::hasEnoughSamples(const std::string& experimentId) const {
    auto calc = getSampleSizeStatus(experimentId);
    
    auto exp = getExperiment(experimentId);
    auto assignments = userAssignments_.find(experimentId);
    if (assignments == userAssignments_.end()) {
        return false;
    }
    
    return assignments->second.size() >= calc.totalRequired;
}

SampleSizeCalculation ABTestingFramework::getSampleSizeStatus(const std::string& experimentId) const {
    auto exp = getExperiment(experimentId);
    
    double baselineRate = 0.1;  // Default 10% conversion
    double mde = 0.05;  // 5% minimum detectable effect
    
    for (const auto& metric : exp.successMetrics) {
        if (metric.isPrimary) {
            mde = metric.minimumDetectableEffect;
            break;
        }
    }
    
    return calculateRequiredSampleSize(baselineRate, mde);
}

// ============================================================================
// Guardrail Monitoring
// ============================================================================

std::vector<std::string> ABTestingFramework::checkGuardrails(const std::string& experimentId) const {
    std::vector<std::string> violations;
    
    auto exp = getExperiment(experimentId);
    
    // Would check actual guardrail metrics
    for (const auto& guardrail : exp.guardrailMetrics) {
        // Placeholder check
        if (guardrail.maxValue > 0) {
            // Check if metric exceeds max
        }
    }
    
    return violations;
}

bool ABTestingFramework::areGuardrailsViolated(const std::string& experimentId) const {
    return !checkGuardrails(experimentId).empty();
}

// ============================================================================
// Auto-Decision
// ============================================================================

void ABTestingFramework::enableAutoDecision(const std::string& experimentId,
                                         std::chrono::hours minDuration,
                                         double confidenceThreshold) {
    // Would store auto-decision configuration
}

bool ABTestingFramework::shouldAutoStop(const std::string& experimentId) const {
    auto exp = getExperiment(experimentId);
    
    if (exp.status != ExperimentStatus::RUNNING) {
        return false;
    }
    
    // Check if enough time has passed
    auto elapsed = std::chrono::system_clock::now() - exp.schedule.startTime;
    if (exp.schedule.minDuration && elapsed < *exp.schedule.minDuration) {
        return false;
    }
    
    // Check if we have a winner
    auto results = getResults(experimentId);
    return results.hasWinner && results.winnerConfidence >= exp.confidenceLevel;
}

// ============================================================================
// Feature Flags (Simplified)
// ============================================================================

std::string ABTestingFramework::createFeatureFlag(const std::string& name,
                                               const std::map<std::string, std::string>& config,
                                               double rolloutPercentage) {
    Experiment flag;
    flag.name = name;
    flag.description = "Feature flag: " + name;
    flag.type = ExperimentType::FEATURE_FLAG;
    flag.status = ExperimentStatus::RUNNING;
    
    // Create control (off) and treatment (on) variants
    Variant control;
    control.id = "off";
    control.name = "Off";
    control.isControl = true;
    control.allocation.percentage = 100.0 - rolloutPercentage;
    
    Variant treatment;
    treatment.id = "on";
    treatment.name = "On";
    treatment.isControl = false;
    treatment.config = config;
    treatment.allocation.percentage = rolloutPercentage;
    
    flag.variants.push_back(control);
    flag.variants.push_back(treatment);
    
    flag.schedule.startTime = std::chrono::system_clock::now();
    
    return createExperiment(flag);
}

bool ABTestingFramework::updateFeatureFlagRollout(const std::string& flagId, double percentage) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = experiments_.find(flagId);
    if (it == experiments_.end()) {
        return false;
    }
    
    if (it->second.variants.size() >= 2) {
        it->second.variants[0].allocation.percentage = 100.0 - percentage;
        it->second.variants[1].allocation.percentage = percentage;
    }
    
    return true;
}

bool ABTestingFramework::deleteFeatureFlag(const std::string& flagId) {
    return deleteExperiment(flagId);
}

std::vector<Experiment> ABTestingFramework::listFeatureFlags() const {
    auto all = listExperiments();
    std::vector<Experiment> result;
    
    for (const auto& exp : all) {
        if (exp.type == ExperimentType::FEATURE_FLAG) {
            result.push_back(exp);
        }
    }
    
    return result;
}

// ============================================================================
// Progress Tracking
// ============================================================================

ABTestingFramework::ExperimentProgress ABTestingFramework::getProgress(const std::string& experimentId) const {
    ExperimentProgress progress;
    progress.experimentId = experimentId;
    
    auto exp = getExperiment(experimentId);
    auto calc = getSampleSizeStatus(experimentId);
    
    auto assignIt = userAssignments_.find(experimentId);
    if (assignIt != userAssignments_.end()) {
        progress.usersEnrolled = assignIt->second.size();
    }
    
    progress.usersNeeded = calc.totalRequired;
    progress.progressPercentage = progress.usersNeeded > 0 
        ? static_cast<double>(progress.usersEnrolled) / progress.usersNeeded * 100.0 
        : 0.0;
    
    progress.elapsed = std::chrono::duration_cast<std::chrono::hours>(
        std::chrono::system_clock::now() - exp.schedule.startTime);
    
    // Estimate remaining time
    if (progress.progressPercentage > 0) {
        double hoursPerPercent = progress.elapsed.count() / progress.progressPercentage;
        double remainingPercent = 100.0 - progress.progressPercentage;
        progress.estimatedRemaining = std::chrono::hours(
            static_cast<int>(hoursPerPercent * remainingPercent));
    }
    
    progress.isComplete = progress.progressPercentage >= 100.0;
    
    return progress;
}

// ============================================================================
// Statistics
// ============================================================================

ABTestingFramework::ABTestStats ABTestingFramework::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    ABTestStats stats{};
    stats.totalExperiments = static_cast<uint32_t>(experiments_.size());
    
    for (const auto& [id, exp] : experiments_) {
        if (exp.status == ExperimentStatus::RUNNING) {
            stats.runningExperiments++;
        } else if (exp.status == ExperimentStatus::COMPLETED) {
            stats.completedExperiments++;
        }
    }
    
    for (const auto& [expId, assignments] : userAssignments_) {
        stats.totalUsersEnrolled += static_cast<uint32_t>(assignments.size());
    }
    
    return stats;
}

// ============================================================================
// Internal Methods
// ============================================================================

std::string ABTestingFramework::generateExperimentId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << "exp-";
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << dis(gen);
    }
    return ss.str();
}

std::string ABTestingFramework::hashUserToVariant(const std::string& experimentId,
                                                 const std::string& userId,
                                                 const std::vector<Variant>& variants) const {
    // Simple hash-based assignment
    std::hash<std::string> hasher;
    size_t hash = hasher(experimentId + ":" + userId);
    
    // Normalize to 0-99
    int bucket = static_cast<int>(hash % 100);
    
    // Assign based on traffic allocation
    int cumulative = 0;
    for (const auto& variant : variants) {
        cumulative += static_cast<int>(variant.allocation.percentage);
        if (bucket < cumulative) {
            return variant.id;
        }
    }
    
    // Fallback to first variant
    return variants.empty() ? "" : variants[0].id;
}

bool ABTestingFramework::matchesTargeting(const std::map<std::string, std::string>& userAttributes,
                                         const std::vector<TargetingRule>& rules) const {
    if (rules.empty()) return true;
    
    for (const auto& rule : rules) {
        if (!evaluateRule(userAttributes, rule)) {
            return false;
        }
    }
    return true;
}

bool ABTestingFramework::evaluateRule(const std::map<std::string, std::string>& userAttributes,
                                     const TargetingRule& rule) const {
    auto it = userAttributes.find(rule.attribute);
    if (it == userAttributes.end()) {
        return false;
    }
    
    bool matches = false;
    
    if (rule.operator_ == "equals") {
        matches = (it->second == rule.value);
    } else if (rule.operator_ == "contains") {
        matches = (it->second.find(rule.value) != std::string::npos);
    } else if (rule.operator_ == "gt") {
        try {
            matches = (std::stod(it->second) > std::stod(rule.value));
        } catch (...) {
            matches = false;
        }
    } else if (rule.operator_ == "lt") {
        try {
            matches = (std::stod(it->second) < std::stod(rule.value));
        } catch (...) {
            matches = false;
        }
    }
    
    return rule.negate ? !matches : matches;
}

void ABTestingFramework::checkExperimentSchedule() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    for (auto& [id, exp] : experiments_) {
        // Auto-start scheduled experiments
        if (exp.status == ExperimentStatus::SCHEDULED && exp.schedule.startTime <= now) {
            exp.status = ExperimentStatus::RUNNING;
        }
    }
}

void ABTestingFramework::autoStopExperiments() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::system_clock::now();
    
    for (auto& [id, exp] : experiments_) {
        // Auto-stop based on max duration
        if (exp.status == ExperimentStatus::RUNNING && exp.schedule.maxDuration) {
            auto elapsed = now - exp.schedule.startTime;
            if (elapsed >= *exp.schedule.maxDuration) {
                exp.status = ExperimentStatus::COMPLETED;
            }
        }
    }
}

// ============================================================================
// ExperimentBuilder Implementation
// ============================================================================

ExperimentBuilder::ExperimentBuilder(ABTestingFramework* framework)
    : framework_(framework) {
}

ExperimentBuilder& ExperimentBuilder::withName(const std::string& name) {
    experiment_.name = name;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withDescription(const std::string& description) {
    experiment_.description = description;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withHypothesis(const std::string& hypothesis) {
    experiment_.hypothesis = hypothesis;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::ofType(ExperimentType type) {
    experiment_.type = type;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withVariant(const Variant& variant) {
    experiment_.variants.push_back(variant);
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withControl(const std::string& name) {
    Variant control;
    control.id = "control";
    control.name = name;
    control.isControl = true;
    control.allocation.percentage = 50.0;
    experiment_.variants.push_back(control);
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withTreatment(const std::string& name) {
    Variant treatment;
    treatment.id = "treatment";
    treatment.name = name;
    treatment.isControl = false;
    treatment.allocation.percentage = 50.0;
    experiment_.variants.push_back(treatment);
    return *this;
}

ExperimentBuilder& ExperimentBuilder::targeting(const std::vector<TargetingRule>& rules) {
    experiment_.audience.includeRules = rules;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::excluding(const std::vector<TargetingRule>& rules) {
    experiment_.audience.excludeRules = rules;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withTrafficPercentage(uint32_t percentage) {
    experiment_.audience.trafficPercentage = percentage;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::measuring(const SuccessMetric& metric) {
    experiment_.successMetrics.push_back(metric);
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withPrimaryMetric(const std::string& eventName) {
    SuccessMetric metric;
    metric.name = eventName;
    metric.eventName = eventName;
    metric.isPrimary = true;
    experiment_.successMetrics.push_back(metric);
    return *this;
}

ExperimentBuilder& ExperimentBuilder::guarding(const GuardrailMetric& metric) {
    experiment_.guardrailMetrics.push_back(metric);
    return *this;
}

ExperimentBuilder& ExperimentBuilder::startingAt(std::chrono::system_clock::time_point time) {
    experiment_.schedule.startTime = time;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::endingAt(std::chrono::system_clock::time_point time) {
    experiment_.schedule.endTime = time;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::forDuration(std::chrono::hours duration) {
    experiment_.schedule.startTime = std::chrono::system_clock::now();
    experiment_.schedule.endTime = experiment_.schedule.startTime + duration;
    return *this;
}

ExperimentBuilder& ExperimentBuilder::withConfidence(double level) {
    experiment_.confidenceLevel = level;
    return *this;
}

std::string ExperimentBuilder::create() {
    return framework_->createExperiment(experiment_);
}

// ============================================================================
// FeatureFlagBuilder Implementation
// ============================================================================

FeatureFlagBuilder::FeatureFlagBuilder(ABTestingFramework* framework)
    : framework_(framework) {
    flag_.type = ExperimentType::FEATURE_FLAG;
    flag_.status = ExperimentStatus::RUNNING;
}

FeatureFlagBuilder& FeatureFlagBuilder::withName(const std::string& name) {
    flag_.name = name;
    flag_.description = "Feature flag: " + name;
    return *this;
}

FeatureFlagBuilder& FeatureFlagBuilder::withConfig(const std::map<std::string, std::string>& config) {
    if (flag_.variants.size() >= 2) {
        flag_.variants[1].config = config;
    }
    return *this;
}

FeatureFlagBuilder& FeatureFlagBuilder::rolledOutTo(double percentage) {
    if (flag_.variants.size() >= 2) {
        flag_.variants[0].allocation.percentage = 100.0 - percentage;
        flag_.variants[1].allocation.percentage = percentage;
    }
    return *this;
}

FeatureFlagBuilder& FeatureFlagBuilder::targeting(const std::vector<TargetingRule>& rules) {
    flag_.audience.includeRules = rules;
    return *this;
}

std::string FeatureFlagBuilder::create() {
    // Ensure variants exist
    if (flag_.variants.empty()) {
        Variant control;
        control.id = "off";
        control.name = "Off";
        control.isControl = true;
        control.allocation.percentage = 100.0;
        flag_.variants.push_back(control);
        
        Variant treatment;
        treatment.id = "on";
        treatment.name = "On";
        treatment.isControl = false;
        treatment.allocation.percentage = 0.0;
        flag_.variants.push_back(treatment);
    }
    
    flag_.schedule.startTime = std::chrono::system_clock::now();
    
    return framework_->createExperiment(flag_);
}

} // namespace Monitoring
} // namespace RawrXD
