#include "ab_testing.hpp"
#include "../core/logger.hpp"
#include <algorithm>
#include <numeric>

namespace rawrxd::serving {

// ============================================================================
// A/B Testing Manager
// ============================================================================

ABTestingManager::ABTestingManager() {
    RAWRXD_LOG_INFO("ABTestingManager", "Initialized");
}

bool ABTestingManager::createExperiment(const ExperimentConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (experiments_.find(config.experiment_id) != experiments_.end()) {
        RAWRXD_LOG_ERROR("ABTestingManager", "Experiment {} already exists", config.experiment_id);
        return false;
    }

    // Validate traffic split
    float total = std::accumulate(config.traffic_split.begin(), config.traffic_split.end(), 0.0f);
    if (std::abs(total - 1.0f) > 0.001f) {
        RAWRXD_LOG_ERROR("ABTestingManager", "Traffic split must sum to 1.0, got {}", total);
        return false;
    }

    experiments_[config.experiment_id] = config;
    experiment_states_[config.experiment_id] = ExperimentState::PENDING;

    RAWRXD_LOG_INFO("ABTestingManager", "Created experiment: {}", config.experiment_id);
    return true;
}

bool ABTestingManager::startExperiment(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = experiments_.find(experiment_id);
    if (it == experiments_.end()) {
        return false;
    }

    experiment_states_[experiment_id] = ExperimentState::RUNNING;
    results_[experiment_id] = ExperimentResults();
    results_[experiment_id].experiment_id = experiment_id;
    results_[experiment_id].start_time = std::chrono::system_clock::now();

    RAWRXD_LOG_INFO("ABTestingManager", "Started experiment: {}", experiment_id);
    return true;
}

bool ABTestingManager::pauseExperiment(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = experiment_states_.find(experiment_id);
    if (it == experiment_states_.end()) return false;

    it->second = ExperimentState::PAUSED;
    RAWRXD_LOG_INFO("ABTestingManager", "Paused experiment: {}", experiment_id);
    return true;
}

bool ABTestingManager::resumeExperiment(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = experiment_states_.find(experiment_id);
    if (it == experiment_states_.end()) return false;

    it->second = ExperimentState::RUNNING;
    RAWRXD_LOG_INFO("ABTestingManager", "Resumed experiment: {}", experiment_id);
    return true;
}

bool ABTestingManager::stopExperiment(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = experiment_states_.find(experiment_id);
    if (it == experiment_states_.end()) return false;

    it->second = ExperimentState::COMPLETED;

    auto result_it = results_.find(experiment_id);
    if (result_it != results_.end()) {
        result_it->second.end_time = std::chrono::system_clock::now();
        analyzeResults(experiment_id);
    }

    RAWRXD_LOG_INFO("ABTestingManager", "Stopped experiment: {}", experiment_id);
    return true;
}

bool ABTestingManager::deleteExperiment(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    experiments_.erase(experiment_id);
    experiment_states_.erase(experiment_id);
    results_.erase(experiment_id);

    RAWRXD_LOG_INFO("ABTestingManager", "Deleted experiment: {}", experiment_id);
    return true;
}

std::string ABTestingManager::getVariant(const std::string& experiment_id,
                                           const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto state_it = experiment_states_.find(experiment_id);
    if (state_it == experiment_states_.end() || state_it->second != ExperimentState::RUNNING) {
        return "";
    }

    auto exp_it = experiments_.find(experiment_id);
    if (exp_it == experiments_.end()) {
        return "";
    }

    int variant_idx = assignVariant(exp_it->second, user_id);
    if (variant_idx >= 0 && variant_idx < static_cast<int>(exp_it->second.model_variants.size())) {
        return exp_it->second.model_variants[variant_idx];
    }

    return "";
}

void ABTestingManager::recordOutcome(const std::string& experiment_id,
                                     const std::string& variant,
                                     float metric_value,
                                     bool success) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto result_it = results_.find(experiment_id);
    if (result_it == results_.end()) return;

    result_it->second.total_requests++;
    result_it->second.variant_metrics[variant] = metric_value;
}

std::optional<ExperimentResults> ABTestingManager::getResults(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = results_.find(experiment_id);
    if (it != results_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<ExperimentConfig> ABTestingManager::listExperiments() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ExperimentConfig> list;
    for (const auto& [id, config] : experiments_) {
        list.push_back(config);
    }
    return list;
}

std::vector<ExperimentConfig> ABTestingManager::listActiveExperiments() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<ExperimentConfig> list;
    for (const auto& [id, state] : experiment_states_) {
        if (state == ExperimentState::RUNNING) {
            auto it = experiments_.find(id);
            if (it != experiments_.end()) {
                list.push_back(it->second);
            }
        }
    }
    return list;
}

bool ABTestingManager::isStatisticallySignificant(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto result_it = results_.find(experiment_id);
    if (result_it == results_.end()) return false;

    return result_it->second.confidence_level >= 0.95f;
}

std::string ABTestingManager::recommendWinner(const std::string& experiment_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto result_it = results_.find(experiment_id);
    if (result_it == results_.end()) return "";

    // Find variant with best metric
    std::string winner;
    float best_metric = std::numeric_limits<float>::max();

    for (const auto& [variant, metric] : result_it->second.variant_metrics) {
        if (metric < best_metric) {
            best_metric = metric;
            winner = variant;
        }
    }

    return winner;
}

int ABTestingManager::assignVariant(const ExperimentConfig& config, const std::string& user_id) {
    std::mt19937* rng = &default_rng_;

    if (!user_id.empty()) {
        auto it = user_rngs_.find(user_id);
        if (it == user_rngs_.end()) {
            // Create deterministic RNG for user
            std::hash<std::string> hasher;
            user_rngs_[user_id] = std::mt19937(hasher(user_id));
        }
        rng = &user_rngs_[user_id];
    }

    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float roll = dist(*rng);

    float cumulative = 0.0f;
    for (size_t i = 0; i < config.traffic_split.size(); ++i) {
        cumulative += config.traffic_split[i];
        if (roll <= cumulative) {
            return static_cast<int>(i);
        }
    }

    return static_cast<int>(config.traffic_split.size()) - 1;
}

void ABTestingManager::analyzeResults(const std::string& experiment_id) {
    // Statistical analysis would go here
    // Calculate confidence intervals, p-values, etc.
}

// ============================================================================
// Feature Flag Manager
// ============================================================================

bool FeatureFlagManager::createFlag(const FeatureFlag& flag) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (flags_.find(flag.name) != flags_.end()) {
        return false;
    }

    FeatureFlag new_flag = flag;
    new_flag.created_at = std::chrono::system_clock::now();
    new_flag.updated_at = new_flag.created_at;

    flags_[flag.name] = new_flag;
    return true;
}

bool FeatureFlagManager::updateFlag(const std::string& name, const FeatureFlag& flag) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flags_.find(name);
    if (it == flags_.end()) return false;

    FeatureFlag updated = flag;
    updated.created_at = it->second.created_at;
    updated.updated_at = std::chrono::system_clock::now();

    flags_[name] = updated;
    return true;
}

bool FeatureFlagManager::deleteFlag(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return flags_.erase(name) > 0;
}

std::optional<FeatureFlagManager::FeatureFlag> FeatureFlagManager::getFlag(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flags_.find(name);
    if (it != flags_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<FeatureFlagManager::FeatureFlag> FeatureFlagManager::listFlags() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<FeatureFlag> list;
    for (const auto& [name, flag] : flags_) {
        list.push_back(flag);
    }
    return list;
}

bool FeatureFlagManager::isEnabled(const std::string& flag_name, const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flags_.find(flag_name);
    if (it == flags_.end()) return false;

    const auto& flag = it->second;

    if (!flag.enabled) return false;

    // Check allowed/blocked lists
    if (!flag.allowed_users.empty()) {
        return std::find(flag.allowed_users.begin(), flag.allowed_users.end(), user_id) != flag.allowed_users.end();
    }

    if (std::find(flag.blocked_users.begin(), flag.blocked_users.end(), user_id) != flag.blocked_users.end()) {
        return false;
    }

    // Percentage rollout
    if (flag.rollout_percent >= 100.0f) return true;
    if (flag.rollout_percent <= 0.0f) return false;

    std::hash<std::string> hasher;
    std::mt19937 user_rng(hasher(user_id + flag_name));
    std::uniform_real_distribution<float> dist(0.0f, 100.0f);

    return dist(user_rng) < flag.rollout_percent;
}

void FeatureFlagManager::enableFlag(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flags_.find(name);
    if (it != flags_.end()) {
        it->second.enabled = true;
        it->second.updated_at = std::chrono::system_clock::now();
    }
}

void FeatureFlagManager::disableFlag(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flags_.find(name);
    if (it != flags_.end()) {
        it->second.enabled = false;
        it->second.updated_at = std::chrono::system_clock::now();
    }
}

void FeatureFlagManager::setRolloutPercent(const std::string& name, float percent) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = flags_.find(name);
    if (it != flags_.end()) {
        it->second.rollout_percent = std::clamp(percent, 0.0f, 100.0f);
        it->second.updated_at = std::chrono::system_clock::now();
    }
}

} // namespace rawrxd::serving
