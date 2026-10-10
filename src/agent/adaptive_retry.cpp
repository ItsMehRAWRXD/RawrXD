// ============================================================================
// File: src/agent/adaptive_retry.cpp
//
// Implementation of Adaptive Retry System
// ============================================================================

#include "adaptive_retry.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <thread>
#include <cmath>

// ============================================================================
// RetryPolicy JSON serialization
// ============================================================================
std::string RetryPolicy::toJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"operationType\":\"" << operationType << "\",";
    oss << "\"description\":\"" << description << "\",";
    oss << "\"maxAttempts\":" << maxAttempts << ",";
    oss << "\"baseDelayMs\":" << baseDelayMs << ",";
    oss << "\"maxDelayMs\":" << maxDelayMs << ",";
    oss << "\"backoffMultiplier\":" << backoffMultiplier << ",";
    oss << "\"jitterFactor\":" << jitterFactor << ",";
    oss << "\"enableCircuitBreaker\":" << (enableCircuitBreaker ? "true" : "false") << ",";
    oss << "\"failureThreshold\":" << failureThreshold << ",";
    oss << "\"successThreshold\":" << successThreshold << ",";
    oss << "\"circuitTimeoutMs\":" << circuitTimeoutMs << ",";
    oss << "\"retryableErrorPatterns\":[";
    for (size_t i = 0; i < retryableErrorPatterns.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << retryableErrorPatterns[i] << "\"";
    }
    oss << "],";
    oss << "\"nonRetryableErrorPatterns\":[";
    for (size_t i = 0; i < nonRetryableErrorPatterns.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << nonRetryableErrorPatterns[i] << "\"";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

// Minimal, dependency-free JSON field extraction. Handles the flat object
// produced by RetryPolicy::toJSON(). Full JSON parsing is intentionally out of
// scope â€” this project forbids third-party libraries.
namespace {

std::string jsonField(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";
    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        ++pos;
        std::string out;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) ++pos;
            out += json[pos++];
        }
        return out;
    }
    size_t end = pos;
    while (end < json.size() && json[end] != ',' && json[end] != '}' &&
           json[end] != '\n' && json[end] != '\r') {
        ++end;
    }
    return json.substr(pos, end - pos);
}

std::vector<std::string> jsonArrayField(const std::string& json, const std::string& key) {
    std::vector<std::string> out;
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return out;
    pos = json.find('[', pos + needle.size());
    if (pos == std::string::npos) return out;
    ++pos;
    std::string cur;
    bool inString = false;
    while (pos < json.size() && json[pos] != ']') {
        char c = json[pos];
        if (c == '"') {
            inString = !inString;
            if (!inString && !cur.empty()) { out.push_back(cur); cur.clear(); }
        } else if (inString) {
            cur += c;
        }
        ++pos;
    }
    return out;
}

bool jsonBool(const std::string& json, const std::string& key, bool fallback) {
    std::string v = jsonField(json, key);
    if (v.empty()) return fallback;
    return v == "true" || v == "1";
}

int jsonInt(const std::string& json, const std::string& key, int fallback) {
    std::string v = jsonField(json, key);
    if (v.empty()) return fallback;
    try { return std::stoi(v); } catch (...) { return fallback; }
}

double jsonDouble(const std::string& json, const std::string& key, double fallback) {
    std::string v = jsonField(json, key);
    if (v.empty()) return fallback;
    try { return std::stod(v); } catch (...) { return fallback; }
}

} // namespace

RetryPolicy RetryPolicy::fromJSON(const std::string& json) {
    RetryPolicy policy;
    policy.operationType      = jsonField(json, "operationType");
    policy.description        = jsonField(json, "description");
    policy.maxAttempts        = jsonInt(json, "maxAttempts", policy.maxAttempts);
    policy.baseDelayMs        = jsonInt(json, "baseDelayMs", policy.baseDelayMs);
    policy.maxDelayMs         = jsonInt(json, "maxDelayMs", policy.maxDelayMs);
    policy.backoffMultiplier  = jsonDouble(json, "backoffMultiplier", policy.backoffMultiplier);
    policy.jitterFactor       = jsonDouble(json, "jitterFactor", policy.jitterFactor);
    policy.enableCircuitBreaker = jsonBool(json, "enableCircuitBreaker", policy.enableCircuitBreaker);
    policy.failureThreshold   = jsonInt(json, "failureThreshold", policy.failureThreshold);
    policy.successThreshold   = jsonInt(json, "successThreshold", policy.successThreshold);
    policy.circuitTimeoutMs   = jsonInt(json, "circuitTimeoutMs", policy.circuitTimeoutMs);
    policy.retryableErrorPatterns     = jsonArrayField(json, "retryableErrorPatterns");
    policy.nonRetryableErrorPatterns  = jsonArrayField(json, "nonRetryableErrorPatterns");
    return policy;
}

// ============================================================================
// AdaptiveRetryEngine Implementation
// ============================================================================

AdaptiveRetryEngine::AdaptiveRetryEngine() 
    : m_rng(std::random_device{}()) {
    
    // Register default policies
    registerPolicy(RetryPolicy::defaultLLMInvocation());
    registerPolicy(RetryPolicy::defaultFileOperation());
    registerPolicy(RetryPolicy::defaultBuildOperation());
    registerPolicy(RetryPolicy::defaultTestOperation());
    registerPolicy(RetryPolicy::defaultGitOperation());
}

AdaptiveRetryEngine::~AdaptiveRetryEngine() = default;

void AdaptiveRetryEngine::registerPolicy(const RetryPolicy& policy) {
    if (!policy.validate()) {
        // Log error but don't throw
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_policies[policy.operationType] = policy;
    
    // Create circuit breaker if enabled
    if (policy.enableCircuitBreaker) {
        m_circuitBreakers[policy.operationType] = 
            std::make_unique<CircuitBreaker>(policy.operationType,
                                              policy.failureThreshold,
                                              policy.successThreshold,
                                              policy.circuitTimeoutMs);
    }
    
    // Initialize stats
    m_stats[policy.operationType] = std::make_unique<Stats>();
}

const RetryPolicy* AdaptiveRetryEngine::getPolicy(const std::string& operationType) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_policies.find(operationType);
    if (it != m_policies.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<RetryPolicy> AdaptiveRetryEngine::getAllPolicies() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<RetryPolicy> result;
    result.reserve(m_policies.size());
    for (const auto& pair : m_policies) {
        result.push_back(pair.second);
    }
    return result;
}

bool AdaptiveRetryEngine::removePolicy(const std::string& operationType) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_policies.erase(operationType);
    m_circuitBreakers.erase(operationType);
    m_stats.erase(operationType);
    return true;
}

bool AdaptiveRetryEngine::loadPoliciesFromFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string json = buffer.str();

    // The file is a JSON array of RetryPolicy objects as emitted by
    // savePoliciesToFile(). Split on top-level '{' ... '}' pairs and parse each.
    int imported = 0;
    size_t searchFrom = 0;
    while (true) {
        size_t open = json.find('{', searchFrom);
        if (open == std::string::npos) break;

        // Walk forward to the matching close brace so nested arrays of errors
        // don't terminate the object early.
        size_t close = std::string::npos;
        int depth = 0;
        bool inString = false;
        for (size_t i = open; i < json.size(); ++i) {
            char c = json[i];
            if (c == '"') inString = !inString;
            else if (!inString && c == '{') ++depth;
            else if (!inString && c == '}') {
                --depth;
                if (depth == 0) { close = i; break; }
            }
        }
        if (close == std::string::npos) break;

        std::string obj = json.substr(open, close - open + 1);
        RetryPolicy policy = RetryPolicy::fromJSON(obj);
        if (!policy.operationType.empty() && policy.validate()) {
            registerPolicy(policy);
            ++imported;
        }
        searchFrom = close + 1;
    }
    return imported > 0;
}

bool AdaptiveRetryEngine::savePoliciesToFile(const std::string& filePath) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ofstream file(filePath);
    if (!file.is_open()) return false;
    
    file << "[\n";
    bool first = true;
    for (const auto& pair : m_policies) {
        if (!first) file << ",\n";
        file << pair.second.toJSON();
        first = false;
    }
    file << "\n]";
    return true;
}

int AdaptiveRetryEngine::calculateDelay(const RetryPolicy& policy, int attempt, std::mt19937& rng) const {
    // Exponential backoff: baseDelay * multiplier^(attempt-1)
    double delay = policy.baseDelayMs * std::pow(policy.backoffMultiplier, attempt - 1);
    
    // Cap at maxDelay
    delay = std::min(delay, static_cast<double>(policy.maxDelayMs));
    
    // Add jitter: Â±jitterFactor * delay
    if (policy.jitterFactor > 0.0) {
        std::uniform_real_distribution<double> dist(-policy.jitterFactor, policy.jitterFactor);
        double jitter = delay * dist(rng);
        delay += jitter;
    }
    
    return static_cast<int>(std::max(0.0, delay));
}

bool AdaptiveRetryEngine::isRetryableError(const RetryPolicy& policy, const std::string& error) const {
    std::string lowerError = error;
    std::transform(lowerError.begin(), lowerError.end(), lowerError.begin(), ::tolower);
    
    // Check non-retryable patterns first (explicit deny)
    for (const auto& pattern : policy.nonRetryableErrorPatterns) {
        std::string lowerPattern = pattern;
        std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
        if (lowerError.find(lowerPattern) != std::string::npos) {
            return false;
        }
    }
    
    // Check retryable patterns (explicit allow)
    if (!policy.retryableErrorPatterns.empty()) {
        for (const auto& pattern : policy.retryableErrorPatterns) {
            std::string lowerPattern = pattern;
            std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
            if (lowerError.find(lowerPattern) != std::string::npos) {
                return true;
            }
        }
        // If explicit retryable patterns exist but none match, don't retry
        return false;
    }
    
    // Default: retry on any error if no patterns specified
    return true;
}

void AdaptiveRetryEngine::emitMetric(const std::string& operation, const std::string& metric, double value) const {
    if (m_metricsCb) {
        m_metricsCb(operation, metric, value);
    }
}

int64_t AdaptiveRetryEngine::nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

RetryResult AdaptiveRetryEngine::execute(const std::string& operationType, OperationFn operation) {
    return execute(operationType, operation, [](const std::string&) { return true; });
}

RetryResult AdaptiveRetryEngine::execute(const std::string& operationType, OperationFn operation, ShouldRetryFn shouldRetry) {
    const RetryPolicy* policy = getPolicy(operationType);
    if (!policy) {
        // No policy registered, execute once without retry
        try {
            std::string result = operation();
            return RetryResult::makeOk(result, 1, 0);
        } catch (const std::exception& e) {
            return RetryResult::makeError(e.what(), 1, 0);
        } catch (...) {
            return RetryResult::makeError("Unknown error", 1, 0);
        }
    }
    
    // Check circuit breaker
    auto cbIt = m_circuitBreakers.find(operationType);
    if (cbIt != m_circuitBreakers.end()) {
        if (!cbIt->second->allowRequest()) {
            return RetryResult::makeError("Circuit breaker open for " + operationType, 0, 0, true);
        }
    }
    
    // Get or create stats
    std::unique_ptr<Stats>* statsPtr = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_stats.find(operationType);
        if (it == m_stats.end()) {
            m_stats[operationType] = std::make_unique<Stats>();
        }
        statsPtr = &m_stats[operationType];
    }
    
    // Execute with retries
    int64_t startTime = nowMs();
    std::vector<std::string> attemptErrors;
    std::string lastError;
    
    std::lock_guard<std::mutex> rngLock(m_rngMutex);
    
    for (int attempt = 1; attempt <= policy->maxAttempts; ++attempt) {
        try {
            std::string result = operation();
            
            // Success!
            int64_t elapsed = nowMs() - startTime;
            
            // Update stats
            statsPtr->get()->totalExecutions++;
            statsPtr->get()->successfulExecutions++;
            statsPtr->get()->totalTimeMs += elapsed;
            statsPtr->get()->totalRetries += (attempt - 1);
            
            // Record circuit breaker success
            if (cbIt != m_circuitBreakers.end()) {
                cbIt->second->recordSuccess();
            }
            
            // Emit metrics
            emitMetric(operationType, "success", 1.0);
            emitMetric(operationType, "attempts", static_cast<double>(attempt));
            emitMetric(operationType, "latency_ms", static_cast<double>(elapsed));
            
            return RetryResult::makeOk(result, attempt, elapsed, attemptErrors);
            
        } catch (const std::exception& e) {
            lastError = e.what();
            attemptErrors.push_back(lastError);
        } catch (...) {
            lastError = "Unknown error";
            attemptErrors.push_back(lastError);
        }
        
        // Check if we should retry
        bool retryable = isRetryableError(*policy, lastError) && shouldRetry(lastError);

        if (!retryable || attempt >= policy->maxAttempts) {
            break;
        }

        // Calculate delay and wait
        int delayMs = calculateDelay(*policy, attempt, m_rng);
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }

    // Number of attempts actually performed. The loop may break early on a
    // non-retryable error, so this can be less than policy->maxAttempts.
    const int attemptsMade = static_cast<int>(attemptErrors.size());

    // All attempts failed
    int64_t elapsed = nowMs() - startTime;

    // Update stats. Count only the retries that actually happened:
    //   retries = attempts - 1
    statsPtr->get()->totalExecutions++;
    statsPtr->get()->failedExecutions++;
    statsPtr->get()->totalTimeMs += elapsed;
    statsPtr->get()->totalRetries += (attemptsMade > 1 ? attemptsMade - 1 : 0);

    // Record circuit breaker failure
    if (cbIt != m_circuitBreakers.end()) {
        cbIt->second->recordFailure();
        if (cbIt->second->getState() == CircuitState::Open) {
            return RetryResult::makeError(lastError, attemptsMade, elapsed, true, attemptErrors);
        }
    }

    // Emit metrics
    emitMetric(operationType, "failure", 1.0);
    emitMetric(operationType, "attempts", static_cast<double>(attemptsMade));
    emitMetric(operationType, "latency_ms", static_cast<double>(elapsed));

    return RetryResult::makeError(lastError, attemptsMade, elapsed, false, attemptErrors);
}

void AdaptiveRetryEngine::forceCircuitOpen(const std::string& operationType) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_circuitBreakers.find(operationType);
    if (it != m_circuitBreakers.end()) {
        std::lock_guard<std::mutex> cbLock(it->second->mutex);
        it->second->state.store(CircuitState::Open);
        it->second->lastStateChange.store(nowMs());
    }
}

void AdaptiveRetryEngine::forceCircuitClosed(const std::string& operationType) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_circuitBreakers.find(operationType);
    if (it != m_circuitBreakers.end()) {
        std::lock_guard<std::mutex> cbLock(it->second->mutex);
        it->second->state.store(CircuitState::Closed);
        it->second->failureCount.store(0);
        it->second->lastStateChange.store(nowMs());
    }
}

std::optional<CircuitBreakerSnapshot> AdaptiveRetryEngine::getCircuitBreaker(
    const std::string& operationType) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_circuitBreakers.find(operationType);
    if (it == m_circuitBreakers.end()) return std::nullopt;

    CircuitBreakerSnapshot snap;
    snap.operationType = it->second->operationType;
    snap.state = it->second->state.load();
    snap.failureCount = it->second->failureCount.load();
    snap.successCount = it->second->successCount.load();
    snap.lastFailureTime = it->second->lastFailureTime.load();
    snap.lastStateChange = it->second->lastStateChange.load();
    return snap;
}

std::vector<CircuitBreakerSnapshot> AdaptiveRetryEngine::getAllCircuitBreakers() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<CircuitBreakerSnapshot> result;
    for (const auto& pair : m_circuitBreakers) {
        CircuitBreakerSnapshot snap;
        snap.operationType = pair.second->operationType;
        snap.state = pair.second->state.load();
        snap.failureCount = pair.second->failureCount.load();
        snap.successCount = pair.second->successCount.load();
        snap.lastFailureTime = pair.second->lastFailureTime.load();
        snap.lastStateChange = pair.second->lastStateChange.load();
        result.push_back(snap);
    }
    return result;
}

AdaptiveRetryEngine::OperationStats AdaptiveRetryEngine::getStats(const std::string& operationType) const {
    OperationStats stats;
    stats.operationType = operationType;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto statsIt = m_stats.find(operationType);
    if (statsIt != m_stats.end()) {
        stats.totalExecutions = statsIt->second->totalExecutions.load();
        stats.successfulExecutions = statsIt->second->successfulExecutions.load();
        stats.failedExecutions = statsIt->second->failedExecutions.load();
        stats.totalRetries = statsIt->second->totalRetries.load();
        stats.totalTimeMs = statsIt->second->totalTimeMs.load();
        
        if (stats.totalExecutions > 0) {
            stats.avgAttemptsPerExecution = 1.0 + static_cast<double>(stats.totalRetries) / stats.totalExecutions;
        }
    }
    
    auto cbIt = m_circuitBreakers.find(operationType);
    if (cbIt != m_circuitBreakers.end()) {
        stats.circuitState = cbIt->second->getState();
    }
    
    return stats;
}

std::vector<AdaptiveRetryEngine::OperationStats> AdaptiveRetryEngine::getAllStats() const {
    // Build the policy list under the lock, but call the locking getStats()
    // per operation *outside* it: std::mutex is NOT recursive, so calling
    // getStats() here would self-deadlock.
    std::vector<std::string> opTypes;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        opTypes.reserve(m_policies.size());
        for (const auto& pair : m_policies) opTypes.push_back(pair.first);
    }

    std::vector<OperationStats> result;
    result.reserve(opTypes.size());
    for (const auto& op : opTypes) result.push_back(getStats(op));
    return result;
}

void AdaptiveRetryEngine::resetStats(const std::string& operationType) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_stats.find(operationType);
    if (it != m_stats.end()) {
        it->second->totalExecutions = 0;
        it->second->successfulExecutions = 0;
        it->second->failedExecutions = 0;
        it->second->totalRetries = 0;
        it->second->totalTimeMs = 0;
    }
}

void AdaptiveRetryEngine::resetAllStats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& pair : m_stats) {
        pair.second->totalExecutions = 0;
        pair.second->successfulExecutions = 0;
        pair.second->failedExecutions = 0;
        pair.second->totalRetries = 0;
        pair.second->totalTimeMs = 0;
    }
}

std::string AdaptiveRetryEngine::exportStatsJSON() const {
    auto allStats = getAllStats();
    std::ostringstream oss;
    oss << "[\n";
    for (size_t i = 0; i < allStats.size(); ++i) {
        if (i > 0) oss << ",\n";
        const auto& s = allStats[i];
        oss << "  {\n";
        oss << "    \"operationType\": \"" << s.operationType << "\",\n";
        oss << "    \"totalExecutions\": " << s.totalExecutions << ",\n";
        oss << "    \"successfulExecutions\": " << s.successfulExecutions << ",\n";
        oss << "    \"failedExecutions\": " << s.failedExecutions << ",\n";
        oss << "    \"totalRetries\": " << s.totalRetries << ",\n";
        oss << "    \"totalTimeMs\": " << s.totalTimeMs << ",\n";
        oss << "    \"avgAttemptsPerExecution\": " << s.avgAttemptsPerExecution << ",\n";
        oss << "    \"circuitState\": \"" << [&]() {
            switch (s.circuitState) {
                case CircuitState::Closed: return "closed";
                case CircuitState::Open: return "open";
                case CircuitState::HalfOpen: return "half_open";
            }
            return "unknown";
        }() << "\"\n";
        oss << "  }";
    }
    oss << "\n]";
    return oss.str();
}

// ============================================================================
// Global instance
// ============================================================================

AdaptiveRetryEngine& getGlobalRetryEngine() {
    static AdaptiveRetryEngine instance;
    return instance;
}

// ============================================================================
// Integration helpers (dependency-free)
// ============================================================================

bool retryCall(const std::string& operationType, const std::function<void()>& operation) {
    auto result = getGlobalRetryEngine().execute(operationType, [&operation]() -> std::string {
        operation();
        return "ok";
    });
    return result.success;
}

std::string retryCallWithResult(const std::string& operationType,
                                const std::function<std::string()>& operation) {
    auto result = getGlobalRetryEngine().execute(operationType, operation);
    if (!result.success) throw std::runtime_error(result.errorMessage);
    return result.result;
}

bool isRetryableUnderPolicy(const std::string& operationType, const std::string& error) {
    const RetryPolicy* policy = getGlobalRetryEngine().getPolicy(operationType);
    if (!policy) return false;
    // Reuse the engine's private matcher via a policy-level check.
    std::string lowerError = error;
    std::transform(lowerError.begin(), lowerError.end(), lowerError.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto matches = [&](const std::vector<std::string>& patterns) {
        for (const auto& pattern : patterns) {
            std::string p = pattern;
            std::transform(p.begin(), p.end(), p.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (lowerError.find(p) != std::string::npos) return true;
        }
        return false;
    };

    if (matches(policy->nonRetryableErrorPatterns)) return false;
    if (policy->retryableErrorPatterns.empty()) return true;
    return matches(policy->retryableErrorPatterns);
}