// ============================================================================
// BackendHealthMonitor.cpp — Backend Health, Latency Tracking & Auto-Failover
// ============================================================================
#include "BackendHealthMonitor.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <numeric>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace RawrXD {
namespace Security {

// ============================================================================
// Constructor / Destructor
// ============================================================================
BackendHealthMonitor::BackendHealthMonitor() = default;

BackendHealthMonitor::~BackendHealthMonitor() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool BackendHealthMonitor::Initialize() {
    if (m_initialized) return true;

    // Register default backends
    RegisterBackend({
        "local-deep2",
        BackendType::LocalGGUF,
        "local",
        "",
        0,      // Highest priority
        3,      // maxRetries
        30000,  // timeoutMs
        30,     // healthCheckIntervalSec
        5000.0f, // degradationThreshold
        30000.0f, // offlineThreshold
        true
    });

    RegisterBackend({
        "ollama",
        BackendType::Ollama,
        "http://localhost:11434",
        "",
        1,      // Second priority
        3,
        15000,
        15,
        3000.0f,
        15000.0f,
        true
    });

    RegisterBackend({
        "openai",
        BackendType::OpenAI,
        "https://api.openai.com",
        "",     // API key from env
        2,      // Third priority
        2,
        30000,
        60,
        10000.0f,
        60000.0f,
        false   // Disabled by default
    });

    // Start health check thread
    m_running = true;
    m_healthThread = std::thread(&BackendHealthMonitor::HealthCheckLoop, this);

    m_initialized = true;
    return true;
}

void BackendHealthMonitor::Shutdown() {
    m_running = false;
    m_initialized = false;

    if (m_healthThread.joinable()) {
        m_healthThread.join();
    }
}

// ============================================================================
// Backend Registration
// ============================================================================
void BackendHealthMonitor::RegisterBackend(const BackendConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto state = std::make_unique<BackendState>();
    state->config = config;
    state->status = BackendStatus::Unknown;
    m_backends[config.name] = std::move(state);
}

void BackendHealthMonitor::UnregisterBackend(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_backends.erase(name);
}

std::vector<BackendConfig> BackendHealthMonitor::GetRegisteredBackends() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<BackendConfig> result;
    for (const auto& [name, state] : m_backends) {
        result.push_back(state->config);
    }
    return result;
}

BackendConfig BackendHealthMonitor::GetBackend(const std::string& name) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(name);
    if (it != m_backends.end()) {
        return it->second->config;
    }
    return BackendConfig{};
}

// ============================================================================
// Health Checks
// ============================================================================
HealthResult BackendHealthMonitor::CheckHealth(const std::string& backendName) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_backends.find(backendName);
    if (it == m_backends.end()) {
        HealthResult result;
        result.status = BackendStatus::Error;
        result.error = "Backend not found: " + backendName;
        return result;
    }

    auto& state = it->second;
    HealthResult result;

    switch (state->config.type) {
        case BackendType::LocalGGUF:
            result = CheckLocalGGUF(state->config);
            break;
        case BackendType::Ollama:
            result = CheckOllama(state->config);
            break;
        case BackendType::OpenAI:
            result = CheckOpenAI(state->config);
            break;
        default:
            result.status = BackendStatus::Unknown;
            result.error = "Unsupported backend type";
            break;
    }

    result.checkedAt = std::chrono::system_clock::now();
    state->lastHealth = result;

    // Update status based on result
    BackendStatus oldStatus = state->status;
    state->status = result.status;
    if (oldStatus != result.status) {
        UpdateStatus(backendName, result.status);
    }

    if (result.status == BackendStatus::Online || result.status == BackendStatus::Degraded) {
        state->consecutiveFailures = 0;
    } else {
        state->consecutiveFailures++;
    }

    return result;
}

HealthResult BackendHealthMonitor::GetLastHealth(const std::string& backendName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(backendName);
    if (it != m_backends.end()) {
        return it->second->lastHealth;
    }
    return HealthResult{};
}

BackendStatus BackendHealthMonitor::GetStatus(const std::string& backendName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(backendName);
    if (it != m_backends.end()) {
        return it->second->status;
    }
    return BackendStatus::Unknown;
}

std::vector<std::string> BackendHealthMonitor::GetOnlineBackends() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> result;
    for (const auto& [name, state] : m_backends) {
        if (state->status == BackendStatus::Online && state->config.enabled) {
            result.push_back(name);
        }
    }
    return result;
}

std::vector<std::string> BackendHealthMonitor::GetAvailableBackends() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> result;
    for (const auto& [name, state] : m_backends) {
        if ((state->status == BackendStatus::Online || 
             state->status == BackendStatus::Degraded) && 
            state->config.enabled) {
            result.push_back(name);
        }
    }
    return result;
}

// ============================================================================
// Latency Tracking
// ============================================================================
void BackendHealthMonitor::RecordLatency(const std::string& backendName, double latencyMs,
                                          const std::string& operation, bool success) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_backends.find(backendName);
    if (it == m_backends.end()) return;

    auto& state = it->second;
    LatencyRecord record;
    record.latencyMs = latencyMs;
    record.operation = operation;
    record.timestamp = std::chrono::system_clock::now();
    record.success = success;

    state->latencies.push_back(record);

    // Keep only last 1000 records
    if (state->latencies.size() > 1000) {
        state->latencies.erase(state->latencies.begin());
    }

    m_totalRequests++;
    if (!success) m_failedRequests++;
}

double BackendHealthMonitor::GetAverageLatency(const std::string& backendName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(backendName);
    if (it == m_backends.end() || it->second->latencies.empty()) return 0.0;

    const auto& latencies = it->second->latencies;
    double sum = 0.0;
    for (const auto& r : latencies) {
        sum += r.latencyMs;
    }
    return sum / latencies.size();
}

double BackendHealthMonitor::GetP95Latency(const std::string& backendName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(backendName);
    if (it == m_backends.end() || it->second->latencies.empty()) return 0.0;

    auto latencies = it->second->latencies;
    std::sort(latencies.begin(), latencies.end(),
        [](const LatencyRecord& a, const LatencyRecord& b) {
            return a.latencyMs < b.latencyMs;
        });

    size_t idx = static_cast<size_t>(latencies.size() * 0.95);
    if (idx >= latencies.size()) idx = latencies.size() - 1;
    return latencies[idx].latencyMs;
}

json BackendHealthMonitor::GetLatencyStats(const std::string& backendName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    json stats;

    auto it = m_backends.find(backendName);
    if (it == m_backends.end() || it->second->latencies.empty()) {
        stats["available"] = false;
        return stats;
    }

    const auto& latencies = it->second->latencies;
    std::vector<double> values;
    for (const auto& r : latencies) {
        values.push_back(r.latencyMs);
    }

    std::sort(values.begin(), values.end());

    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    stats["count"] = values.size();
    stats["min_ms"] = values.front();
    stats["max_ms"] = values.back();
    stats["avg_ms"] = sum / values.size();
    stats["p50_ms"] = values[values.size() * 0.5];
    stats["p95_ms"] = values[values.size() * 0.95];
    stats["p99_ms"] = values[values.size() * 0.99];
    stats["success_rate"] = static_cast<double>(it->second->consecutiveFailures == 0 ? 100 : 
        std::max(0, 100 - it->second->consecutiveFailures * 10));

    return stats;
}

// ============================================================================
// Auto-Failover Routing
// ============================================================================
RoutingDecision BackendHealthMonitor::RouteRequest(const std::string& taskType,
                                                    int estimatedTokens,
                                                    const std::vector<std::string>& preferredBackends) {
    std::lock_guard<std::mutex> lock(m_mutex);

    RoutingDecision decision;
    decision.confidence = 0.0f;
    decision.reason = "No available backends";

    // Try preferred backends first
    for (const auto& preferred : preferredBackends) {
        auto it = m_backends.find(preferred);
        if (it != m_backends.end() && it->second->config.enabled &&
            (it->second->status == BackendStatus::Online ||
             it->second->status == BackendStatus::Degraded)) {
            decision.backendName = preferred;
            decision.backendType = it->second->config.type;
            decision.estimatedLatencyMs = GetAverageLatency(preferred);
            decision.confidence = CalculateScore(it->second->config, taskType);
            decision.reason = "Preferred backend available";
            return decision;
        }
    }

    // Score all available backends
    float bestScore = -1.0f;
    for (const auto& [name, state] : m_backends) {
        if (!state->config.enabled) continue;
        if (state->status != BackendStatus::Online && 
            state->status != BackendStatus::Degraded) continue;

        float score = CalculateScore(state->config, taskType);
        if (score > bestScore) {
            bestScore = score;
            decision.backendName = name;
            decision.backendType = state->config.type;
            decision.estimatedLatencyMs = GetAverageLatency(name);
            decision.confidence = score;
            decision.reason = "Best scoring backend";
        }
    }

    return decision;
}

RoutingDecision BackendHealthMonitor::Failover(const std::string& failedBackend,
                                                const std::string& taskType) {
    m_failoverCount++;

    // Get all backends except the failed one
    std::vector<std::string> alternatives;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& [name, state] : m_backends) {
            if (name != failedBackend && state->config.enabled &&
                (state->status == BackendStatus::Online ||
                 state->status == BackendStatus::Degraded)) {
                alternatives.push_back(name);
            }
        }
    }

    RoutingDecision decision = RouteRequest(taskType, 0, alternatives);

    if (m_failoverCb && !decision.backendName.empty()) {
        m_failoverCb(failedBackend, decision.backendName);
    }

    return decision;
}

// ============================================================================
// Quality Scoring
// ============================================================================
float BackendHealthMonitor::GetQualityScore(const std::string& backendName) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(backendName);
    if (it == m_backends.end() || it->second->qualityScores.empty()) return 0.0f;

    const auto& scores = it->second->qualityScores;
    float sum = std::accumulate(scores.begin(), scores.end(), 0.0f);
    return sum / scores.size();
}

void BackendHealthMonitor::RecordQuality(const std::string& backendName, float score) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_backends.find(backendName);
    if (it == m_backends.end()) return;

    it->second->qualityScores.push_back(score);
    if (it->second->qualityScores.size() > 100) {
        it->second->qualityScores.erase(it->second->qualityScores.begin());
    }
}

// ============================================================================
// Statistics
// ============================================================================
json BackendHealthMonitor::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    json stats;

    stats["total_requests"] = m_totalRequests.load();
    stats["failed_requests"] = m_failedRequests.load();
    stats["failover_count"] = m_failoverCount.load();

    json backends = json::object();
    for (const auto& [name, state] : m_backends) {
        json b;
        b["status"] = static_cast<int>(state->status);
        b["enabled"] = state->config.enabled;
        b["priority"] = state->config.priority;
        b["consecutive_failures"] = state->consecutiveFailures;
        b["avg_latency_ms"] = GetAverageLatency(name);
        b["quality_score"] = GetQualityScore(name);
        backends[name] = b;
    }
    stats["backends"] = backends;

    return stats;
}

// ============================================================================
// Private: Health Check Loop
// ============================================================================
void BackendHealthMonitor::HealthCheckLoop() {
    while (m_running.load()) {
        // Check each backend
        std::vector<std::string> backendsToCheck;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& [name, state] : m_backends) {
                if (state->config.enabled) {
                    backendsToCheck.push_back(name);
                }
            }
        }

        for (const auto& name : backendsToCheck) {
            if (!m_running.load()) break;
            CheckHealth(name);
        }

        // Sleep for the shortest check interval
        int sleepSec = 30;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (const auto& [name, state] : m_backends) {
                if (state->config.healthCheckIntervalSec < sleepSec) {
                    sleepSec = state->config.healthCheckIntervalSec;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(sleepSec));
    }
}

// ============================================================================
// Private: Backend-Specific Health Checks
// ============================================================================
HealthResult BackendHealthMonitor::CheckLocalGGUF(const BackendConfig& config) {
    HealthResult result;
    auto t0 = std::chrono::high_resolution_clock::now();

    // Check if the GGUF model file exists
    std::string modelPath = config.endpoint.empty() ? "models/deep2-22b-q4.gguf" : config.endpoint;
    
    FILE* f = fopen(modelPath.c_str(), "rb");
    if (f) {
        fclose(f);
        result.status = BackendStatus::Online;
        result.modelLoaded = true;
        result.modelName = modelPath;
    } else {
        result.status = BackendStatus::Degraded;
        result.error = "Model file not found: " + modelPath;
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    result.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    return result;
}

HealthResult BackendHealthMonitor::CheckOllama(const BackendConfig& config) {
    HealthResult result;
    auto t0 = std::chrono::high_resolution_clock::now();

#ifdef _WIN32
    // Simple WinHTTP health check
    HINTERNET hSession = WinHttpOpen(L"RawrXD-HealthCheck/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (hSession) {
        std::wstring url = L"http://localhost:11434/api/tags";
        HINTERNET hConnect = WinHttpOpenRequest(hSession, L"GET", L"/api/tags",
            NULL, NULL, NULL, 0);
        if (hConnect) {
            if (WinHttpSendRequest(hConnect, NULL, 0, NULL, 0, 0, 0)) {
                if (WinHttpReceiveResponse(hConnect, NULL)) {
                    result.status = BackendStatus::Online;
                    result.modelLoaded = true;
                }
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
#endif

    if (result.status == BackendStatus::Unknown) {
        result.status = BackendStatus::Offline;
        result.error = "Ollama not reachable";
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    result.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    return result;
}

HealthResult BackendHealthMonitor::CheckOpenAI(const BackendConfig& config) {
    HealthResult result;
    auto t0 = std::chrono::high_resolution_clock::now();

    // Check if API key is configured
    const char* apiKey = getenv("OPENAI_API_KEY");
    if (apiKey && strlen(apiKey) > 0) {
        result.status = BackendStatus::Online;
        result.modelLoaded = true;
    } else {
        result.status = BackendStatus::Offline;
        result.error = "OPENAI_API_KEY not set";
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    result.latencyMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    return result;
}

// ============================================================================
// Private: Status Management
// ============================================================================
void BackendHealthMonitor::UpdateStatus(const std::string& name, BackendStatus newStatus) {
    auto it = m_backends.find(name);
    if (it == m_backends.end()) return;

    BackendStatus oldStatus = it->second->status;
    it->second->status = newStatus;

    if (m_statusCb && oldStatus != newStatus) {
        m_statusCb(name, oldStatus, newStatus);
    }

    printf("[HealthMonitor] Backend '%s' status: %d -> %d\n",
           name.c_str(), static_cast<int>(oldStatus), static_cast<int>(newStatus));
}

// ============================================================================
// Private: Scoring
// ============================================================================
float BackendHealthMonitor::CalculateScore(const BackendConfig& config, 
                                            const std::string& taskType) const {
    float score = 100.0f;

    // Priority bonus (lower number = higher priority)
    score -= config.priority * 10.0f;

    // Latency penalty
    double avgLatency = 0.0;
    auto it = m_backends.find(config.name);
    if (it != m_backends.end() && !it->second->latencies.empty()) {
        const auto& latencies = it->second->latencies;
        double sum = 0.0;
        for (const auto& r : latencies) {
            sum += r.latencyMs;
        }
        avgLatency = sum / latencies.size();
    }

    if (avgLatency > config.degradationThresholdMs) {
        score -= 20.0f;
    }
    if (avgLatency > config.offlineThresholdMs) {
        score -= 50.0f;
    }

    // Quality bonus
    float quality = GetQualityScore(config.name);
    score += quality * 10.0f;

    // Consecutive failure penalty
    auto stateIt = m_backends.find(config.name);
    if (stateIt != m_backends.end()) {
        score -= stateIt->second->consecutiveFailures * 5.0f;
    }

    return std::max(0.0f, score);
}

} // namespace Security
} // namespace RawrXD
