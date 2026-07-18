// RawrXD Canary Deployment
// Phase 9 - Task 15: Canary Deployments

#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <math.h>
#include <mutex>

// Canary deployment state
enum CanaryState {
    CANARY_PENDING,
    CANARY_RUNNING,
    CANARY_PROMOTING,
    CANARY_ROLLING_BACK,
    CANARY_COMPLETED,
    CANARY_FAILED
};

// Health check result
struct HealthCheckResult {
    bool healthy;
    float errorRate;
    float latencyP99;
    float cpuUsage;
    float memoryUsage;
    std::string message;
};

// Canary configuration
struct CanaryConfig {
    std::string deploymentId;
    std::string newVersion;
    std::string currentVersion;
    float initialTrafficPercent;
    float maxTrafficPercent;
    float trafficIncrement;
    int stepDurationMinutes;
    float maxErrorRate;
    float maxLatencyP99;
    int minSamplesPerStep;
};

// Canary metrics
struct CanaryMetrics {
    int totalRequests;
    int errorRequests;
    float totalLatency;
    float minLatency;
    float maxLatency;
    std::vector<float> latencies;
};

// Canary deployment manager
class CanaryDeploymentManager {
private:
    std::map<std::string, CanaryConfig> deployments;
    std::map<std::string, CanaryState> states;
    std::map<std::string, float> currentTrafficPercent;
    std::map<std::string, CanaryMetrics> metrics;
    std::map<std::string, std::chrono::steady_clock::time_point> stepStartTimes;
    std::mutex deployMutex;
    std::thread monitorThread;
    std::atomic<bool> running;
    
public:
    CanaryDeploymentManager() : running(false) {}
    
    ~CanaryDeploymentManager() {
        Shutdown();
    }
    
    bool Initialize() {
        running = true;
        monitorThread = std::thread(&CanaryDeploymentManager::MonitorLoop, this);
        
        printf("Canary deployment manager initialized\n");
        return true;
    }
    
    // Start new canary deployment
    bool StartDeployment(const CanaryConfig& config) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        if (deployments.find(config.deploymentId) != deployments.end()) {
            printf("Deployment %s already exists\n", config.deploymentId.c_str());
            return false;
        }
        
        deployments[config.deploymentId] = config;
        states[config.deploymentId] = CANARY_PENDING;
        currentTrafficPercent[config.deploymentId] = config.initialTrafficPercent;
        metrics[config.deploymentId] = {};
        
        printf("Started canary deployment: %s\n", config.deploymentId.c_str());
        printf("  New version: %s\n", config.newVersion.c_str());
        printf("  Current version: %s\n", config.currentVersion.c_str());
        printf("  Initial traffic: %.1f%%\n", config.initialTrafficPercent * 100);
        printf("  Max traffic: %.1f%%\n", config.maxTrafficPercent * 100);
        
        return true;
    }
    
    // Get traffic split for a deployment
    float GetTrafficPercent(const std::string& deploymentId) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        auto it = currentTrafficPercent.find(deploymentId);
        if (it != currentTrafficPercent.end()) {
            return it->second;
        }
        
        return 0.0f;
    }
    
    // Route request to canary or stable
    bool ShouldRouteToCanary(const std::string& deploymentId, const std::string& userId) {
        float canaryPercent = GetTrafficPercent(deploymentId);
        
        if (canaryPercent <= 0.0f) return false;
        if (canaryPercent >= 1.0f) return true;
        
        // Deterministic routing based on user ID
        std::hash<std::string> hasher;
        size_t hash = hasher(userId + deploymentId);
        float normalized = (float)(hash % 10000) / 10000.0f;
        
        return normalized < canaryPercent;
    }
    
    // Record canary metrics
    void RecordMetrics(const std::string& deploymentId, bool success, float latencyMs) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        auto it = metrics.find(deploymentId);
        if (it == metrics.end()) return;
        
        auto& m = it->second;
        m.totalRequests++;
        if (!success) m.errorRequests++;
        m.totalLatency += latencyMs;
        m.latencies.push_back(latencyMs);
        
        if (latencyMs < m.minLatency || m.minLatency == 0) m.minLatency = latencyMs;
        if (latencyMs > m.maxLatency) m.maxLatency = latencyMs;
    }
    
    // Perform health check
    HealthCheckResult HealthCheck(const std::string& deploymentId) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        HealthCheckResult result = {};
        result.healthy = true;
        
        auto it = metrics.find(deploymentId);
        if (it == metrics.end()) {
            result.healthy = false;
            result.message = "Deployment not found";
            return result;
        }
        
        auto& m = it->second;
        auto configIt = deployments.find(deploymentId);
        if (configIt == deployments.end()) {
            result.healthy = false;
            result.message = "Config not found";
            return result;
        }
        
        // Calculate metrics
        if (m.totalRequests > 0) {
            result.errorRate = (float)m.errorRequests / m.totalRequests;
            
            // Calculate P99 latency
            if (!m.latencies.empty()) {
                std::sort(m.latencies.begin(), m.latencies.end());
                size_t p99Index = (size_t)(m.latencies.size() * 0.99);
                result.latencyP99 = m.latencies[p99Index];
            }
        }
        
        // Check thresholds
        if (result.errorRate > configIt->second.maxErrorRate) {
            result.healthy = false;
            result.message = "Error rate exceeded threshold";
        }
        
        if (result.latencyP99 > configIt->second.maxLatencyP99) {
            result.healthy = false;
            result.message = "Latency exceeded threshold";
        }
        
        return result;
    }
    
    // Promote canary to full deployment
    bool Promote(const std::string& deploymentId) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        auto it = states.find(deploymentId);
        if (it == states.end()) return false;
        
        it->second = CANARY_PROMOTING;
        currentTrafficPercent[deploymentId] = 1.0f;
        
        printf("Promoting canary deployment: %s\n", deploymentId.c_str());
        
        // In production, would update load balancer config
        
        it->second = CANARY_COMPLETED;
        return true;
    }
    
    // Rollback canary deployment
    bool Rollback(const std::string& deploymentId) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        auto it = states.find(deploymentId);
        if (it == states.end()) return false;
        
        it->second = CANARY_ROLLING_BACK;
        currentTrafficPercent[deploymentId] = 0.0f;
        
        printf("Rolling back canary deployment: %s\n", deploymentId.c_str());
        
        // In production, would revert load balancer config
        
        it->second = CANARY_FAILED;
        return true;
    }
    
    // Get deployment status
    void GetStatus(const std::string& deploymentId, CanaryState& state, 
                   float& trafficPercent, HealthCheckResult& health) {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        auto it = states.find(deploymentId);
        if (it != states.end()) {
            state = it->second;
        } else {
            state = CANARY_FAILED;
        }
        
        auto trafficIt = currentTrafficPercent.find(deploymentId);
        if (trafficIt != currentTrafficPercent.end()) {
            trafficPercent = trafficIt->second;
        } else {
            trafficPercent = 0.0f;
        }
        
        health = HealthCheck(deploymentId);
    }
    
    // List active deployments
    std::vector<std::string> GetActiveDeployments() {
        std::lock_guard<std::mutex> lock(deployMutex);
        
        std::vector<std::string> active;
        for (const auto& pair : states) {
            if (pair.second == CANARY_RUNNING || pair.second == CANARY_PENDING) {
                active.push_back(pair.first);
            }
        }
        return active;
    }
    
    void Shutdown() {
        running = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
    
private:
    void MonitorLoop() {
        while (running) {
            Sleep(60000); // Check every minute
            
            std::lock_guard<std::mutex> lock(deployMutex);
            
            for (auto& pair : states) {
                if (pair.second != CANARY_RUNNING) continue;
                
                const std::string& deployId = pair.first;
                
                // Check health
                HealthCheckResult health = HealthCheck(deployId);
                if (!health.healthy) {
                    printf("Canary %s failed health check: %s\n", 
                           deployId.c_str(), health.message.c_str());
                    Rollback(deployId);
                    continue;
                }
                
                // Check if ready to advance
                auto& metrics = this->metrics[deployId];
                auto& config = deployments[deployId];
                
                if (metrics.totalRequests >= config.minSamplesPerStep) {
                    float currentTraffic = currentTrafficPercent[deployId];
                    
                    if (currentTraffic >= config.maxTrafficPercent) {
                        // Ready for full promotion
                        Promote(deployId);
                    } else {
                        // Advance traffic
                        currentTrafficPercent[deployId] = 
                            fminf(currentTraffic + config.trafficIncrement, 
                                  config.maxTrafficPercent);
                        
                        printf("Canary %s traffic increased to %.1f%%\n",
                               deployId.c_str(), 
                               currentTrafficPercent[deployId] * 100);
                        
                        // Reset metrics for next step
                        metrics = {};
                    }
                }
            }
        }
    }
};

// Global instance
static CanaryDeploymentManager g_CanaryManager;

// C API
extern "C" {

bool Canary_Init() {
    return g_CanaryManager.Initialize();
}

bool Canary_Start(const char* deploymentId, const char* newVersion, const char* currentVersion,
                  float initialTraffic, float maxTraffic, float increment,
                  float maxErrorRate, float maxLatency) {
    CanaryConfig config;
    config.deploymentId = deploymentId;
    config.newVersion = newVersion;
    config.currentVersion = currentVersion;
    config.initialTrafficPercent = initialTraffic;
    config.maxTrafficPercent = maxTraffic;
    config.trafficIncrement = increment;
    config.stepDurationMinutes = 10;
    config.maxErrorRate = maxErrorRate;
    config.maxLatencyP99 = maxLatency;
    config.minSamplesPerStep = 100;
    
    return g_CanaryManager.StartDeployment(config);
}

bool Canary_ShouldRoute(const char* deploymentId, const char* userId) {
    return g_CanaryManager.ShouldRouteToCanary(deploymentId, userId);
}

void Canary_RecordMetrics(const char* deploymentId, bool success, float latencyMs) {
    g_CanaryManager.RecordMetrics(deploymentId, success, latencyMs);
}

bool Canary_Promote(const char* deploymentId) {
    return g_CanaryManager.Promote(deploymentId);
}

bool Canary_Rollback(const char* deploymentId) {
    return g_CanaryManager.Rollback(deploymentId);
}

void Canary_Shutdown() {
    g_CanaryManager.Shutdown();
}

} // extern "C"
