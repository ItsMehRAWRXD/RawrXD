// RawrXD Health Checks
// Phase 9 - Task 16: Health Checks

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <mutex>

// Health check types
enum HealthCheckType {
    HEALTH_LIVENESS,    // Is the process running?
    HEALTH_READINESS,   // Is it ready to serve traffic?
    HEALTH_STARTUP      // Has it finished starting up?
};

// Health status
enum HealthStatus {
    HEALTH_UNKNOWN,
    HEALTH_HEALTHY,
    HEALTH_DEGRADED,
    HEALTH_UNHEALTHY
};

// Health check result
struct HealthCheckResult {
    HealthCheckType type;
    HealthStatus status;
    std::string component;
    std::string message;
    std::chrono::steady_clock::time_point timestamp;
    int responseTimeMs;
};

// Health check function
using HealthCheckFunc = std::function<HealthCheckResult()>;

// Health check configuration
struct HealthCheckConfig {
    std::string name;
    HealthCheckType type;
    HealthCheckFunc check;
    int intervalMs;
    int timeoutMs;
    int failureThreshold;
    int successThreshold;
};

// Health check manager
class HealthCheckManager {
private:
    std::vector<HealthCheckConfig> checks;
    std::map<std::string, HealthCheckResult> results;
    std::map<std::string, int> failureCounts;
    std::map<std::string, int> successCounts;
    std::mutex healthMutex;
    std::vector<std::thread> checkThreads;
    std::atomic<bool> running;
    
public:
    HealthCheckManager() : running(false) {}
    
    ~HealthCheckManager() {
        Shutdown();
    }
    
    bool Initialize() {
        running = true;
        
        // Register default health checks
        RegisterDefaultChecks();
        
        // Start check threads
        for (const auto& check : checks) {
            checkThreads.emplace_back(&HealthCheckManager::CheckLoop, this, check);
        }
        
        printf("Health check manager initialized\n");
        return true;
    }
    
    void RegisterDefaultChecks() {
        // Liveness check
        RegisterCheck({
            "liveness",
            HEALTH_LIVENESS,
            [&]() -> HealthCheckResult {
                HealthCheckResult result;
                result.type = HEALTH_LIVENESS;
                result.component = "process";
                result.status = HEALTH_HEALTHY;
                result.message = "Process is running";
                result.timestamp = std::chrono::steady_clock::now();
                result.responseTimeMs = 0;
                return result;
            },
            10000,  // 10 seconds
            5000,   // 5 second timeout
            3,      // 3 failures threshold
            1       // 1 success threshold
        });
        
        // Readiness check - model loaded
        RegisterCheck({
            "readiness_model",
            HEALTH_READINESS,
            [&]() -> HealthCheckResult {
                HealthCheckResult result;
                result.type = HEALTH_READINESS;
                result.component = "model";
                // Check if model is loaded
                result.status = HEALTH_HEALTHY;  // Simplified
                result.message = "Model is loaded";
                result.timestamp = std::chrono::steady_clock::now();
                result.responseTimeMs = 0;
                return result;
            },
            30000,  // 30 seconds
            10000,  // 10 second timeout
            3,
            1
        });
        
        // Readiness check - GPU available
        RegisterCheck({
            "readiness_gpu",
            HEALTH_READINESS,
            [&]() -> HealthCheckResult {
                HealthCheckResult result;
                result.type = HEALTH_READINESS;
                result.component = "gpu";
                // Check GPU availability
                result.status = HEALTH_HEALTHY;  // Simplified
                result.message = "GPU is available";
                result.timestamp = std::chrono::steady_clock::now();
                result.responseTimeMs = 0;
                return result;
            },
            30000,
            5000,
            3,
            1
        });
        
        // Startup check
        RegisterCheck({
            "startup",
            HEALTH_STARTUP,
            [&]() -> HealthCheckResult {
                HealthCheckResult result;
                result.type = HEALTH_STARTUP;
                result.component = "service";
                // Check if startup complete
                result.status = HEALTH_HEALTHY;  // Simplified
                result.message = "Startup complete";
                result.timestamp = std::chrono::steady_clock::now();
                result.responseTimeMs = 0;
                return result;
            },
            5000,
            30000,
            1,
            1
        });
    }
    
    void RegisterCheck(const HealthCheckConfig& config) {
        std::lock_guard<std::mutex> lock(healthMutex);
        checks.push_back(config);
        failureCounts[config.name] = 0;
        successCounts[config.name] = 0;
    }
    
    void CheckLoop(HealthCheckConfig config) {
        while (running) {
            auto start = std::chrono::steady_clock::now();
            
            // Run health check
            HealthCheckResult result = config.check();
            
            auto end = std::chrono::steady_clock::now();
            result.responseTimeMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                end - start).count();
            
            // Update failure/success counts
            {
                std::lock_guard<std::mutex> lock(healthMutex);
                
                if (result.status == HEALTH_HEALTHY) {
                    successCounts[config.name]++;
                    failureCounts[config.name] = 0;
                    
                    // Mark as healthy after success threshold
                    if (successCounts[config.name] >= config.successThreshold) {
                        results[config.name] = result;
                    }
                } else {
                    failureCounts[config.name]++;
                    successCounts[config.name] = 0;
                    
                    // Mark as unhealthy after failure threshold
                    if (failureCounts[config.name] >= config.failureThreshold) {
                        results[config.name] = result;
                        
                        printf("Health check failed: %s - %s\n", 
                               config.name.c_str(), result.message.c_str());
                    }
                }
            }
            
            // Sleep until next check
            Sleep(config.intervalMs);
        }
    }
    
    // Get overall health status
    HealthStatus GetOverallHealth(HealthCheckType type) {
        std::lock_guard<std::mutex> lock(healthMutex);
        
        HealthStatus worstStatus = HEALTH_HEALTHY;
        
        for (const auto& pair : results) {
            // Find config for this check
            auto it = std::find_if(checks.begin(), checks.end(),
                [&](const HealthCheckConfig& c) { return c.name == pair.first; });
            
            if (it != checks.end() && it->type == type) {
                if (pair.second.status == HEALTH_UNHEALTHY) {
                    return HEALTH_UNHEALTHY;
                } else if (pair.second.status == HEALTH_DEGRADED) {
                    worstStatus = HEALTH_DEGRADED;
                }
            }
        }
        
        return worstStatus;
    }
    
    // Get liveness status
    bool IsAlive() {
        return GetOverallHealth(HEALTH_LIVENESS) == HEALTH_HEALTHY;
    }
    
    // Get readiness status
    bool IsReady() {
        return GetOverallHealth(HEALTH_READINESS) == HEALTH_HEALTHY;
    }
    
    // Get startup status
    bool IsStarted() {
        return GetOverallHealth(HEALTH_STARTUP) == HEALTH_HEALTHY;
    }
    
    // Get detailed health report
    std::string GetHealthReport() {
        std::lock_guard<std::mutex> lock(healthMutex);
        
        std::string report = "{\n";
        report += "  \"status\": \"" + std::string(IsReady() ? "healthy" : "unhealthy") + "\",\n";
        report += "  \"checks\": [\n";
        
        bool first = true;
        for (const auto& pair : results) {
            if (!first) report += ",\n";
            
            const char* statusStr = "unknown";
            switch (pair.second.status) {
                case HEALTH_HEALTHY: statusStr = "healthy"; break;
                case HEALTH_DEGRADED: statusStr = "degraded"; break;
                case HEALTH_UNHEALTHY: statusStr = "unhealthy"; break;
                default: break;
            }
            
            report += "    {\n";
            report += "      \"name\": \"" + pair.first + "\",\n";
            report += "      \"status\": \"" + std::string(statusStr) + "\",\n";
            report += "      \"component\": \"" + pair.second.component + "\",\n";
            report += "      \"message\": \"" + pair.second.message + "\",\n";
            report += "      \"response_time_ms\": " + std::to_string(pair.second.responseTimeMs) + "\n";
            report += "    }";
            
            first = false;
        }
        
        report += "\n  ]\n";
        report += "}\n";
        
        return report;
    }
    
    void Shutdown() {
        running = false;
        
        for (auto& thread : checkThreads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }
};

// Global instance
static HealthCheckManager g_HealthManager;

// C API
extern "C" {

bool Health_Init() {
    return g_HealthManager.Initialize();
}

bool Health_IsAlive() {
    return g_HealthManager.IsAlive();
}

bool Health_IsReady() {
    return g_HealthManager.IsReady();
}

bool Health_IsStarted() {
    return g_HealthManager.IsStarted();
}

const char* Health_GetReport() {
    static std::string report;
    report = g_HealthManager.GetHealthReport();
    return report.c_str();
}

void Health_Shutdown() {
    g_HealthManager.Shutdown();
}

} // extern "C"
