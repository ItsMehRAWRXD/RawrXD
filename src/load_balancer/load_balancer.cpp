// RawrXD Load Balancer
// Phase 9 - Task 4: Load Balancer

#include <windows.h>
#include <vector>
#include <string.h>
#include <math.h>
#include <atomic>
#include <mutex>

// Backend server configuration
struct BackendServer {
    char address[256];
    int port;
    int weight;
    std::atomic<bool> healthy;
    std::atomic<int> activeConnections;
    std::atomic<uint64_t> totalRequests;
    std::atomic<uint64_t> failedRequests;
    std::atomic<double> avgResponseTime;
    uint64_t lastHealthCheck;
};

// Load balancing algorithms
enum LoadBalancerAlgorithm {
    LB_ROUND_ROBIN,
    LB_WEIGHTED_ROUND_ROBIN,
    LB_LEAST_CONNECTIONS,
    LB_IP_HASH,
    LB_HEALTH_BASED,
    LB_LATENCY_BASED
};

// Load balancer configuration
struct LoadBalancerConfig {
    LoadBalancerAlgorithm algorithm;
    int healthCheckIntervalMs;
    int healthCheckTimeoutMs;
    int maxRetries;
    bool stickySessions;
};

// Load balancer
class LoadBalancer {
private:
    std::vector<BackendServer*> backends;
    LoadBalancerConfig config;
    std::atomic<int> currentIndex;
    std::mutex backendMutex;
    std::atomic<bool> running;
    HANDLE healthCheckThread;
    
public:
    LoadBalancer() : currentIndex(0), running(false) {}
    
    ~LoadBalancer() {
        Shutdown();
    }
    
    bool Initialize(const LoadBalancerConfig& cfg) {
        config = cfg;
        running = true;
        
        // Start health check thread
        healthCheckThread = CreateThread(nullptr, 0, 
                                         HealthCheckThreadProc, this, 0, nullptr);
        
        printf("Load balancer initialized:\n");
        printf("  Algorithm: %s\n", GetAlgorithmName(config.algorithm));
        printf("  Health check interval: %d ms\n", config.healthCheckIntervalMs);
        
        return true;
    }
    
    // Add backend server
    bool AddBackend(const char* address, int port, int weight = 1) {
        std::lock_guard<std::mutex> lock(backendMutex);
        
        BackendServer* server = new BackendServer();
        strncpy_s(server->address, address, sizeof(server->address) - 1);
        server->port = port;
        server->weight = weight;
        server->healthy = true;
        server->activeConnections = 0;
        server->totalRequests = 0;
        server->failedRequests = 0;
        server->avgResponseTime = 0.0;
        server->lastHealthCheck = 0;
        
        backends.push_back(server);
        
        printf("Added backend: %s:%d (weight=%d)\n", address, port, weight);
        return true;
    }
    
    // Remove backend server
    bool RemoveBackend(const char* address, int port) {
        std::lock_guard<std::mutex> lock(backendMutex);
        
        for (auto it = backends.begin(); it != backends.end(); ++it) {
            if (strcmp((*it)->address, address) == 0 && (*it)->port == port) {
                delete *it;
                backends.erase(it);
                printf("Removed backend: %s:%d\n", address, port);
                return true;
            }
        }
        
        return false;
    }
    
    // Select backend for request
    BackendServer* SelectBackend(const char* clientIP = nullptr) {
        std::lock_guard<std::mutex> lock(backendMutex);
        
        if (backends.empty()) return nullptr;
        
        // Filter healthy backends
        std::vector<BackendServer*> healthyBackends;
        for (auto* backend : backends) {
            if (backend->healthy.load()) {
                healthyBackends.push_back(backend);
            }
        }
        
        if (healthyBackends.empty()) return nullptr;
        
        BackendServer* selected = nullptr;
        
        switch (config.algorithm) {
            case LB_ROUND_ROBIN:
                selected = RoundRobin(healthyBackends);
                break;
                
            case LB_WEIGHTED_ROUND_ROBIN:
                selected = WeightedRoundRobin(healthyBackends);
                break;
                
            case LB_LEAST_CONNECTIONS:
                selected = LeastConnections(healthyBackends);
                break;
                
            case LB_IP_HASH:
                selected = IPHash(healthyBackends, clientIP);
                break;
                
            case LB_HEALTH_BASED:
                selected = HealthBased(healthyBackends);
                break;
                
            case LB_LATENCY_BASED:
                selected = LatencyBased(healthyBackends);
                break;
        }
        
        if (selected) {
            selected->activeConnections++;
            selected->totalRequests++;
        }
        
        return selected;
    }
    
    // Release backend after request completes
    void ReleaseBackend(BackendServer* backend) {
        if (backend) {
            backend->activeConnections--;
        }
    }
    
    // Mark request as failed
    void MarkFailed(BackendServer* backend) {
        if (backend) {
            backend->failedRequests++;
            
            // If failure rate too high, mark unhealthy
            double failureRate = (double)backend->failedRequests / backend->totalRequests;
            if (failureRate > 0.5 && backend->totalRequests > 10) {
                backend->healthy = false;
            }
        }
    }
    
    // Update response time
    void UpdateResponseTime(BackendServer* backend, double responseTimeMs) {
        if (backend) {
            // Exponential moving average
            double alpha = 0.3;
            backend->avgResponseTime = alpha * responseTimeMs + 
                                        (1 - alpha) * backend->avgResponseTime;
        }
    }
    
    // Get backend statistics
    void GetBackendStats(int index, uint64_t& totalReq, uint64_t& failedReq, 
                         double& avgTime, int& activeConn) {
        std::lock_guard<std::mutex> lock(backendMutex);
        
        if (index >= 0 && index < (int)backends.size()) {
            BackendServer* backend = backends[index];
            totalReq = backend->totalRequests.load();
            failedReq = backend->failedRequests.load();
            avgTime = backend->avgResponseTime.load();
            activeConn = backend->activeConnections.load();
        }
    }
    
    // Get number of backends
    size_t GetBackendCount() {
        std::lock_guard<std::mutex> lock(backendMutex);
        return backends.size();
    }
    
    // Get number of healthy backends
    size_t GetHealthyBackendCount() {
        std::lock_guard<std::mutex> lock(backendMutex);
        size_t count = 0;
        for (auto* backend : backends) {
            if (backend->healthy.load()) count++;
        }
        return count;
    }
    
    void Shutdown() {
        running = false;
        
        if (healthCheckThread) {
            WaitForSingleObject(healthCheckThread, 5000);
            CloseHandle(healthCheckThread);
        }
        
        std::lock_guard<std::mutex> lock(backendMutex);
        for (auto* backend : backends) {
            delete backend;
        }
        backends.clear();
    }
    
private:
    // Round-robin selection
    BackendServer* RoundRobin(std::vector<BackendServer*>& healthyBackends) {
        int index = currentIndex++ % healthyBackends.size();
        return healthyBackends[index];
    }
    
    // Weighted round-robin selection
    BackendServer* WeightedRoundRobin(std::vector<BackendServer*>& healthyBackends) {
        // Simple weighted selection based on total weight
        int totalWeight = 0;
        for (auto* backend : healthyBackends) {
            totalWeight += backend->weight;
        }
        
        if (totalWeight == 0) return healthyBackends[0];
        
        int randomWeight = rand() % totalWeight;
        int currentWeight = 0;
        
        for (auto* backend : healthyBackends) {
            currentWeight += backend->weight;
            if (randomWeight < currentWeight) {
                return backend;
            }
        }
        
        return healthyBackends.back();
    }
    
    // Least connections selection
    BackendServer* LeastConnections(std::vector<BackendServer*>& healthyBackends) {
        BackendServer* selected = healthyBackends[0];
        int minConnections = selected->activeConnections.load();
        
        for (size_t i = 1; i < healthyBackends.size(); i++) {
            int connections = healthyBackends[i]->activeConnections.load();
            if (connections < minConnections) {
                minConnections = connections;
                selected = healthyBackends[i];
            }
        }
        
        return selected;
    }
    
    // IP hash selection (for sticky sessions)
    BackendServer* IPHash(std::vector<BackendServer*>& healthyBackends, const char* clientIP) {
        if (!clientIP) return RoundRobin(healthyBackends);
        
        // Simple hash of IP address
        unsigned int hash = 0;
        for (const char* p = clientIP; *p; p++) {
            hash = hash * 31 + *p;
        }
        
        return healthyBackends[hash % healthyBackends.size()];
    }
    
    // Health-based selection (prefer healthier backends)
    BackendServer* HealthBased(std::vector<BackendServer*>& healthyBackends) {
        // All are healthy, use round-robin
        return RoundRobin(healthyBackends);
    }
    
    // Latency-based selection
    BackendServer* LatencyBased(std::vector<BackendServer*>& healthyBackends) {
        BackendServer* selected = healthyBackends[0];
        double minLatency = selected->avgResponseTime.load();
        
        for (size_t i = 1; i < healthyBackends.size(); i++) {
            double latency = healthyBackends[i]->avgResponseTime.load();
            if (latency < minLatency) {
                minLatency = latency;
                selected = healthyBackends[i];
            }
        }
        
        return selected;
    }
    
    // Health check thread
    static DWORD WINAPI HealthCheckThreadProc(LPVOID param) {
        LoadBalancer* lb = (LoadBalancer*)param;
        lb->HealthCheckLoop();
        return 0;
    }
    
    void HealthCheckLoop() {
        while (running) {
            Sleep(config.healthCheckIntervalMs);
            
            std::lock_guard<std::mutex> lock(backendMutex);
            
            for (auto* backend : backends) {
                // Perform health check
                bool healthy = PerformHealthCheck(backend);
                backend->healthy = healthy;
                backend->lastHealthCheck = GetTickCount64();
            }
        }
    }
    
    bool PerformHealthCheck(BackendServer* backend) {
        // Simplified health check - would actually connect to backend
        // For now, just check if it's been marked unhealthy
        return backend->healthy.load();
    }
    
    const char* GetAlgorithmName(LoadBalancerAlgorithm algo) {
        switch (algo) {
            case LB_ROUND_ROBIN: return "Round Robin";
            case LB_WEIGHTED_ROUND_ROBIN: return "Weighted Round Robin";
            case LB_LEAST_CONNECTIONS: return "Least Connections";
            case LB_IP_HASH: return "IP Hash";
            case LB_HEALTH_BASED: return "Health Based";
            case LB_LATENCY_BASED: return "Latency Based";
            default: return "Unknown";
        }
    }
};

// C API
extern "C" {

void* LoadBalancer_Create() {
    return new LoadBalancer();
}

void LoadBalancer_Destroy(void* lb) {
    delete (LoadBalancer*)lb;
}

bool LoadBalancer_Init(void* lb, int algorithm, int healthCheckIntervalMs) {
    if (!lb) return false;
    
    LoadBalancerConfig config;
    config.algorithm = (LoadBalancerAlgorithm)algorithm;
    config.healthCheckIntervalMs = healthCheckIntervalMs;
    config.healthCheckTimeoutMs = 5000;
    config.maxRetries = 3;
    config.stickySessions = false;
    
    return ((LoadBalancer*)lb)->Initialize(config);
}

bool LoadBalancer_AddBackend(void* lb, const char* address, int port, int weight) {
    if (!lb) return false;
    return ((LoadBalancer*)lb)->AddBackend(address, port, weight);
}

bool LoadBalancer_RemoveBackend(void* lb, const char* address, int port) {
    if (!lb) return false;
    return ((LoadBalancer*)lb)->RemoveBackend(address, port);
}

void* LoadBalancer_Select(void* lb, const char* clientIP) {
    if (!lb) return nullptr;
    return ((LoadBalancer*)lb)->SelectBackend(clientIP);
}

void LoadBalancer_Release(void* lb, void* backend) {
    if (lb && backend) {
        ((LoadBalancer*)lb)->ReleaseBackend((BackendServer*)backend);
    }
}

void LoadBalancer_Shutdown(void* lb) {
    if (lb) {
        ((LoadBalancer*)lb)->Shutdown();
    }
}

} // extern "C"
