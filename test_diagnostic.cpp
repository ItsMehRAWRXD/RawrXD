// Standalone diagnostic test for balancer logging
// Compile: cl /EHsc /std:c++17 /Fe:test_diagnostic.exe test_diagnostic.cpp
// Run: .\test_diagnostic.exe

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

// Simulated BalancerCallResult structure
struct BalancerCallResult {
    bool ok = false;
    int status_code = 0;
    int latency_ms = 0;
    std::string body;
    std::string node_id;
    std::string balancer_latency;
    std::string error;
};

// Simulated CallShadowBalancer function
BalancerCallResult CallShadowBalancer(
    const std::string& path,
    const std::string& request_body,
    const std::string& request_id,
    int timeout_ms,
    const std::string& host,
    int port) {
    
    BalancerCallResult result;
    
    // Simulate a successful balancer call
    result.ok = true;
    result.status_code = 200;
    result.latency_ms = 42;
    result.node_id = "node-42";
    result.body = R"({"choices":[{"message":{"content":"Hello from balancer"}}]})";
    
    return result;
}

// Simulated EnvFlagEnabled
bool EnvFlagEnabled(const char* name, bool default_val) {
    const char* val = std::getenv(name);
    if (!val) return default_val;
    return (std::string(val) == "1" || std::string(val) == "true");
}

// Simulated EnvOrDefault
std::string EnvOrDefault(const char* name, const std::string& default_val) {
    const char* val = std::getenv(name);
    return val ? val : default_val;
}

// Simulated EnvIntOrDefault
int EnvIntOrDefault(const char* name, int default_val) {
    const char* val = std::getenv(name);
    if (!val) return default_val;
    try {
        return std::stoi(val);
    } catch (...) {
        return default_val;
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Balancer Diagnostic Test Harness" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Set test environment variables
    _putenv("RAWRXD_API_LOG_FILE=D:\\rawrxd\\test_balancer.log");
    _putenv("RAWRXD_BALANCER_SHADOW_MODE=1");
    _putenv("RAWRXD_BALANCER_PRIMARY=0");
    _putenv("RAWRXD_BALANCER_HOST=localhost");
    _putenv("RAWRXD_BALANCER_PORT=12639");
    _putenv("RAWRXD_BALANCER_TIMEOUT_MS=500");
    
    std::cout << "\n[SETUP] Environment variables set:" << std::endl;
    std::cout << "  RAWRXD_API_LOG_FILE=D:\\rawrxd\\test_balancer.log" << std::endl;
    std::cout << "  RAWRXD_BALANCER_SHADOW_MODE=1" << std::endl;
    std::cout << "  RAWRXD_BALANCER_HOST=localhost" << std::endl;
    std::cout << "  RAWRXD_BALANCER_PORT=12639" << std::endl;
    
    // Read environment (same as patched api_server.cpp)
    const bool shadow_mode = EnvFlagEnabled("RAWRXD_BALANCER_SHADOW_MODE", false);
    const bool balancer_primary = EnvFlagEnabled("RAWRXD_BALANCER_PRIMARY", false);
    const std::string balancer_host = EnvOrDefault("RAWRXD_BALANCER_HOST", "localhost");
    const int balancer_port = EnvIntOrDefault("RAWRXD_BALANCER_PORT", 12639);
    const int balancer_timeout_ms = EnvIntOrDefault("RAWRXD_BALANCER_TIMEOUT_MS", 500);
    
    std::cout << "\n[CONFIG] Balancer configuration:" << std::endl;
    std::cout << "  shadow_mode=" << shadow_mode << std::endl;
    std::cout << "  balancer_primary=" << balancer_primary << std::endl;
    std::cout << "  host=" << balancer_host << std::endl;
    std::cout << "  port=" << balancer_port << std::endl;
    
    // Generate shadow ID
    static uint64_t s_shadow_id = 0;
    const uint64_t sid = s_shadow_id++;
    const std::string shadow_id = "shadow-test-" + std::to_string(sid);
    
    BalancerCallResult balancer_result;
    
    if (shadow_mode || balancer_primary) {
        // --- BEGIN DIAGNOSTIC LOGGING PATCH ---
        // Pre-call: Log that we're entering the balancer path
        {
            const char* logPath = std::getenv("RAWRXD_API_LOG_FILE");
            std::cout << "\n[BALANCER_DIAGNOSTIC] Mode: " << (balancer_primary ? "primary" : "shadow") << std::endl;
            std::cout << "[BALANCER_DIAGNOSTIC] RAWRXD_API_LOG_FILE env: " << (logPath ? logPath : "NULL") << std::endl;
            std::cout << "[BALANCER_DIAGNOSTIC] Calling balancer at " << balancer_host << ":" << balancer_port << std::endl;
            std::cout.flush();
        }
        // --- END DIAGNOSTIC LOGGING PATCH ---
        
        // Call the balancer
        balancer_result = CallShadowBalancer(
            "/v1/chat/completions",
            R"({"model":"test","messages":[{"role":"user","content":"hello"}]}")",
            shadow_id,
            balancer_timeout_ms,
            balancer_host,
            balancer_port);
        
        // --- BEGIN DIAGNOSTIC LOGGING PATCH ---
        // Post-call: Log the actual results with forced flush
        {
            const char* logPath = std::getenv("RAWRXD_API_LOG_FILE");
            std::cout << "\n[BALANCER_DIAGNOSTIC] Call completed. ok=" << balancer_result.ok 
                      << " status=" << balancer_result.status_code 
                      << " node=" << balancer_result.node_id << std::endl;
            
            if (logPath) {
                std::ofstream logFile(logPath, std::ios::app);
                if (logFile.is_open()) {
                    auto now = std::chrono::system_clock::now();
                    auto time_t = std::chrono::system_clock::to_time_t(now);
                    std::stringstream ss;
                    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
                    
                    logFile << "[" << ss.str() << "] [BALANCER_CALL] id=" << shadow_id
                            << " mode=" << (balancer_primary ? "primary" : "shadow")
                            << " node=" << balancer_result.node_id
                            << " status=" << balancer_result.status_code
                            << " latency_ms=" << balancer_result.latency_ms << std::endl;
                    logFile.flush(); // Force sync to disk
                    std::cout << "[BALANCER_DIAGNOSTIC] Log flushed to file: " << logPath << std::endl;
                } else {
                    std::cout << "[BALANCER_DIAGNOSTIC] ERROR: Could not open file: " << logPath << std::endl;
                }
            } else {
                std::cout << "[BALANCER_DIAGNOSTIC] WARNING: RAWRXD_API_LOG_FILE not set" << std::endl;
            }
            std::cout.flush(); // Ensure console output is seen
        }
        // --- END DIAGNOSTIC LOGGING PATCH ---
        
        if (balancer_result.ok) {
            std::cout << "\n[SUCCESS] Balancer call succeeded!" << std::endl;
            std::cout << "  Response: " << balancer_result.body << std::endl;
        } else {
            std::cout << "\n[FAILED] Balancer call failed: " << balancer_result.error << std::endl;
        }
    } else {
        std::cout << "\n[SKIP] Balancer not enabled (shadow_mode=false, balancer_primary=false)" << std::endl;
    }
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test complete. Check log file at:" << std::endl;
    std::cout << "  D:\\rawrxd\\test_balancer.log" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
