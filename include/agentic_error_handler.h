#pragma once

#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <map>
#include <unordered_map>
#include <chrono>

#include "nlohmann/json.hpp"

class AgenticObservability;
class AgenticLoopState;

using json = nlohmann::json;

/**
 * @class AgenticErrorHandler
 * @brief Non-intrusive centralized error handling with recovery strategies
 * 
 * Features:
 * - Centralized exception capture at high level
 * - Resource guards (RAII patterns)
 * - Graceful degradation
 * - Automatic recovery strategies
 * - Error classification and metrics
 * - Retry policies with exponential backoff
 */
class AgenticErrorHandler {
public:
    enum class ErrorType {
        ValidationError,
        ExecutionError,
        ResourceError,
        NetworkError,
        TimeoutError,
        StateError,
        ConfigurationError,
        InternalError,
        Unknown
    };

    enum class RecoveryStrategy {
        Retry,
        Backtrack,
        Fallback,
        Escalate,
        Ignore,
        Abort
    };

    struct ErrorContext {
        std::string errorId;
        ErrorType type;
        std::string message;
        std::string stackTrace;
        std::string component;
        json systemState;
        int retryCount;
        RecoveryStrategy strategy;
        bool recoverySucceeded = false;
    };

    struct RecoveryPolicy {
        ErrorType errorType;
        RecoveryStrategy strategy;
        int maxRetries;
        int initialDelayMs;
        float backoffMultiplier;
        bool fallbackEnabled;
    };

public:
    explicit AgenticErrorHandler();
    ~AgenticErrorHandler();

    // Initialize with observability system
    void initialize(AgenticObservability* obs, AgenticLoopState* state);

    // ===== ERROR CAPTURE AND HANDLING =====
    
    // Main error handler (high-level exception capture)
    json handleError(
        const std::exception& e,
        const std::string& component,
        const json& context = json::object()
    );

    // Explicit error recording
    std::string recordError(
        ErrorType type,
        const std::string& message,
        const std::string& component,
        const std::string& stackTrace = "",
        const json& context = json::object()
    );

    // ===== RECOVERY EXECUTION =====
    
    bool executeRecovery(const std::string& errorId);
    bool retry(
        const std::string& errorId,
        std::function<bool()> operation,
        int maxAttempts = 3
    );
    
    // Backtrack to previous known good state
    bool backtrack(const std::string& targetStateId);
    
    // Fallback to alternative execution path
    bool fallback(const std::string& errorId, const std::string& fallbackPlan);
    
    // Escalate error to higher level
    void escalate(const std::string& errorId, const std::string& reason);

    // ===== RESOURCE GUARDS (RAII) =====
    
    class ResourceGuard {
    public:
        template<typename Fn>
        ResourceGuard(Fn cleanup) : m_cleanup(cleanup) {}
        
        ~ResourceGuard() {
            if (m_cleanup) m_cleanup();
        }
        
        void release() {
            m_cleanup = nullptr;
        }
        
    private:
        std::function<void()> m_cleanup;
    };

    // Create guarded resource
    template<typename ResourceType>
    std::unique_ptr<ResourceGuard> guardResource(
        ResourceType* resource,
        std::function<void(ResourceType*)> cleanup
    ) {
        return std::make_unique<ResourceGuard>([resource, cleanup]() {
            cleanup(resource);
        });
    }

    // ===== RECOVERY POLICIES =====
    void setRecoveryPolicy(const RecoveryPolicy& policy);
    RecoveryPolicy getRecoveryPolicy(ErrorType type) const;
    json getAllRecoveryPolicies() const;

    // ===== ERROR CLASSIFICATION =====
    ErrorType classifyError(const std::string& errorMessage);
    bool isRetryable(ErrorType type) const;
    bool isFallbackable(ErrorType type) const;

    // ===== MONITORING AND METRICS =====
    json getErrorStatistics() const;
    int getErrorCount(ErrorType type) const;
    float getErrorRate() const;
    std::vector<ErrorContext> getRecentErrors(int limit = 10);
    json getRecoverySuccess() const;

    // ===== CONFIGURATION =====
    void setGracefulDegradation(bool enabled) { m_enableGracefulDegradation = enabled; }
    void setMaxErrorMemory(int size) { m_maxErrorMemory = size; }
    void setErrorThreshold(int count) { m_errorThreshold = count; }
    void enableCircuitBreaker(const std::string& component, int failureThreshold);

private:
    // Recovery execution helpers
    bool executeRetryStrategy(
        const ErrorContext& context,
        std::function<bool()> operation
    );
    bool executeBacktrackStrategy(const ErrorContext& context);
    bool executeFallbackStrategy(const ErrorContext& context);
    void executeEscalateStrategy(const ErrorContext& context);

    // Error analysis
    std::string analyzeError(const std::exception& e);
    std::string extractStackTrace();
    void recordMetrics(const ErrorContext& context);

    // Circuit breaker
    struct CircuitBreaker {
        std::string component;
        int failureCount;
        int failureThreshold;
        bool isTripped;
        std::chrono::system_clock::time_point tripTime;
    };
    
    CircuitBreaker* getOrCreateCircuitBreaker(const std::string& component);
    void checkCircuitBreaker(const std::string& component);

    // Storage
    std::vector<ErrorContext> m_errorHistory;
    std::vector<RecoveryPolicy> m_recoveryPolicies;
    std::unordered_map<std::string, CircuitBreaker> m_circuitBreakers;

    // Configuration
    AgenticObservability* m_observability = nullptr;
    AgenticLoopState* m_state = nullptr;
    bool m_enableGracefulDegradation = true;
    int m_maxErrorMemory = 100;
    int m_errorThreshold = 10;
    float m_circuitBreakerTimeout = 60.0f; // seconds

    // Metrics
    int m_totalErrors = 0;
    int m_totalRecoveries = 0;
    int m_successfulRecoveries = 0;
};

// RAII wrapper for operations
class ErrorSafeOperation {
public:
    ErrorSafeOperation(
        AgenticErrorHandler* handler,
        const std::string& operationName,
        const std::string& component
    );
    ~ErrorSafeOperation();

    // Execute operation with automatic error handling
    template<typename Fn>
    bool execute(Fn operation) {
        try {
            operation();
            return true;
        } catch (const std::exception& e) {
            // Handler will manage the error
            return false;
        }
    }

private:
    AgenticErrorHandler* m_handler;
    std::string m_operationName;
    std::string m_component;
};
