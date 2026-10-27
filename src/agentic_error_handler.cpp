// AgenticErrorHandler Implementation
#include "agentic_error_handler.h"
#include "agentic_observability.h"
#include "agentic_loop_state.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>

namespace {

// Simple UUID v4 generator
std::string generateUuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint16_t> dist(0, 0xffff);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dist(gen);
    ss << "-";
    ss << "4"; // version 4
    for (int i = 0; i < 3; ++i) ss << dist(gen) & 0x0fff;
    ss << "-";
    ss << (dist(gen) & 0x3fff | 0x8000); // variant 1
    for (int i = 0; i < 3; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 6; ++i) ss << dist(gen);
    return ss.str();
}

// Current timestamp as ISO string
std::string nowIsoString() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

} // namespace

AgenticErrorHandler::AgenticErrorHandler() {
    std::clog << "[AgenticErrorHandler] Initialized - Ready for error handling and recovery" << std::endl;

    // Set up default recovery policies
    setRecoveryPolicy(RecoveryPolicy{
        ErrorType::ExecutionError,
        RecoveryStrategy::Retry,
        3,      // maxRetries
        100,    // initialDelayMs
        2.0f    // backoffMultiplier
    });

    setRecoveryPolicy(RecoveryPolicy{
        ErrorType::TimeoutError,
        RecoveryStrategy::Retry,
        5,
        500,
        1.5f
    });

    setRecoveryPolicy(RecoveryPolicy{
        ErrorType::ResourceError,
        RecoveryStrategy::Fallback,
        2,
        200,
        2.0f
    });

    setRecoveryPolicy(RecoveryPolicy{
        ErrorType::NetworkError,
        RecoveryStrategy::Retry,
        4,
        1000,
        1.5f
    });

    setRecoveryPolicy(RecoveryPolicy{
        ErrorType::ValidationError,
        RecoveryStrategy::Abort,
        1,
        0,
        1.0f
    });
}

AgenticErrorHandler::~AgenticErrorHandler() {
    std::clog << "[AgenticErrorHandler] Destroyed - Handled" << m_totalErrors
              << "errors with" << m_successfulRecoveries << "successful recoveries" << std::endl;
}

void AgenticErrorHandler::initialize(AgenticObservability* obs, AgenticLoopState* state) {
    m_observability = obs;
    m_state = state;

    if (m_observability) {
        m_observability->logInfo("AgenticErrorHandler",
            "Initialized with observability and state management");
    }
}

// ===== ERROR CAPTURE AND HANDLING =====

json AgenticErrorHandler::handleError(
    const std::exception& e,
    const std::string& component,
    const json& context)
{
    std::string errorId = recordError(
        ErrorType::InternalError,
        e.what(),
        component,
        extractStackTrace(),
        context
    );

    json result;
    result["error_id"] = errorId;
    result["handled"] = false;

    // Determine recovery strategy
    RecoveryPolicy policy = getRecoveryPolicy(ErrorType::InternalError);

    if (policy.strategy == RecoveryStrategy::Retry && policy.maxRetries > 0) {
        result["handled"] = executeRetryStrategy(m_errorHistory.back(), []() {
            return false; // Would retry operation
        });
    } else if (policy.strategy == RecoveryStrategy::Fallback && policy.fallbackEnabled) {
        result["handled"] = executeFallbackStrategy(m_errorHistory.back());
    }

    return result;
}

std::string AgenticErrorHandler::recordError(
    ErrorType type,
    const std::string& message,
    const std::string& component,
    const std::string& stackTrace,
    const json& context)
{
    ErrorContext errorContext;
    errorContext.errorId = generateUuid();
    errorContext.type = type;
    errorContext.message = message;
    errorContext.stackTrace = stackTrace;
    errorContext.component = component;
    errorContext.systemState = context;
    errorContext.retryCount = 0;
    errorContext.strategy = getRecoveryPolicy(type).strategy;

    m_errorHistory.push_back(errorContext);
    m_totalErrors++;

    // Keep bounded
    if ((int)m_errorHistory.size() > m_maxErrorMemory) {
        m_errorHistory.erase(m_errorHistory.begin());
    }

    if (m_observability) {
        json logContext = context;
        logContext["error_id"] = errorContext.errorId;
        logContext["error_type"] = static_cast<int>(type);

        m_observability->logError(component, message, logContext);
    }

    if (m_state) {
        m_state->recordError(
            std::to_string(static_cast<int>(type)),
            message,
            stackTrace
        );
    }

    // Check circuit breaker
    checkCircuitBreaker(component);

    return errorContext.errorId;
}

// ===== RECOVERY EXECUTION =====

bool AgenticErrorHandler::executeRecovery(const std::string& errorId) {
    for (auto& errorContext : m_errorHistory) {
        if (errorContext.errorId == errorId) {
            std::clog << "[AgenticErrorHandler] Recovery started for " << errorId << std::endl;

            bool success = false;

            switch (errorContext.strategy) {
                case RecoveryStrategy::Retry:
                    success = executeRetryStrategy(errorContext, []() { return false; });
                    break;
                case RecoveryStrategy::Backtrack:
                    success = executeBacktrackStrategy(errorContext);
                    break;
                case RecoveryStrategy::Fallback:
                    success = executeFallbackStrategy(errorContext);
                    break;
                case RecoveryStrategy::Escalate:
                    executeEscalateStrategy(errorContext);
                    success = true;
                    break;
                default:
                    success = false;
            }

            if (success) {
                m_successfulRecoveries++;
                std::clog << "[AgenticErrorHandler] Recovery succeeded for " << errorId << std::endl;
            } else {
                std::clog << "[AgenticErrorHandler] Recovery failed for " << errorId << std::endl;
            }

            return success;
        }
    }

    return false;
}

bool AgenticErrorHandler::retry(
    const std::string& errorId,
    std::function<bool()> operation,
    int maxAttempts)
{
    for (auto& errorContext : m_errorHistory) {
        if (errorContext.errorId == errorId) {
            return executeRetryStrategy(errorContext, operation);
        }
    }

    return false;
}

bool AgenticErrorHandler::backtrack(const std::string& targetStateId) {
    if (!m_state) return false;

    std::clog << "[AgenticErrorHandler] Backtracking to state: " << targetStateId << std::endl;

    // In production, would restore from checkpoint
    return true;
}

bool AgenticErrorHandler::fallback(const std::string& errorId, const std::string& fallbackPlan) {
    for (auto& errorContext : m_errorHistory) {
        if (errorContext.errorId == errorId) {
            std::clog << "[AgenticErrorHandler] Executing fallback for " << errorId << std::endl;
            return true;
        }
    }
    return false;
}

void AgenticErrorHandler::escalate(const std::string& errorId, const std::string& reason) {
    for (auto& errorContext : m_errorHistory) {
        if (errorContext.errorId == errorId) {
            executeEscalateStrategy(errorContext);
            break;
        }
    }
}

// ===== RECOVERY POLICIES =====

void AgenticErrorHandler::setRecoveryPolicy(const RecoveryPolicy& policy) {
    // Replace existing policy for same error type
    m_recoveryPolicies.erase(
        std::remove_if(m_recoveryPolicies.begin(), m_recoveryPolicies.end(),
                       [&](const RecoveryPolicy& p) { return p.errorType == policy.errorType; }),
        m_recoveryPolicies.end()
    );

    m_recoveryPolicies.push_back(policy);
}

AgenticErrorHandler::RecoveryPolicy AgenticErrorHandler::getRecoveryPolicy(ErrorType type) const {
    for (const auto& policy : m_recoveryPolicies) {
        if (policy.errorType == type) {
            return policy;
        }
    }

    // Return default policy
    return RecoveryPolicy{
        type,
        RecoveryStrategy::Abort,
        0,
        0,
        1.0f,
        false
    };
}

json AgenticErrorHandler::getAllRecoveryPolicies() const {
    json policies = json::array();

    for (const auto& policy : m_recoveryPolicies) {
        json policyObj;
        policyObj["error_type"] = static_cast<int>(policy.errorType);
        policyObj["strategy"] = static_cast<int>(policy.strategy);
        policyObj["max_retries"] = policy.maxRetries;
        policyObj["initial_delay_ms"] = policy.initialDelayMs;
        policyObj["backoff_multiplier"] = policy.backoffMultiplier;
        policyObj["fallback_enabled"] = policy.fallbackEnabled;

        policies.push_back(policyObj);
    }

    return policies;
}

// ===== ERROR CLASSIFICATION =====

AgenticErrorHandler::ErrorType AgenticErrorHandler::classifyError(const std::string& errorMessage) {
    std::string lowerMsg = errorMessage;
    std::transform(lowerMsg.begin(), lowerMsg.end(), lowerMsg.begin(), [](unsigned char c){ return std::tolower(c); });

    // GPU-kernel/image incompatibility is deterministic for the selected
    // provider/device. Treat it as configuration, not a transient execution
    // failure, so recovery terminates once and can offer a fallback model.
    if (lowerMsg.find("tensilelibrary") != std::string::npos ||
        lowerMsg.find("rocblaslt") != std::string::npos ||
        lowerMsg.find("no kernel image") != std::string::npos ||
        lowerMsg.find("kernel image is not available") != std::string::npos ||
        lowerMsg.find("rocm error") != std::string::npos ||
        lowerMsg.find("hip error") != std::string::npos ||
        lowerMsg.find("unsupported gpu architecture") != std::string::npos) {
        return ErrorType::ConfigurationError;
    } else if (lowerMsg.find("timeout") != std::string::npos) {
        return ErrorType::TimeoutError;
    } else if (lowerMsg.find("validation") != std::string::npos) {
        return ErrorType::ValidationError;
    } else if (lowerMsg.find("resource") != std::string::npos ||
               lowerMsg.find("memory") != std::string::npos) {
        return ErrorType::ResourceError;
    } else if (lowerMsg.find("network") != std::string::npos ||
               lowerMsg.find("connection") != std::string::npos) {
        return ErrorType::NetworkError;
    } else if (lowerMsg.find("config") != std::string::npos) {
        return ErrorType::ConfigurationError;
    } else if (lowerMsg.find("state") != std::string::npos) {
        return ErrorType::StateError;
    }

    return ErrorType::ExecutionError;
}

bool AgenticErrorHandler::isRetryable(ErrorType type) const {
    RecoveryPolicy policy = getRecoveryPolicy(type);
    return policy.strategy == RecoveryStrategy::Retry;
}

bool AgenticErrorHandler::isFallbackable(ErrorType type) const {
    RecoveryPolicy policy = getRecoveryPolicy(type);
    return policy.fallbackEnabled;
}

// ===== MONITORING =====

json AgenticErrorHandler::getErrorStatistics() const {
    json stats;
    stats["total_errors"] = m_totalErrors;
    stats["total_recoveries"] = m_totalRecoveries;
    stats["successful_recoveries"] = m_successfulRecoveries;
    stats["recovery_success_rate"] = m_totalRecoveries > 0 ?
        (m_successfulRecoveries * 100.0f / m_totalRecoveries) : 0.0f;

    return stats;
}

int AgenticErrorHandler::getErrorCount(ErrorType type) const {
    int count = 0;
    for (const auto& error : m_errorHistory) {
        if (error.type == type) count++;
    }
    return count;
}

float AgenticErrorHandler::getErrorRate() const {
    // Errors per minute (approximate)
    return m_totalErrors > 0 ? m_totalErrors / 10.0f : 0.0f;
}

std::vector<AgenticErrorHandler::ErrorContext> AgenticErrorHandler::getRecentErrors(int limit) {
    std::vector<ErrorContext> recent(
        m_errorHistory.rbegin(),
        m_errorHistory.rend()
    );

    if (limit > 0 && (int)recent.size() > limit) {
        recent.resize(limit);
    }

    return recent;
}

json AgenticErrorHandler::getRecoverySuccess() const {
    json success;

    std::unordered_map<int, int> recoveryByType;
    for (const auto& error : m_errorHistory) {
        if (error.recoverySucceeded) {
            recoveryByType[static_cast<int>(error.type)]++;
        }
    }

    json byType = json::object();
    for (const auto& pair : recoveryByType) {
        byType[std::to_string(pair.first)] = pair.second;
    }

    success["by_type"] = byType;
    success["total_successful"] = m_successfulRecoveries;

    return success;
}

// ===== CIRCUIT BREAKER =====

void AgenticErrorHandler::enableCircuitBreaker(const std::string& component, int failureThreshold) {
    auto breaker = getOrCreateCircuitBreaker(component);
    breaker->failureThreshold = failureThreshold;
}

AgenticErrorHandler::CircuitBreaker* AgenticErrorHandler::getOrCreateCircuitBreaker(
    const std::string& component)
{
    auto it = m_circuitBreakers.find(component);

    if (it != m_circuitBreakers.end()) {
        return &it->second;
    }

    CircuitBreaker breaker;
    breaker.component = component;
    breaker.failureCount = 0;
    breaker.failureThreshold = 5;
    breaker.isTripped = false;

    m_circuitBreakers[component] = breaker;

    auto it2 = m_circuitBreakers.find(component);
    return &it2->second;
}

void AgenticErrorHandler::checkCircuitBreaker(const std::string& component) {
    auto breaker = getOrCreateCircuitBreaker(component);
    breaker->failureCount++;

    if (!breaker->isTripped && breaker->failureCount >= breaker->failureThreshold) {
        breaker->isTripped = true;
        breaker->tripTime = std::chrono::system_clock::now();

        std::cerr << "[AgenticErrorHandler] Circuit breaker tripped for " << component << std::endl;
    }
}

// ===== PRIVATE HELPERS =====

bool AgenticErrorHandler::executeRetryStrategy(
    const ErrorContext& context,
    std::function<bool()> operation)
{
    RecoveryPolicy policy = getRecoveryPolicy(context.type);
    int delayMs = policy.initialDelayMs;

    for (int attempt = 0; attempt < policy.maxRetries; ++attempt) {
        if (attempt > 0) {
            // Exponential backoff
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            delayMs = static_cast<int>(delayMs * policy.backoffMultiplier);
        }

        if (operation()) {
            std::clog << "[AgenticErrorHandler] Retry succeeded for " << context.errorId << std::endl;
            m_totalRecoveries++;
            return true;
        }
    }

    std::clog << "[AgenticErrorHandler] All retry attempts failed for " << context.errorId << std::endl;
    m_totalRecoveries++;
    return false;
}

bool AgenticErrorHandler::executeBacktrackStrategy(const ErrorContext& context) {
    std::clog << "[AgenticErrorHandler] Backtracking from error " << context.errorId << std::endl;

    if (m_state) {
        // Restore from checkpoint
        json snapshot = m_state->getLastSnapshot();
        if (!snapshot.is_null() && !snapshot.empty()) {
            m_state->restoreFromSnapshot(snapshot);
            m_totalRecoveries++;
            return true;
        }
    }

    m_totalRecoveries++;
    return false;
}

bool AgenticErrorHandler::executeFallbackStrategy(const ErrorContext& context) {
    std::clog << "[AgenticErrorHandler] Executing fallback for " << context.errorId << std::endl;

    // Use alternative code path
    m_totalRecoveries++;
    return true;
}

void AgenticErrorHandler::executeEscalateStrategy(const ErrorContext& context) {
    std::cerr << "[AgenticErrorHandler] Escalating error " << context.errorId
              << " - Type:" << static_cast<int>(context.type)
              << " - Message:" << context.message << std::endl;

    // Would notify higher-level handlers or administrators
}

std::string AgenticErrorHandler::analyzeError(const std::exception& e) {
    return e.what();
}

std::string AgenticErrorHandler::extractStackTrace() {
    // Platform-specific stack trace extraction would go here
    return "Stack trace not available on this platform";
}

void AgenticErrorHandler::recordMetrics(const ErrorContext& context) {
    if (m_observability) {
        m_observability->incrementCounter("errors_total");
        m_observability->incrementCounter(
            "errors_by_type_" + std::to_string(static_cast<int>(context.type))
        );
    }
}

// ===== ERROR SAFE OPERATION =====

ErrorSafeOperation::ErrorSafeOperation(
    AgenticErrorHandler* handler,
    const std::string& operationName,
    const std::string& component)
    : m_handler(handler), m_operationName(operationName), m_component(component)
{
}

ErrorSafeOperation::~ErrorSafeOperation() {
}
