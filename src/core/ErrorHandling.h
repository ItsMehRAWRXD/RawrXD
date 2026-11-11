/**
 * @file ErrorHandling.h
 * @brief Production-grade error handling framework
 * 
 * Provides structured error handling, circuit breakers, and retry policies
 * for the unified architecture.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <variant>
#include <unordered_map>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <random>

namespace RawrXD {
namespace Core {

// ============================================================================
// Error Codes
// ============================================================================

enum class ErrorCode {
    Success = 0,
    InvalidArgument,
    NotInitialized,
    AlreadyInitialized,
    ResourceExhausted,
    Timeout,
    Cancelled,
    InternalError,
    NetworkError,
    SecurityViolation,
    NotImplemented,
    Unknown
};

// ============================================================================
// Error Structure
// ============================================================================

struct Error {
    ErrorCode code = ErrorCode::Unknown;
    std::string message;
    std::string file;
    int line = 0;
    std::chrono::steady_clock::time_point timestamp;
    std::optional<std::string> stackTrace;
    std::unordered_map<std::string, std::string> context;
    
    Error() = default;
    Error(ErrorCode c, const std::string& msg) 
        : code(c), message(msg), timestamp(std::chrono::steady_clock::now()) {}
    
    bool IsSuccess() const { return code == ErrorCode::Success; }
    bool IsFailure() const { return code != ErrorCode::Success; }
    
    std::string ToString() const;
};

// ============================================================================
// Result Type
// ============================================================================

template<typename T>
class Result {
public:
    Result() = default;
    Result(const T& value) : m_value(value) {}
    Result(T&& value) : m_value(std::move(value)) {}
    Result(const Error& error) : m_value(error) {}
    Result(Error&& error) : m_value(std::move(error)) {}
    
    bool HasValue() const { return std::holds_alternative<T>(m_value); }
    bool HasError() const { return std::holds_alternative<Error>(m_value); }
    
    T& Value() { return std::get<T>(m_value); }
    const T& Value() const { return std::get<T>(m_value); }
    
    Error& GetError() { return std::get<struct Error>(m_value); }
    const Error& GetError() const { return std::get<struct Error>(m_value); }
    
    T ValueOr(const T& defaultValue) const {
        return HasValue() ? Value() : defaultValue;
    }
    
    template<typename Func>
    auto Map(Func&& func) -> Result<decltype(func(std::declval<T>()))> {
        if (HasError()) return GetError();
        return func(Value());
    }
    
    template<typename Func>
    auto FlatMap(Func&& func) -> decltype(func(std::declval<T>())) {
        if (HasError()) return GetError();
        return func(Value());
    }
    
private:
    std::variant<T, struct Error> m_value;
};

// ============================================================================
// Circuit Breaker
// ============================================================================

class CircuitBreaker {
public:
    enum class State { Closed, Open, HalfOpen };
    
    struct Config {
        int failureThreshold;
        std::chrono::milliseconds timeout;
        int halfOpenMaxCalls;
        
        Config() 
            : failureThreshold(5)
            , timeout(std::chrono::milliseconds(30000))
            , halfOpenMaxCalls(3) {}
    };
    
    explicit CircuitBreaker(const Config& config = Config());
    
    State GetState() const;
    bool CanExecute();
    
    void RecordSuccess();
    void RecordFailure();
    
    void Reset();
    
    std::string GetStateString() const;
    
private:
    Config m_config;
    std::atomic<State> m_state{State::Closed};
    std::atomic<int> m_failureCount{0};
    std::atomic<int> m_successCount{0};
    std::atomic<int> m_halfOpenCalls{0};
    std::chrono::steady_clock::time_point m_lastFailureTime;
    mutable std::mutex m_mutex;
    
    void TransitionTo(State newState);
    bool ShouldAttemptReset() const;
};

// ============================================================================
// Retry Policy
// ============================================================================

class RetryPolicy {
public:
    enum class BackoffStrategy {
        Fixed,
        Linear,
        Exponential,
        ExponentialWithJitter
    };
    
    struct Config {
        int maxRetries;
        std::chrono::milliseconds initialDelay;
        std::chrono::milliseconds maxDelay;
        float backoffMultiplier;
        BackoffStrategy strategy;
        std::vector<ErrorCode> retryableErrors;
        
        Config()
            : maxRetries(3)
            , initialDelay(std::chrono::milliseconds(100))
            , maxDelay(std::chrono::milliseconds(30000))
            , backoffMultiplier(2.0f)
            , strategy(BackoffStrategy::ExponentialWithJitter)
            , retryableErrors({
                ErrorCode::Timeout,
                ErrorCode::NetworkError,
                ErrorCode::ResourceExhausted
            }) {}
    };
    
    explicit RetryPolicy(const Config& config = Config());
    
    bool ShouldRetry(int attempt, const Error& error) const;
    std::chrono::milliseconds GetDelay(int attempt) const;
    
    template<typename Func>
    auto Execute(Func&& func) -> Result<decltype(func())> {
        for (int attempt = 0; attempt <= m_config.maxRetries; ++attempt) {
            auto result = func();
            if (result.HasValue()) return result;
            
            if (attempt < m_config.maxRetries && ShouldRetry(attempt, result.GetError())) {
                std::this_thread::sleep_for(GetDelay(attempt));
            } else {
                return result;
            }
        }
        return Error(ErrorCode::InternalError, "Max retries exceeded");
    }
    
private:
    Config m_config;
    
    std::chrono::milliseconds CalculateDelay(int attempt) const;
    std::chrono::milliseconds AddJitter(std::chrono::milliseconds delay) const;
};

// ============================================================================
// Exception Safety Helpers
// ============================================================================

template<typename Func>
auto TryCatch(Func&& func, const std::string& context = "") -> Result<decltype(func())> {
    try {
        return func();
    } catch (const std::exception& e) {
        Error error;
        error.code = ErrorCode::InternalError;
        error.message = context.empty() ? e.what() : context + ": " + e.what();
        error.timestamp = std::chrono::steady_clock::now();
        return error;
    } catch (...) {
        Error error;
        error.code = ErrorCode::Unknown;
        error.message = context.empty() ? "Unknown exception" : context + ": Unknown exception";
        error.timestamp = std::chrono::steady_clock::now();
        return error;
    }
}

// ============================================================================
// Convenience Macros
// ============================================================================

#define RETURN_IF_ERROR(result) \
    do { \
        if ((result).HasError()) return (result).Error(); \
    } while(0)

#define TRY_ASSIGN(var, expr) \
    auto _result_##var = (expr); \
    if (_result_##var.HasError()) return _result_##var.Error(); \
    auto var = std::move(_result_##var.Value())

#define MAKE_ERROR(code, msg) \
    Error(code, msg)

#define MAKE_ERROR_WITH_CONTEXT(code, msg, ctx) \
    [&]() { \
        Error e(code, msg); \
        e.context = ctx; \
        return e; \
    }()

} // namespace Core
} // namespace RawrXD
