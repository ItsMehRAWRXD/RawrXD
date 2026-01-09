/**
 * @file metrics_stubs.cpp
 * @brief Stub implementations for LLMMetrics and CircuitBreakerMetrics
 * @date 2026-01-08
 */

#include <cstdint>
#include <QString>

namespace RawrXD {

/**
 * @brief LLMMetrics - Stub implementation for LLM request recording
 */
namespace LLMMetrics {
    struct Request {
        QString backend;
        std::uint64_t latencyMs;
        int tokensUsed;
        bool success;
        int retryAttempts;
        bool cacheHit;
    };

    void recordRequest(const Request& request) {
        // Stub: No-op for now
        // In production, this would send to observability backend
        (void)request;  // Suppress unused warning
    }
}

/**
 * @brief CircuitBreakerMetrics - Stub implementation for circuit breaker event recording
 */
namespace CircuitBreakerMetrics {
    struct Event {
        QString backend;
        QString status;  // "open", "half-open", "closed"
        QString reason;
    };

    void recordEvent(const Event& event) {
        // Stub: No-op for now
        // In production, this would send to observability backend
        (void)event;  // Suppress unused warning
    }
}

}  // namespace RawrXD
