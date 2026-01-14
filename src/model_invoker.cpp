#include "model_invoker.h"
#include "logging/structured_logger.h"
#include "error_handler.h"
#include "agent_cancellation.h"
#include <QThread>
#include <QEventLoop>
#include <QTimer>
#include <stdexcept>

namespace RawrXD {

CircuitBreaker::CircuitBreaker(int failureThreshold, int timeoutSeconds, int halfOpenTimeout)
    : failureThreshold_(failureThreshold), timeoutSeconds_(timeoutSeconds)
    , halfOpenTimeout_(halfOpenTimeout), state_(InvokerState::CLOSED) {
    stateChangeTime_ = QDateTime::currentDateTime();
}

bool CircuitBreaker::allowRequest() {
    QMutexLocker lock(&mutex_);
    
    switch (state_) {
        case InvokerState::CLOSED:
            return true;
            
        case InvokerState::OPEN:
            // Check if timeout has passed
            if (stateChangeTime_.secsTo(QDateTime::currentDateTime()) >= timeoutSeconds_) {
                transitionToHalfOpen();
                return true; // Allow one request to test
            }
            return false;
            
        case InvokerState::HALF_OPEN:
            // Check if half-open timeout has passed
            if (stateChangeTime_.secsTo(QDateTime::currentDateTime()) >= halfOpenTimeout_) {
                transitionToClosed();
                return true;
            }
            return false;
    }
    
    return false;
}

void CircuitBreaker::recordSuccess() {
    QMutexLocker lock(&mutex_);
    
    stats_.recordSuccess();
    
    if (state_ == InvokerState::HALF_OPEN) {
        transitionToClosed();
    }
}

void CircuitBreaker::recordFailure() {
    QMutexLocker lock(&mutex_);
    
    stats_.recordFailure();
    
    if (state_ == InvokerState::CLOSED && stats_.consecutiveFailures >= failureThreshold_) {
        transitionToOpen();
    } else if (state_ == InvokerState::HALF_OPEN) {
        transitionToOpen();
    }
}

void CircuitBreaker::transitionToOpen() {
    state_ = InvokerState::OPEN;
    stateChangeTime_ = QDateTime::currentDateTime();
    
    LOG_WARN("Circuit breaker opened", {{"consecutive_failures", stats_.consecutiveFailures}});
}

void CircuitBreaker::transitionToHalfOpen() {
    state_ = InvokerState::HALF_OPEN;
    stateChangeTime_ = QDateTime::currentDateTime();
    
    LOG_INFO("Circuit breaker half-open");
}

void CircuitBreaker::transitionToClosed() {
    state_ = InvokerState::CLOSED;
    stateChangeTime_ = QDateTime::currentDateTime();
    stats_.consecutiveFailures = 0;
    
    LOG_INFO("Circuit breaker closed");
}

RetryPolicy::RetryPolicy(int maxAttempts, int initialDelayMs, double backoffMultiplier)
    : maxAttempts_(maxAttempts), initialDelayMs_(initialDelayMs)
    , backoffMultiplier_(backoffMultiplier) {}

bool RetryPolicy::shouldRetry(int attempt, const std::exception& error) const {
    if (attempt >= maxAttempts_) {
        return false;
    }
    
    // Don't retry on certain error types
    const char* errorType = typeid(error).name();
    if (std::string(errorType).find("timeout") != std::string::npos) {
        return true; // Retry timeouts
    }
    
    if (std::string(errorType).find("network") != std::string::npos) {
        return true; // Retry network errors
    }
    
    // Don't retry on client errors (4xx)
    if (std::string(errorType).find("client_error") != std::string::npos) {
        return false;
    }
    
    return true;
}

int RetryPolicy::getDelayMs(int attempt) const {
    if (attempt == 0) return 0;
    
    double delay = initialDelayMs_ * std::pow(backoffMultiplier_, attempt - 1);
    return static_cast<int>(delay);
}

ModelInvoker& ModelInvoker::instance() {
    static ModelInvoker instance;
    return instance;
}

void ModelInvoker::initialize(const QString& modelName, const QJsonObject& config) {
    QMutexLocker lock(&mutex_);
    
    if (initialized_) {
        return;
    }
    
    modelName_ = modelName;
    
    // Configure circuit breaker
    int failureThreshold = config["circuit_breaker"].toObject()["failure_threshold"].toInt(5);
    int timeoutSeconds = config["circuit_breaker"].toObject()["timeout_seconds"].toInt(60);
    int halfOpenTimeout = config["circuit_breaker"].toObject()["half_open_timeout"].toInt(30);
    
    circuitBreaker_.reset(new CircuitBreaker(failureThreshold, timeoutSeconds, halfOpenTimeout));
    
    // Configure retry policy
    int maxAttempts = config["retry"].toObject()["max_attempts"].toInt(3);
    int initialDelayMs = config["retry"].toObject()["initial_delay_ms"].toInt(1000);
    double backoffMultiplier = config["retry"].toObject()["backoff_multiplier"].toDouble(2.0);
    
    retryPolicy_.reset(new RetryPolicy(maxAttempts, initialDelayMs, backoffMultiplier));
    
    // Configure fallback
    fallbackModel_ = config["fallback"].toObject()["model"].toString();
    
    initialized_ = true;
    
    LOG_INFO("Model invoker initialized", {
        {"model_name", modelName_},
        {"failure_threshold", failureThreshold},
        {"max_attempts", maxAttempts},
        {"fallback_model", fallbackModel_}
    });
}

void ModelInvoker::shutdown() {
    QMutexLocker lock(&mutex_);
    
    if (initialized_) {
        circuitBreaker_.reset();
        retryPolicy_.reset();
        fallbackHandler_ = nullptr;
        initialized_ = false;
        
        LOG_INFO("Model invoker shut down");
    }
}

QJsonObject ModelInvoker::invoke(const QJsonObject& request, int timeoutMs) {
    AGENT_REGISTER("ModelInvoker", "Model invocation with retry and circuit breaker");
    
    if (!initialized_) {
        ERROR_HANDLE("Model invoker not initialized", ErrorContext()
            .setSeverity(ErrorSeverity::HIGH)
            .setCategory(ErrorCategory::CONFIGURATION)
            .setOperation("ModelInvoker invoke"));
        return QJsonObject();
    }
    
    // Check circuit breaker
    if (!circuitBreaker_->allowRequest()) {
        LOG_WARN("Request blocked by circuit breaker", {{"model", modelName_}});
        
        // Try fallback if available
        if (!fallbackModel_.isEmpty() || fallbackHandler_) {
            LOG_INFO("Attempting fallback model", {{"fallback_model", fallbackModel_}});
            return invokeFallback(request);
        }
        
        throw std::runtime_error("Service unavailable (circuit breaker open)");
    }
    
    int attempt = 0;
    QJsonObject response;
    
    while (attempt < retryPolicy_->getMaxAttempts()) {
        AGENT_CHECK_CANCELLATION();
        
        attempt++;
        
        try {
            START_SPAN("model_invocation");
            
            response = doInvoke(request, timeoutMs);
            
            circuitBreaker_->recordSuccess();
            END_SPAN("model_invocation", {{"attempt", attempt}, {"success", true}});
            
            LOG_INFO("Model invocation successful", {
                {"model", modelName_},
                {"attempt", attempt},
                {"timeout_ms", timeoutMs}
            });
            
            return response;
            
        } catch (const std::exception& e) {
            END_SPAN("model_invocation", {{"attempt", attempt}, {"success", false}, {"error", e.what()}});
            
            circuitBreaker_->recordFailure();
            
            LOG_ERROR("Model invocation failed", {
                {"model", modelName_},
                {"attempt", attempt},
                {"error", e.what()}
            });
            
            // Check if we should retry
            if (!retryPolicy_->shouldRetry(attempt, e)) {
                break;
            }
            
            // Wait before retry
            int delayMs = retryPolicy_->getDelayMs(attempt);
            if (delayMs > 0) {
                LOG_DEBUG("Waiting before retry", {{"delay_ms", delayMs}});
                QThread::msleep(delayMs);
            }
        }
    }
    
    // All retries failed, try fallback
    if (!fallbackModel_.isEmpty() || fallbackHandler_) {
        LOG_INFO("All retries failed, attempting fallback", {{"fallback_model", fallbackModel_}});
        return invokeFallback(request);
    }
    
    // No fallback available
    ERROR_HANDLE("Model invocation failed after all retries", ErrorContext()
        .setSeverity(ErrorSeverity::HIGH)
        .setCategory(ErrorCategory::MODEL)
        .setOperation("ModelInvoker invoke")
        .addMetadata("model", modelName_)
        .addMetadata("attempts", attempt));
    
    throw std::runtime_error("Model invocation failed after " + std::to_string(attempt) + " attempts");
}

void ModelInvoker::invokeAsync(const QJsonObject& request,
                              std::function<void(const QJsonObject&)> successCallback,
                              std::function<void(const std::exception&)> errorCallback,
                              int timeoutMs) {
    QThread* thread = QThread::create([=]() {
        try {
            QJsonObject response = invoke(request, timeoutMs);
            successCallback(response);
        } catch (const std::exception& e) {
            errorCallback(e);
        }
    });
    
    thread->start();
    
    // Clean up thread when done
    QObject::connect(thread, &QThread::finished, thread, &QThread::deleteLater);
}

void ModelInvoker::setFallbackModel(const QString& fallbackModel) {
    QMutexLocker lock(&mutex_);
    fallbackModel_ = fallbackModel;
}

void ModelInvoker::setFallbackHandler(std::function<QJsonObject(const QJsonObject&)> handler) {
    QMutexLocker lock(&mutex_);
    fallbackHandler_ = handler;
}

InvokerStats ModelInvoker::getStatistics() const {
    QMutexLocker lock(&mutex_);
    
    if (!circuitBreaker_) {
        return InvokerStats();
    }
    
    return circuitBreaker_->getStats();
}

bool ModelInvoker::isHealthy() const {
    QMutexLocker lock(&mutex_);
    
    if (!circuitBreaker_) {
        return false;
    }
    
    InvokerStats stats = circuitBreaker_->getStats();
    return stats.getSuccessRate() > 0.8; // 80% success rate considered healthy
}

void ModelInvoker::resetStatistics() {
    QMutexLocker lock(&mutex_);
    
    if (circuitBreaker_) {
        circuitBreaker_.reset(new CircuitBreaker());
    }
}

void ModelInvoker::updateConfig(const QJsonObject& config) {
    QMutexLocker lock(&mutex_);
    
    // Reinitialize with new config
    shutdown();
    initialize(modelName_, config);
}

QJsonObject ModelInvoker::doInvoke(const QJsonObject& request, int timeoutMs) {
    // This is where the actual model invocation would happen
    // For now, simulate a successful response
    
    Q_UNUSED(timeoutMs);
    
    // Simulate processing time
    QThread::msleep(100 + (qrand() % 400)); // 100-500ms delay
    
    // Simulate occasional failures (10% failure rate)
    if (qrand() % 10 == 0) {
        throw std::runtime_error("Simulated model invocation failure");
    }
    
    QJsonObject response = request;
    response["status"] = "success";
    response["timestamp"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    response["model"] = modelName_;
    
    return response;
}

QJsonObject ModelInvoker::invokeFallback(const QJsonObject& request) {
    if (fallbackHandler_) {
        return fallbackHandler_(request);
    }
    
    if (!fallbackModel_.isEmpty()) {
        // Create a new invoker for the fallback model
        ModelInvoker fallbackInvoker;
        fallbackInvoker.initialize(fallbackModel_);
        return fallbackInvoker.invoke(request);
    }
    
    throw std::runtime_error("No fallback available");
}

ModelInvoker::~ModelInvoker() {
    shutdown();
}

} // namespace RawrXD
