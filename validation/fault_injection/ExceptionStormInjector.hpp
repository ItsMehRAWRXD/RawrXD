// ============================================================================
// ExceptionStormInjector.hpp — Repeated Exception Injection
// ============================================================================
// Simulates exception storms to validate recovery without cascading loops.
// ============================================================================

#pragma once

#include "FaultInjector.hpp"
#include <functional>
#include <vector>
#include <mutex>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Exception Storm Injector
// ============================================================================
class ExceptionStormInjector : public FaultInjector {
public:
    ExceptionStormInjector();
    ~ExceptionStormInjector() override;
    
    // FaultInjector interface
    FaultType getType() const override { return FaultType::EXCEPTION_STORM; }
    std::string getName() const override { return "ExceptionStormInjector"; }
    FaultInjectionResult inject() override;
    bool isAvailable() const override { return true; }
    
    bool initialize() override;
    void shutdown() override;
    
    // Storm modes
    enum class StormMode {
        RAPID_FIRE,         // Exceptions as fast as possible
        BURST,              // Short burst of exceptions
        SUSTAINED,          // Long duration, moderate rate
        ESCALATING,         // Increasing frequency
        RANDOM              // Random intervals
    };
    
    void setStormMode(StormMode mode) { m_stormMode = mode; }
    StormMode getStormMode() const { return m_stormMode; }
    
    // Configuration
    void setExceptionCount(int count) { m_exceptionCount = count; }
    void setRatePerSecond(int rate) { m_ratePerSecond = rate; }
    void setDurationSeconds(int seconds) { m_durationSeconds = seconds; }
    
    // Specific injection methods
    FaultInjectionResult injectBurst(int count, int ratePerSec);
    FaultInjectionResult injectSustained(int durationSec, int ratePerSec);
    FaultInjectionResult injectEscalating(int durationSec);
    
    // Storm status
    bool isStormActive() const { return m_stormActive.load(); }
    int getInjectedCount() const { return m_injectedCount.load(); }
    int getCaughtCount() const { return m_caughtCount.load(); }
    
    // Exception handler registration
    using ExceptionHandler = std::function<void(const std::exception&)>;
    void setExceptionHandler(ExceptionHandler handler) { m_exceptionHandler = std::move(handler); }

private:
    StormMode m_stormMode = StormMode::BURST;
    int m_exceptionCount = 100;
    int m_ratePerSecond = 10;
    int m_durationSeconds = 10;
    
    std::atomic<bool> m_stormActive{false};
    std::atomic<int> m_injectedCount{0};
    std::atomic<int> m_caughtCount{0};
    std::atomic<bool> m_stopStorm{false};
    
    std::thread m_stormThread;
    ExceptionHandler m_exceptionHandler;
    
    void stormLoop();
    void injectSingleException();
    std::chrono::milliseconds calculateDelay() const;
};

} // namespace Validation
} // namespace RawrXD