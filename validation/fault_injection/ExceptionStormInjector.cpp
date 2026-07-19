// ============================================================================
// ExceptionStormInjector.cpp — Exception Storm Implementation
// ============================================================================

#include "ExceptionStormInjector.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <random>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Exception Storm Injector Implementation
// ============================================================================
ExceptionStormInjector::ExceptionStormInjector() = default;

ExceptionStormInjector::~ExceptionStormInjector() {
    shutdown();
}

bool ExceptionStormInjector::initialize() {
    return true;
}

void ExceptionStormInjector::shutdown() {
    m_stopStorm.store(true);
    if (m_stormThread.joinable()) {
        m_stormThread.join();
    }
}

FaultInjectionResult ExceptionStormInjector::inject() {
    switch (m_stormMode) {
        case StormMode::RAPID_FIRE:
        case StormMode::BURST:
            return injectBurst(m_exceptionCount, m_ratePerSecond);
        case StormMode::SUSTAINED:
            return injectSustained(m_durationSeconds, m_ratePerSecond);
        case StormMode::ESCALATING:
            return injectEscalating(m_durationSeconds);
        case StormMode::RANDOM:
            return injectBurst(m_exceptionCount, m_ratePerSecond);
        default:
            return injectBurst(m_exceptionCount, m_ratePerSecond);
    }
}

FaultInjectionResult ExceptionStormInjector::injectBurst(int count, int ratePerSec) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("STORM"),
        FaultType::EXCEPTION_STORM,
        m_severity,
        "ExceptionHandler",
        "AUTOMATIC_RETRY"
    );
    m_lastManifest.description = "Exception storm: " + std::to_string(count) + 
                                   " exceptions at " + std::to_string(ratePerSec) + "/sec";
    m_lastManifest.parameters["exception_count"] = count;
    m_lastManifest.parameters["rate_per_second"] = ratePerSec;
    m_lastManifest.parameters["mode"] = "burst";
    
    notifyPreInjection(m_lastManifest);
    
    m_stopStorm.store(false);
    m_stormActive.store(true);
    m_injectedCount.store(0);
    m_caughtCount.store(0);
    
    auto delay = std::chrono::milliseconds(1000 / ratePerSec);
    
    for (int i = 0; i < count && !m_stopStorm.load(); ++i) {
        injectSingleException();
        std::this_thread::sleep_for(delay);
    }
    
    m_stormActive.store(false);
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    result.telemetry["injected_count"] = m_injectedCount.load();
    result.telemetry["caught_count"] = m_caughtCount.load();
    result.telemetry["uncaught_count"] = m_injectedCount.load() - m_caughtCount.load();
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult ExceptionStormInjector::injectSustained(int durationSec, int ratePerSec) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("STORM"),
        FaultType::EXCEPTION_STORM,
        m_severity,
        "ExceptionHandler",
        "AUTOMATIC_RETRY"
    );
    m_lastManifest.description = "Sustained exception storm: " + std::to_string(durationSec) + 
                                   " seconds at " + std::to_string(ratePerSec) + "/sec";
    m_lastManifest.parameters["duration_seconds"] = durationSec;
    m_lastManifest.parameters["rate_per_second"] = ratePerSec;
    m_lastManifest.parameters["mode"] = "sustained";
    
    notifyPreInjection(m_lastManifest);
    
    m_stopStorm.store(false);
    m_stormActive.store(true);
    m_injectedCount.store(0);
    m_caughtCount.store(0);
    
    auto endTime = start + std::chrono::seconds(durationSec);
    auto delay = std::chrono::milliseconds(1000 / ratePerSec);
    
    while (std::chrono::steady_clock::now() < endTime && !m_stopStorm.load()) {
        injectSingleException();
        std::this_thread::sleep_for(delay);
    }
    
    m_stormActive.store(false);
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    result.telemetry["injected_count"] = m_injectedCount.load();
    result.telemetry["caught_count"] = m_caughtCount.load();
    result.telemetry["duration_seconds"] = durationSec;
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult ExceptionStormInjector::injectEscalating(int durationSec) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("STORM"),
        FaultType::EXCEPTION_STORM,
        m_severity,
        "ExceptionHandler",
        "AUTOMATIC_RETRY"
    );
    m_lastManifest.description = "Escalating exception storm: " + std::to_string(durationSec) + 
                                   " seconds with increasing frequency";
    m_lastManifest.parameters["duration_seconds"] = durationSec;
    m_lastManifest.parameters["mode"] = "escalating";
    
    notifyPreInjection(m_lastManifest);
    
    m_stopStorm.store(false);
    m_stormActive.store(true);
    m_injectedCount.store(0);
    m_caughtCount.store(0);
    
    auto endTime = start + std::chrono::seconds(durationSec);
    int currentRate = 1; // Start at 1 exception per second
    
    while (std::chrono::steady_clock::now() < endTime && !m_stopStorm.load()) {
        auto delay = std::chrono::milliseconds(1000 / currentRate);
        injectSingleException();
        std::this_thread::sleep_for(delay);
        
        // Double the rate every 5 seconds
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed > 0 && elapsed % 5 == 0) {
            currentRate = std::min(currentRate * 2, 1000); // Cap at 1000/sec
        }
    }
    
    m_stormActive.store(false);
    
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    result.telemetry["injected_count"] = m_injectedCount.load();
    result.telemetry["caught_count"] = m_caughtCount.load();
    result.telemetry["final_rate"] = currentRate;
    
    notifyPostInjection(m_lastManifest, result);
    
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

void ExceptionStormInjector::injectSingleException() {
    m_injectedCount++;
    
    try {
        // Throw different types of exceptions
        static thread_local std::random_device rd;
        static thread_local std::mt19937 gen(rd());
        std::uniform_int_distribution<int> typeDis(0, 4);
        
        switch (typeDis(gen)) {
            case 0:
                throw std::runtime_error("Injected runtime error");
            case 1:
                throw std::logic_error("Injected logic error");
            case 2:
                throw std::invalid_argument("Injected invalid argument");
            case 3:
                throw std::out_of_range("Injected out of range");
            case 4:
                throw std::bad_alloc();
        }
    } catch (const std::exception& e) {
        m_caughtCount++;
        if (m_exceptionHandler) {
            m_exceptionHandler(e);
        }
    }
}

} // namespace Validation
} // namespace RawrXD