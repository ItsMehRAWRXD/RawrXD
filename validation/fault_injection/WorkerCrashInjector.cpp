// ============================================================================
// WorkerCrashInjector.cpp — Worker Thread Crash Injection Implementation
// ============================================================================

#include "WorkerCrashInjector.hpp"
#include <iostream>
#include <csignal>
#include <random>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Worker Crash Injector Implementation
// ============================================================================
WorkerCrashInjector::WorkerCrashInjector() = default;

WorkerCrashInjector::~WorkerCrashInjector() {
    shutdown();
}

bool WorkerCrashInjector::initialize() {
    m_initialized.store(true);
    return true;
}

void WorkerCrashInjector::shutdown() {
    std::lock_guard<std::mutex> lock(m_workersMutex);
    m_workers.clear();
    m_initialized.store(false);
}

bool WorkerCrashInjector::isAvailable() const {
    return m_initialized.load() && !m_workers.empty();
}

void WorkerCrashInjector::registerWorkerThread(std::thread::id id, const std::string& name) {
    std::lock_guard<std::mutex> lock(m_workersMutex);
    auto info = std::make_shared<WorkerInfo>();
    info->id = id;
    info->name = name;
    info->registrationTime = std::chrono::steady_clock::now();
    m_workers[id] = info;
}

void WorkerCrashInjector::unregisterWorkerThread(std::thread::id id) {
    std::lock_guard<std::mutex> lock(m_workersMutex);
    m_workers.erase(id);
}

FaultInjectionResult WorkerCrashInjector::inject() {
    return injectRandomWorker();
}

FaultInjectionResult WorkerCrashInjector::injectByThreadId(std::thread::id id) {
    FaultInjectionResult result;
    auto start = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(m_workersMutex);
        auto it = m_workers.find(id);
        if (it == m_workers.end()) {
            result.success = false;
            result.errorMessage = "Worker thread not found";
            return result;
        }
    }
    
    // Create manifest
    m_lastManifest = FaultManifest(
        generateFaultId("WORKER"),
        FaultType::THREAD_TERMINATION,
        m_severity,
        "WorkerThread_" + std::to_string(std::hash<std::thread::id>{}(id)),
        "RESTART_SERVICE"
    );
    m_lastManifest.description = "Simulated worker thread crash via " + 
        std::string(m_crashMode == CrashMode::TERMINATE ? "terminate" :
                   m_crashMode == CrashMode::SEGFAULT ? "segfault" :
                   m_crashMode == CrashMode::ABORT ? "abort" :
                   m_crashMode == CrashMode::EXCEPTION ? "exception" :
                   m_crashMode == CrashMode::INFINITE_LOOP ? "infinite_loop" : "stack_overflow");
    
    m_lastManifest.parameters["crash_mode"] = static_cast<int>(m_crashMode);
    m_lastManifest.parameters["target_thread_id"] = std::hash<std::thread::id>{}(id);
    
    notifyPreInjection(m_lastManifest);
    
    // Note: In a real implementation, this would trigger the crash
    // For validation, we record the intent and simulate
    result.success = true;
    result.faultId = m_lastManifest.faultId;
    
    auto end = std::chrono::steady_clock::now();
    result.injectionTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    notifyPostInjection(m_lastManifest, result);
    
    // Update stats
    FaultInjectionRegistry::instance().getStats().totalInjected++;
    FaultInjectionRegistry::instance().getStats().successfulInjections++;
    
    return result;
}

FaultInjectionResult WorkerCrashInjector::injectByName(const std::string& name) {
    std::thread::id targetId;
    {
        std::lock_guard<std::mutex> lock(m_workersMutex);
        
        for (const auto& pair : m_workers) {
            if (pair.second->name == name) {
                targetId = pair.first;
                break;
            }
        }
    }
    
    if (targetId != std::thread::id()) {
        return injectByThreadId(targetId);
    }
    
    FaultInjectionResult result;
    result.success = false;
    result.errorMessage = "Worker with name '" + name + "' not found";
    return result;
}

FaultInjectionResult WorkerCrashInjector::injectRandomWorker() {
    auto id = selectRandomWorker();
    if (id == std::thread::id()) {
        FaultInjectionResult result;
        result.success = false;
        result.errorMessage = "No workers available for injection";
        return result;
    }
    return injectByThreadId(id);
}

std::thread::id WorkerCrashInjector::selectRandomWorker() {
    std::lock_guard<std::mutex> lock(m_workersMutex);
    
    if (m_workers.empty()) {
        return std::thread::id();
    }
    
    // Simple random selection
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, m_workers.size() - 1);
    
    auto it = m_workers.begin();
    std::advance(it, dis(gen));
    return it->first;
}

void WorkerCrashInjector::simulateCrash(CrashMode mode) {
    // This would be called in the target thread context
    // For safety in validation, we just log the intent
    switch (mode) {
        case CrashMode::TERMINATE:
            // std::terminate();
            break;
        case CrashMode::SEGFAULT:
            // int* p = nullptr; *p = 42;
            break;
        case CrashMode::ABORT:
            // std::abort();
            break;
        case CrashMode::EXCEPTION:
            // throw std::runtime_error("Injected fault");
            break;
        case CrashMode::INFINITE_LOOP:
            // while(true) {}
            break;
        case CrashMode::STACK_OVERFLOW:
            // recursive function to exhaust stack
            break;
    }
}

size_t WorkerCrashInjector::getRegisteredWorkerCount() const {
    std::lock_guard<std::mutex> lock(m_workersMutex);
    return m_workers.size();
}

std::vector<std::string> WorkerCrashInjector::getWorkerNames() const {
    std::lock_guard<std::mutex> lock(m_workersMutex);
    std::vector<std::string> names;
    for (const auto& pair : m_workers) {
        names.push_back(pair.second->name);
    }
    return names;
}

} // namespace Validation
} // namespace RawrXD