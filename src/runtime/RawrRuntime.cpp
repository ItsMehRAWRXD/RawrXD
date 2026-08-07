// ============================================================================
// RawrRuntime.cpp — Native Runtime Core Implementation
// ============================================================================

#include "RawrRuntime.hpp"
#include <cstdio>
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

namespace rawr {

// ============================================================================
// Singleton
// ============================================================================
RawrRuntime& RawrRuntime::Get() {
    static RawrRuntime instance;
    return instance;
}

// ============================================================================
// Lifecycle
// ============================================================================
bool RawrRuntime::Initialize() {
    if (m_initialized) return true;

    m_startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();

    m_initialized = true;
    Log(LogLevel::Info, "RawrRuntime initialized");
    return true;
}

void RawrRuntime::Shutdown() {
    if (!m_initialized) return;

    Log(LogLevel::Info, "RawrRuntime shutting down...");

    // Shutdown services in reverse order
    std::vector<IService*> services;
    for (auto& [name, svc] : m_services) {
        services.push_back(svc);
    }
    std::reverse(services.begin(), services.end());
    for (auto* svc : services) {
        svc->Shutdown();
    }

    m_services.clear();
    m_events.clear();
    m_eventNames.clear();
    m_initialized = false;
}

// ============================================================================
// Service Registry
// ============================================================================
bool RawrRuntime::RegisterService(IService* service) {
    if (!service || !service->GetName()) return false;

    std::lock_guard<std::mutex> lock(m_mutex);
    auto [it, inserted] = m_services.try_emplace(service->GetName(), service);
    if (!inserted) {
        Log(LogLevel::Warn, "Service already registered, overwriting");
        it->second = service;
    }

    Log(LogLevel::Info, "Service registered");
    return true;
}

IService* RawrRuntime::ResolveService(const char* name) {
    if (!name) return nullptr;

    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_services.find(name);
    if (it != m_services.end()) {
        return it->second;
    }
    Log(LogLevel::Warn, "Service not found");
    return nullptr;
}

// ============================================================================
// Event Bus
// ============================================================================
EventID RawrRuntime::RegisterEvent(const char* name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_eventNames.find(name);
    if (it != m_eventNames.end()) {
        return it->second;
    }
    EventID id = m_nextEventId++;
    m_eventNames[name] = id;
    m_events[id] = {};
    return id;
}

void RawrRuntime::Subscribe(EventID eventId, EventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events[eventId].push_back(std::move(callback));
}

void RawrRuntime::Unsubscribe(EventID eventId, EventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_events.find(eventId);
    if (it != m_events.end()) {
        auto& callbacks = it->second;
        callbacks.erase(
            std::remove_if(callbacks.begin(), callbacks.end(),
                [&](const EventCallback& cb) {
                    return cb.target_type() == callback.target_type();
                }),
            callbacks.end()
        );
    }
}

void RawrRuntime::Publish(EventID eventId, const void* payload, size_t size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_events.find(eventId);
    if (it != m_events.end()) {
        for (auto& cb : it->second) {
            cb(payload, size);
        }
    }
}

// ============================================================================
// Logging
// ============================================================================
void RawrRuntime::Log(LogLevel level, const char* message) {
    if (level < m_logLevel) return;

    static const char* levelNames[] = {
        "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
    };
    const char* levelName = levelNames[static_cast<int>(level)];

    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    struct tm local;
#ifdef _WIN32
    localtime_s(&local, &time_t);
#else
    localtime_r(&time_t, &local);
#endif

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &local);

    printf("[%s] [%s] %s\n", timestamp, levelName, message);
    fflush(stdout);
}

// ============================================================================
// Diagnostics
// ============================================================================
RawrRuntime::RuntimeInfo RawrRuntime::GetInfo() const {
    RuntimeInfo info = {};
    info.serviceCount = static_cast<uint32_t>(m_services.size());
    info.eventCount = static_cast<uint32_t>(m_events.size());

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
    info.uptimeMs = now - m_startTime;

#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc = {};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        info.memoryUsage = pmc.WorkingSetSize;
    }
#endif

    return info;
}

} // namespace rawr
