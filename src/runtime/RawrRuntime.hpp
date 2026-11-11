// ============================================================================
// RawrRuntime.hpp — Native Runtime Core
// Dependency registry, service lookup, global state, event dispatch, logging
// ============================================================================

#ifndef RAWR_RUNTIME_HPP
#define RAWR_RUNTIME_HPP

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <mutex>

namespace rawr {

// ============================================================================
// Service Interface
// ============================================================================
class IService {
public:
    virtual ~IService() = default;
    virtual const char* GetName() const = 0;
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
};

// ============================================================================
// Event System
// ============================================================================
using EventID = uint32_t;
using EventCallback = std::function<void(const void* payload, size_t size)>;

// ============================================================================
// Log Levels
// ============================================================================
enum class LogLevel : uint8_t {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
    Fatal = 4
};

// ============================================================================
// Runtime Core — Singleton
// ============================================================================
class RawrRuntime {
public:
    static RawrRuntime& Get();

    // --- Lifecycle ---
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // --- Service Registry ---
    bool RegisterService(IService* service);
    IService* ResolveService(const char* name);
    template<typename T>
    T* Resolve() {
        return static_cast<T*>(ResolveService(T::GetStaticName()));
    }

    // --- Event Bus ---
    EventID RegisterEvent(const char* name);
    void Subscribe(EventID eventId, EventCallback callback);
    void Unsubscribe(EventID eventId, EventCallback callback);
    void Publish(EventID eventId, const void* payload = nullptr, size_t size = 0);

    // --- Logging ---
    void Log(LogLevel level, const char* message);
    void SetLogLevel(LogLevel level) { m_logLevel = level; }
    LogLevel GetLogLevel() const { return m_logLevel; }

    // --- Diagnostics ---
    struct RuntimeInfo {
        uint32_t serviceCount;
        uint32_t eventCount;
        uint64_t uptimeMs;
        size_t memoryUsage;
    };
    RuntimeInfo GetInfo() const;

private:
    RawrRuntime() = default;
    ~RawrRuntime() = default;
    RawrRuntime(const RawrRuntime&) = delete;
    RawrRuntime& operator=(const RawrRuntime&) = delete;

    bool m_initialized = false;
    uint64_t m_startTime = 0;
    LogLevel m_logLevel = LogLevel::Info;

    std::mutex m_mutex;
    std::unordered_map<std::string_view, IService*> m_services;
    std::unordered_map<EventID, std::vector<EventCallback>> m_events;
    std::unordered_map<std::string_view, EventID> m_eventNames;
    EventID m_nextEventId = 1;
};

// ============================================================================
// Convenience Macros
// ============================================================================
#define RAWR_LOG(level, msg) rawr::RawrRuntime::Get().Log(level, msg)
#define RAWR_INFO(msg)  RAWR_LOG(rawr::LogLevel::Info, msg)
#define RAWR_WARN(msg)  RAWR_LOG(rawr::LogLevel::Warn, msg)
#define RAWR_ERROR(msg) RAWR_LOG(rawr::LogLevel::Error, msg)

} // namespace rawr

#endif // RAWR_RUNTIME_HPP
