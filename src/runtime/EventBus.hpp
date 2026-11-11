// ============================================================================
// EventBus.hpp — Native Event Bus
// ============================================================================

#ifndef EVENT_BUS_HPP
#define EVENT_BUS_HPP

#include <cstdint>
#include <cstddef>
#include <functional>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string_view>

namespace rawr {

using EventID = uint32_t;
using EventCallback = std::function<void(const void* payload, size_t size)>;

// ============================================================================
// Predefined System Events
// ============================================================================
enum class SystemEvent : EventID {
    EngineStarted = 1,
    EngineStopped,
    ModelLoaded,
    ModelUnloaded,
    TokenGenerated,
    PanelActivated,
    PanelDeactivated,
    StateChanged,
    ErrorOccurred,
    ShutdownInitiated
};

// ============================================================================
// EventBus — Thread-safe publish/subscribe
// ============================================================================
class EventBus {
public:
    static EventBus& Get();

    EventID Register(const char* name);
    void Subscribe(EventID eventId, EventCallback callback);
    void Unsubscribe(EventID eventId, EventCallback callback);
    void Publish(EventID eventId, const void* payload = nullptr, size_t size = 0);

    uint32_t GetEventCount() const { return static_cast<uint32_t>(m_events.size()); }
    uint32_t GetSubscriberCount(EventID eventId) const;

private:
    EventBus() = default;
    ~EventBus() = default;
    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    mutable std::mutex m_mutex;
    std::unordered_map<EventID, std::vector<EventCallback>> m_events;
    std::unordered_map<std::string_view, EventID> m_eventNames;
    EventID m_nextId = 1;
};

} // namespace rawr

#endif // EVENT_BUS_HPP
