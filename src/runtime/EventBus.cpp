// ============================================================================
// EventBus.cpp — Native Event Bus Implementation
// ============================================================================

#include "EventBus.hpp"
#include <algorithm>

namespace rawr {

EventBus& EventBus::Get() {
    static EventBus instance;
    return instance;
}

EventID EventBus::Register(const char* name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_eventNames.find(name);
    if (it != m_eventNames.end()) {
        return it->second;
    }
    EventID id = m_nextId++;
    m_eventNames[name] = id;
    m_events[id] = {};
    return id;
}

void EventBus::Subscribe(EventID eventId, EventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events[eventId].push_back(std::move(callback));
}

void EventBus::Unsubscribe(EventID eventId, EventCallback callback) {
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

void EventBus::Publish(EventID eventId, const void* payload, size_t size) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_events.find(eventId);
    if (it != m_events.end()) {
        for (const auto& cb : it->second) {
            cb(payload, size);
        }
    }
}

uint32_t EventBus::GetSubscriberCount(EventID eventId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_events.find(eventId);
    return (it != m_events.end()) ? static_cast<uint32_t>(it->second.size()) : 0;
}

} // namespace rawr
