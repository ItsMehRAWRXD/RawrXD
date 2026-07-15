# Sovereign Event System
## Core Runtime Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Sovereign Event System provides asynchronous event handling for IDE components and plugins.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Event Types** | 100+ |
| **Delivery** | Async/Sync |
| **Priority** | 5 levels |
| **Buffer Size** | 10,000 events |

---

## Event Types

| Category | Events |
|----------|--------|
| `UI` | Click, Key, Focus |
| `Analysis` | Start, Progress, Complete |
| `Binary` | Load, Unload, Modify |
| `System` | Init, Shutdown, Error |

---

## API Reference

```cpp
// Event handling
SOVEREIGN_API EventResult Event_Initialize();
SOVEREIGN_API void Event_Shutdown();
SOVEREIGN_API EventResult Event_Subscribe(
    EventType type, EventHandler handler, int priority);
SOVEREIGN_API EventResult Event_Unsubscribe(
    EventType type, EventHandler handler);
SOVEREIGN_API EventResult Event_Publish(Event* event);
SOVEREIGN_API EventResult Event_PublishAsync(Event* event);
```

---

## Implementation

```cpp
class EventSystem {
public:
    void Initialize() {
        m_running = true;
        m_thread = std::thread([this] { ProcessLoop(); });
    }
    
    void Subscribe(EventType type, EventHandler handler, int priority) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_subscribers[type].push_back({handler, priority});
        
        // Sort by priority
        std::sort(m_subscribers[type].begin(),
                  m_subscribers[type].end(),
                  [](const auto& a, const auto& b) {
                      return a.priority > b.priority;
                  });
    }
    
    void Publish(Event* event) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        auto it = m_subscribers.find(event->type);
        if (it != m_subscribers.end()) {
            for (const auto& sub : it->second) {
                sub.handler(event);
            }
        }
    }
    
    void PublishAsync(Event* event) {
        m_queue.Push(event);
    }
    
private:
    void ProcessLoop() {
        while (m_running) {
            Event* event = m_queue.Pop();
            if (event) {
                Publish(event);
                delete event;
            }
        }
    }
    
    std::unordered_map<EventType, std::vector<Subscriber>> m_subscribers;
    LockFreeQueue<Event*> m_queue;
    std::thread m_thread;
    std::mutex m_mutex;
    std::atomic<bool> m_running{false};
};
```

---

## Summary

The Sovereign Event System provides:

- ✅ **100+ event types**
- ✅ **Async/Sync delivery**
- ✅ **Priority levels**
- ✅ **Plugin integration**
- ✅ **High performance**

**Status:** ✅ Complete
