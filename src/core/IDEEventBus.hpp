#pragma once
#include "SharedSessionLayout.hpp"
#include "UnifiedSessionState.hpp"
#include <functional>
#include <string_view>

namespace RawrXD {

// Event handler callback type
using EventHandler = std::function<void(const SharedEventFrame&)>;

// Event bus for real-time IDE synchronization
// Built on top of UnifiedSessionState shared memory (Phase 1)
class IDEEventBus {
public:
    IDEEventBus() noexcept;
    ~IDEEventBus();

    // Disable copy/move
    IDEEventBus(const IDEEventBus&) = delete;
    IDEEventBus& operator=(const IDEEventBus&) = delete;
    IDEEventBus(IDEEventBus&&) = delete;
    IDEEventBus& operator=(IDEEventBus&&) = delete;

    // Initialize with existing session state
    bool Initialize(UnifiedSessionState* session) noexcept;
    
    // Shutdown
    void Shutdown() noexcept;

    // --- Event Publishing ---
    
    // Publish event to bus (MPMC safe)
    bool Publish(EventType type, std::string_view payload) noexcept;
    
    // Convenience publishers
    bool PublishFileChanged(std::string_view path) noexcept;
    bool PublishConfigChanged(std::string_view key) noexcept;
    bool PublishModelLoaded(std::string_view hash) noexcept;
    bool PublishModelUnloaded() noexcept;
    bool PublishWorkingDirChanged(std::string_view path) noexcept;
    bool PublishCommandExecuted(std::string_view command) noexcept;
    bool PublishShutdown() noexcept;

    // --- Event Subscription ---
    
    // Subscribe to specific event type
    void Subscribe(EventType type, EventHandler handler) noexcept;
    
    // Subscribe to all events
    void SubscribeAll(EventHandler handler) noexcept;
    
    // Unsubscribe all handlers
    void UnsubscribeAll() noexcept;

    // --- Event Processing ---
    
    // Poll for new events (non-blocking)
    // Returns number of events processed
    size_t Poll() noexcept;
    
    // Wait for events with timeout (blocking)
    // Returns true if events were processed, false on timeout
    bool WaitAndPoll(DWORD timeoutMs) noexcept;
    
    // Get last processed sequence
    uint64_t GetLastSequence() const noexcept { return m_lastSequence; }

    // Check if initialized
    bool IsInitialized() const noexcept { return m_session != nullptr; }

private:
    UnifiedSessionState* m_session;
    uint64_t m_lastSequence;
    
    // Handler storage (simplified - fixed size array)
    static constexpr size_t MAX_HANDLERS = 16;
    struct HandlerEntry {
        EventType type;
        EventHandler handler;
        bool active;
    };
    HandlerEntry m_handlers[MAX_HANDLERS];
    size_t m_handlerCount;
    EventHandler m_catchAllHandler;
    bool m_hasCatchAll;

    void DispatchEvent(const SharedEventFrame& frame) noexcept;
};

// Global event bus accessor (singleton pattern)
IDEEventBus* GetGlobalEventBus() noexcept;
void SetGlobalEventBus(IDEEventBus* bus) noexcept;

} // namespace RawrXD
