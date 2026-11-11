#include "IDEEventBus.hpp"
#include <cstring>
#include <algorithm>

namespace RawrXD {

// Global event bus instance
static IDEEventBus* g_globalEventBus = nullptr;

IDEEventBus* GetGlobalEventBus() noexcept {
    return g_globalEventBus;
}

void SetGlobalEventBus(IDEEventBus* bus) noexcept {
    g_globalEventBus = bus;
}

IDEEventBus::IDEEventBus() noexcept
    : m_session(nullptr)
    , m_lastSequence(0)
    , m_handlerCount(0)
    , m_hasCatchAll(false)
{
    // Clear handler array
    for (auto& entry : m_handlers) {
        entry.active = false;
    }
}

IDEEventBus::~IDEEventBus() {
    Shutdown();
}

bool IDEEventBus::Initialize(UnifiedSessionState* session) noexcept {
    if (!session || !session->IsInitialized()) {
        return false;
    }
    
    m_session = session;
    m_lastSequence = 0;
    
    // Set as global event bus if none exists
    if (!g_globalEventBus) {
        SetGlobalEventBus(this);
    }
    
    return true;
}

void IDEEventBus::Shutdown() noexcept {
    UnsubscribeAll();
    
    if (g_globalEventBus == this) {
        SetGlobalEventBus(nullptr);
    }
    
    m_session = nullptr;
    m_lastSequence = 0;
}

// --- Event Publishing ---

bool IDEEventBus::Publish(EventType type, std::string_view payload) noexcept {
    if (!m_session) return false;
    
    auto result = m_session->WriteEvent(type, payload);
    return result.success;
}

bool IDEEventBus::PublishFileChanged(std::string_view path) noexcept {
    return Publish(EventType::FileChanged, path);
}

bool IDEEventBus::PublishConfigChanged(std::string_view key) noexcept {
    return Publish(EventType::ConfigChanged, key);
}

bool IDEEventBus::PublishModelLoaded(std::string_view hash) noexcept {
    return Publish(EventType::ModelLoaded, hash);
}

bool IDEEventBus::PublishModelUnloaded() noexcept {
    return Publish(EventType::ModelUnloaded, {});
}

bool IDEEventBus::PublishWorkingDirChanged(std::string_view path) noexcept {
    return Publish(EventType::WorkingDirChanged, path);
}

bool IDEEventBus::PublishCommandExecuted(std::string_view command) noexcept {
    return Publish(EventType::CommandExecuted, command);
}

bool IDEEventBus::PublishShutdown() noexcept {
    return Publish(EventType::Shutdown, {});
}

// --- Event Subscription ---

void IDEEventBus::Subscribe(EventType type, EventHandler handler) noexcept {
    if (m_handlerCount >= MAX_HANDLERS) return;
    
    m_handlers[m_handlerCount].type = type;
    m_handlers[m_handlerCount].handler = std::move(handler);
    m_handlers[m_handlerCount].active = true;
    ++m_handlerCount;
}

void IDEEventBus::SubscribeAll(EventHandler handler) noexcept {
    m_catchAllHandler = std::move(handler);
    m_hasCatchAll = true;
}

void IDEEventBus::UnsubscribeAll() noexcept {
    for (auto& entry : m_handlers) {
        entry.active = false;
    }
    m_handlerCount = 0;
    m_hasCatchAll = false;
    m_catchAllHandler = nullptr;
}

// --- Event Processing ---

size_t IDEEventBus::Poll() noexcept {
    if (!m_session) return 0;
    
    size_t processed = 0;
    SharedEventFrame frame;
    
    // Process up to SLOT_COUNT events per poll to prevent starvation
    for (size_t i = 0; i < UnifiedSessionStateArena::SLOT_COUNT; ++i) {
        if (!m_session->ReadNextEvent(frame, m_lastSequence)) {
            break;
        }
        
        DispatchEvent(frame);
        ++processed;
    }
    
    return processed;
}

bool IDEEventBus::WaitAndPoll(DWORD timeoutMs) noexcept {
    // Simple implementation: poll with sleep
    // In production, would use event handles or condition variables
    
    DWORD startTime = GetTickCount();
    
    while (true) {
        size_t processed = Poll();
        if (processed > 0) {
            return true;
        }
        
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        // Yield to prevent busy-waiting
        Sleep(1);
    }
}

void IDEEventBus::DispatchEvent(const SharedEventFrame& frame) noexcept {
    // Dispatch to specific handlers
    for (size_t i = 0; i < m_handlerCount; ++i) {
        if (m_handlers[i].active && 
            static_cast<uint32_t>(m_handlers[i].type) == frame.eventType) {
            m_handlers[i].handler(frame);
        }
    }
    
    // Dispatch to catch-all handler
    if (m_hasCatchAll && m_catchAllHandler) {
        m_catchAllHandler(frame);
    }
}

} // namespace RawrXD
