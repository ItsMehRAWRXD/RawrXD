// ============================================================================
// IpcRouter.cpp — Native IPC Router Implementation
// ============================================================================

#include "IpcRouter.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <chrono>

namespace rawr {

IpcRouter& IpcRouter::Get() {
    static IpcRouter instance;
    return instance;
}

bool IpcRouter::Initialize() {
    RawrRuntime::Get().Log(LogLevel::Info, "IpcRouter initialized");
    return true;
}

void IpcRouter::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_handlers.clear();
    m_queue.clear();
}

void IpcRouter::RegisterHandler(const char* command, IpcHandler handler) {
    if (!command) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_handlers[command] = std::move(handler);
}

void IpcRouter::UnregisterHandler(const char* command) {
    if (!command) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_handlers.erase(command);
}

std::string IpcRouter::Dispatch(const char* command, const char* payload) {
    if (!command) return R"({"error":"no command"})";

    std::lock_guard<std::mutex> lock(m_mutex);
    m_dispatched++;

    auto it = m_handlers.find(command);
    if (it != m_handlers.end()) {
        return it->second(command, payload ? payload : "");
    }

    return R"({"error":"unknown command"})";
}

std::string IpcRouter::DispatchChannel(IpcChannel channel, const char* command, const char* payload) {
    // Prefix command with channel name for routing
    std::string prefixed;
    switch (channel) {
        case IpcChannel::Engine:    prefixed = "engine:"; break;
        case IpcChannel::UI:        prefixed = "ui:"; break;
        case IpcChannel::Agent:     prefixed = "agent:"; break;
        case IpcChannel::Telemetry: prefixed = "telemetry:"; break;
        case IpcChannel::State:     prefixed = "state:"; break;
        case IpcChannel::System:    prefixed = "system:"; break;
    }
    prefixed += command;
    return Dispatch(prefixed.c_str(), payload);
}

void IpcRouter::Enqueue(const IpcMessage& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push_back(message);
}

bool IpcRouter::Dequeue(IpcMessage& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_queue.empty()) return false;
    message = m_queue.front();
    m_queue.erase(m_queue.begin());
    return true;
}

uint32_t IpcRouter::GetQueueSize() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return static_cast<uint32_t>(m_queue.size());
}

} // namespace rawr
