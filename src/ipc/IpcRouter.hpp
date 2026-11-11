// ============================================================================
// IpcRouter.hpp — Native IPC Router
// Internal messages, UI commands, engine commands
// ============================================================================

#ifndef IPC_ROUTER_HPP
#define IPC_ROUTER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <mutex>

namespace rawr {

// ============================================================================
// IPC Message
// ============================================================================
struct IpcMessage {
    uint32_t id;
    uint32_t type;
    std::string command;
    std::string payload;
    uint64_t timestamp;
};

// ============================================================================
// IPC Command Handler
// ============================================================================
using IpcHandler = std::function<std::string(const std::string& command, const std::string& payload)>;

// ============================================================================
// IPC Channel Types
// ============================================================================
enum class IpcChannel : uint32_t {
    Engine = 1,
    UI,
    Agent,
    Telemetry,
    State,
    System
};

// ============================================================================
// IpcRouter — Routes messages between subsystems
// ============================================================================
class IpcRouter {
public:
    static IpcRouter& Get();

    bool Initialize();
    void Shutdown();

    // Command registration
    void RegisterHandler(const char* command, IpcHandler handler);
    void UnregisterHandler(const char* command);

    // Message dispatch
    std::string Dispatch(const char* command, const char* payload);
    std::string DispatchChannel(IpcChannel channel, const char* command, const char* payload);

    // Async queue
    void Enqueue(const IpcMessage& message);
    bool Dequeue(IpcMessage& message);
    uint32_t GetQueueSize() const;

    // Statistics
    uint32_t GetDispatchedCount() const { return m_dispatched; }
    uint32_t GetHandlerCount() const { return static_cast<uint32_t>(m_handlers.size()); }

private:
    IpcRouter() = default;
    ~IpcRouter() = default;
    IpcRouter(const IpcRouter&) = delete;
    IpcRouter& operator=(const IpcRouter&) = delete;

    std::unordered_map<std::string, IpcHandler> m_handlers;
    std::vector<IpcMessage> m_queue;
    uint32_t m_dispatched = 0;
    uint32_t m_nextId = 1;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // IPC_ROUTER_HPP
