#pragma once
#include "UnifiedSessionState.hpp"
#include "CommandRouter.hpp"
#include "CommandQueue.hpp"
#include "../../include/rawrxd_version.hpp"
#include <memory>
#include <functional>

namespace RawrXD {

// Phase 4: Integration Layer
// Wires UnifiedSessionState -> CommandQueue -> CommandRouter
class IntegrationLayer {
public:
    using EventCallback = std::function<void(const SharedEventFrame&)>;
    
    static IntegrationLayer& Instance();
    
    // Initialize all subsystems
    bool Initialize(ComponentType componentType);
    
    // Shutdown all subsystems
    void Shutdown();
    
    // Main event loop - polls shared memory and dispatches commands
    void RunEventLoop();
    
    // Single iteration of event loop (for external loop integration)
    bool PollAndDispatch();
    
    // Register a command handler
    bool RegisterCommand(uint32_t hash, CommandHandler handler);
    
    // Push event to queue
    bool PushEvent(uint32_t eventType, const void* payload, uint32_t len);
    
    // Get version info
    VersionInfo GetVersion() const { return m_version; }
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized; }
    
    // Set event callback for monitoring
    void SetEventCallback(EventCallback cb) { m_eventCallback = cb; }
    
private:
    IntegrationLayer() = default;
    ~IntegrationLayer() = default;
    
    std::unique_ptr<UnifiedSessionState> m_sessionState;
    VersionInfo m_version;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    EventCallback m_eventCallback;
    
    // Command processor that routes to handlers
    static void ProcessCommand(CommandJob* job);
};

// Convenience macros
#define RAWRXD_INIT(comp) RawrXD::IntegrationLayer::Instance().Initialize(comp)
#define RAWRXD_SHUTDOWN() RawrXD::IntegrationLayer::Instance().Shutdown()
#define RAWRXD_REGISTER(hash, handler) RawrXD::IntegrationLayer::Instance().RegisterCommand(hash, handler)
#define RAWRXD_PUSH(type, data, len) RawrXD::IntegrationLayer::Instance().PushEvent(type, data, len)

} // namespace RawrXD
