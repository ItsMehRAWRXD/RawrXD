// ============================================================================
// RawrXD Codex Event Bridge
// Integrates Codex module with IDE EventBus for UnifiedSessionState
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include "CodexGUI.hpp"
#include "CodexEventBus.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

namespace RawrXD {
namespace Codex {

// Codex-specific event types (extend RawrXD::EventType)
enum class CodexEventType {
    StreamStarted = 1000,
    StreamChunk,
    StreamCompleted,
    StreamError,
    CommandReceived,
    GUIStateChanged,
};

// Codex event payload
struct CodexEvent {
    CodexEventType type;
    std::string sessionId;
    std::string data;
    std::string error;
    bool isFinal = false;
    uint64_t timestamp = 0;
};

// Event bridge between Codex and IDE EventBus
class CodexEventBridge {
public:
    using CodexHandler = std::function<void(const CodexEvent&)>;
    using Token = size_t;

    CodexEventBridge();
    ~CodexEventBridge();

    // Initialize with CLI backend
    bool Initialize(std::shared_ptr<CodexCLI> cli);

    // Subscribe to Codex events
    Token Subscribe(CodexEventType type, CodexHandler handler);
    Token SubscribeAll(CodexHandler handler);
    void Unsubscribe(Token token);

    // Publish Codex events
    void Publish(const CodexEvent& event);
    void Publish(CodexEventType type, const std::string& data = "");

    // Process event queue (call from main thread)
    void ProcessQueue();

    // IDE EventBus integration
    void ConnectToIDEEventBus();
    void DisconnectFromIDEEventBus();

    // Command handlers (called from IDE)
    void OnIDECommand(const std::string& command, const std::string& args);
    void OnCompleteRequest(const std::string& prompt);
    void OnStreamRequest(const std::string& prompt);
    void OnGUIRequest();

    // Check if bridge is active
    bool IsActive() const { return m_active; }

    // Get CLI backend
    std::shared_ptr<CodexCLI> GetCLI() const { return m_cli; }

private:
    std::shared_ptr<CodexCLI> m_cli;
    std::unique_ptr<CodexGUI> m_gui;
    std::atomic<bool> m_active{false};
    std::atomic<bool> m_processing{false};

    // Event handlers
    std::mutex m_mutex;
    std::unordered_map<CodexEventType, std::vector<std::pair<Token, CodexHandler>>> m_handlers;
    std::vector<std::pair<Token, CodexHandler>> m_allHandlers;
    std::queue<CodexEvent> m_queue;
    Token m_nextToken = 1;

    // CodexEventBus for IDE integration
    CodexEventBus m_eventBus;
    bool m_eventBusConnected = false;

    // Background processing
    std::thread m_workerThread;
    void WorkerLoop();

    // Stream handling
    void HandleStream(const std::string& prompt);
    static DWORD WINAPI StreamThread(LPVOID param);
};

} // namespace Codex
} // namespace RawrXD
