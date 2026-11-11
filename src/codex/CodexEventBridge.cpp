// ============================================================================
// RawrXD Codex Event Bridge Implementation
// ============================================================================

#include "CodexEventBridge.hpp"
#include <windows.h>
#include <algorithm>

namespace RawrXD {
namespace Codex {

CodexEventBridge::CodexEventBridge() = default;

CodexEventBridge::~CodexEventBridge() {
    DisconnectFromIDEEventBus();
    m_active = false;
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
}

bool CodexEventBridge::Initialize(std::shared_ptr<CodexCLI> cli) {
    m_cli = cli;
    if (!m_cli || !m_cli->IsInitialized()) {
        return false;
    }
    
    m_active = true;
    
    // Start background worker for event processing
    m_workerThread = std::thread(&CodexEventBridge::WorkerLoop, this);
    
    return true;
}

CodexEventBridge::Token CodexEventBridge::Subscribe(CodexEventType type, CodexHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    Token tok = m_nextToken++;
    m_handlers[type].push_back({tok, std::move(handler)});
    return tok;
}

CodexEventBridge::Token CodexEventBridge::SubscribeAll(CodexHandler handler) {
    std::lock_guard<std::mutex> lock(m_mutex);
    Token tok = m_nextToken++;
    m_allHandlers.push_back({tok, std::move(handler)});
    return tok;
}

void CodexEventBridge::Unsubscribe(Token token) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [type, handlers] : m_handlers) {
        handlers.erase(
            std::remove_if(handlers.begin(), handlers.end(),
                [token](const auto& p) { return p.first == token; }),
            handlers.end());
    }
    m_allHandlers.erase(
        std::remove_if(m_allHandlers.begin(), m_allHandlers.end(),
            [token](const auto& p) { return p.first == token; }),
        m_allHandlers.end());
}

void CodexEventBridge::Publish(const CodexEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push(event);
}

void CodexEventBridge::Publish(CodexEventType type, const std::string& data) {
    CodexEvent ev;
    ev.type = type;
    ev.data = data;
    ev.timestamp = GetTickCount64();
    Publish(ev);
}

void CodexEventBridge::ProcessQueue() {
    std::queue<CodexEvent> local;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        local.swap(m_queue);
    }
    
    while (!local.empty()) {
        const auto& event = local.front();
        
        // Dispatch to type-specific handlers
        auto it = m_handlers.find(event.type);
        if (it != m_handlers.end()) {
            for (const auto& [tok, handler] : it->second) {
                if (handler) handler(event);
            }
        }
        
        // Dispatch to catch-all handlers
        for (const auto& [tok, handler] : m_allHandlers) {
            if (handler) handler(event);
        }
        
        local.pop();
    }
}

void CodexEventBridge::ConnectToIDEEventBus() {
    // CodexEventBus connects directly to UnifiedSessionState
    // No need for separate IDE EventBus connection - CodexEventBus handles this
    m_eventBusConnected = m_eventBus.Initialize();
}

void CodexEventBridge::DisconnectFromIDEEventBus() {
    m_eventBusConnected = false;
}

void CodexEventBridge::OnIDECommand(const std::string& command, const std::string& args) {
    if (command == "complete") {
        OnCompleteRequest(args);
    } else if (command == "stream") {
        OnStreamRequest(args);
    } else if (command == "gui") {
        OnGUIRequest();
    }
}

void CodexEventBridge::OnCompleteRequest(const std::string& prompt) {
    if (!m_cli || m_processing) return;
    
    m_processing = true;
    Publish(CodexEventType::StreamStarted, prompt);
    
    // Run completion in background
    auto* param = new std::pair<CodexEventBridge*, std::string>(this, prompt);
    CloseHandle(CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* data = reinterpret_cast<std::pair<CodexEventBridge*, std::string>*>(p);
        auto* bridge = data->first;
        std::string prompt = std::move(data->second);
        delete data;
        
        std::string response = bridge->m_cli->Complete(prompt);
        if (!response.empty()) {
            bridge->Publish(CodexEventType::StreamCompleted, response);
        } else {
            bridge->Publish(CodexEventType::StreamError, bridge->m_cli->GetLastError());
        }
        bridge->m_processing = false;
        return 0;
    }, param, 0, nullptr));
}

void CodexEventBridge::OnStreamRequest(const std::string& prompt) {
    if (!m_cli || m_processing) return;
    
    m_processing = true;
    Publish(CodexEventType::StreamStarted, prompt);
    
    // Run streaming in background
    auto* param = new std::pair<CodexEventBridge*, std::string>(this, prompt);
    CloseHandle(CreateThread(nullptr, 0, StreamThread, param, 0, nullptr));
}

void CodexEventBridge::OnGUIRequest() {
    if (m_gui) {
        m_gui->Show();
        return;
    }
    
    // Launch GUI in separate thread
    auto* param = new std::pair<CodexEventBridge*, std::shared_ptr<CodexCLI>>(this, m_cli);
    CloseHandle(CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        auto* data = reinterpret_cast<std::pair<CodexEventBridge*, std::shared_ptr<CodexCLI>>*>(p);
        auto* bridge = data->first;
        auto cli = std::move(data->second);
        delete data;
        
        bridge->m_gui = std::make_unique<CodexGUI>();
        bridge->m_gui->SetCLI(cli);
        
        HINSTANCE hInstance = GetModuleHandle(nullptr);
        if (bridge->m_gui->Initialize(hInstance, SW_SHOW)) {
            bridge->Publish(CodexEventType::GUIStateChanged, "shown");
            bridge->m_gui->Run();
        }
        
        bridge->Publish(CodexEventType::GUIStateChanged, "closed");
        bridge->m_gui.reset();
        return 0;
    }, param, 0, nullptr));
}

void CodexEventBridge::WorkerLoop() {
    while (m_active) {
        ProcessQueue();
        Sleep(16); // ~60fps polling
    }
}

DWORD WINAPI CodexEventBridge::StreamThread(LPVOID param) {
    auto* p = reinterpret_cast<std::pair<CodexEventBridge*, std::string>*>(param);
    auto* bridge = p->first;
    std::string prompt = std::move(p->second);
    delete p;
    
    bridge->m_cli->CompleteStreaming(prompt, [bridge](const std::string& chunk, bool isFinal) {
        if (isFinal) {
            bridge->Publish(CodexEventType::StreamCompleted, "");
            bridge->m_processing = false;
        } else if (!chunk.empty()) {
            bridge->Publish(CodexEventType::StreamChunk, chunk);
        }
    });
    
    return 0;
}

} // namespace Codex
} // namespace RawrXD
