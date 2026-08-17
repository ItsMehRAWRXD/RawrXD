// Chat Workspace - Agentic chat interface
#include "../include/chat_workspace.h"
#include <windows.h>
#include <vector>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <chrono>

namespace {
    // Message structure for chat history
    struct ChatMessage {
        std::string id;
        std::string role;      // "user", "assistant", "system"
        std::string content;
        std::chrono::steady_clock::time_point timestamp;
        bool isStreaming;
        bool isComplete;
    };
    
    // Workspace state
    struct WorkspaceState {
        std::vector<ChatMessage> messages;
        std::mutex mutex;
        std::condition_variable cv;
        std::atomic<bool> initialized{false};
        std::atomic<bool> shutdown{false};
        void* parentHandle = nullptr;
        std::string currentModel;
        size_t maxHistorySize = 1000;
    };
    
    WorkspaceState g_state;
    
    std::string GenerateMessageId() {
        static std::atomic<uint64_t> counter{0};
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        return "msg_" + std::to_string(now) + "_" + std::to_string(counter.fetch_add(1));
    }
}

ChatWorkspace::ChatWorkspace(void* parent) : m_parent(parent) {
    // Lightweight constructor - defer widget creation
    m_initialized = false;
}

ChatWorkspace::~ChatWorkspace() {
    Shutdown();
}

void ChatWorkspace::initialize() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    if (g_state.initialized.load()) {
        return;  // Already initialized
    }
    
    g_state.parentHandle = m_parent;
    g_state.initialized.store(true);
    g_state.shutdown.store(false);
    
    m_initialized = true;
    fprintf(stderr, "[ChatWorkspace] Initialized\n");
}

void ChatWorkspace::Shutdown() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    if (!g_state.initialized.load()) {
        return;
    }
    
    g_state.shutdown.store(true);
    g_state.initialized.store(false);
    g_state.messages.clear();
    g_state.cv.notify_all();
    
    m_initialized = false;
    fprintf(stderr, "[ChatWorkspace] Shutdown complete\n");
}

bool ChatWorkspace::IsInitialized() const {
    return g_state.initialized.load();
}

std::string ChatWorkspace::SubmitMessage(const std::string& message, const std::string& role) {
    if (!g_state.initialized.load()) {
        return "";
    }
    
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    ChatMessage msg;
    msg.id = GenerateMessageId();
    msg.role = role.empty() ? "user" : role;
    msg.content = message;
    msg.timestamp = std::chrono::steady_clock::now();
    msg.isStreaming = false;
    msg.isComplete = true;
    
    g_state.messages.push_back(msg);
    
    // Trim history if needed
    while (g_state.messages.size() > g_state.maxHistorySize) {
        g_state.messages.erase(g_state.messages.begin());
    }
    
    // Notify listeners
    g_state.cv.notify_all();
    
    // Trigger command callback if set
    if (m_onCommandIssued) {
        m_onCommandIssued(message);
    }
    
    return msg.id;
}

std::string ChatWorkspace::SubmitStreamingMessage(const std::string& role) {
    if (!g_state.initialized.load()) {
        return "";
    }
    
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    ChatMessage msg;
    msg.id = GenerateMessageId();
    msg.role = role.empty() ? "assistant" : role;
    msg.content = "";
    msg.timestamp = std::chrono::steady_clock::now();
    msg.isStreaming = true;
    msg.isComplete = false;
    
    g_state.messages.push_back(msg);
    
    return msg.id;
}

bool ChatWorkspace::AppendToMessage(const std::string& messageId, const std::string& chunk) {
    if (!g_state.initialized.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    for (auto& msg : g_state.messages) {
        if (msg.id == messageId && msg.isStreaming) {
            msg.content += chunk;
            g_state.cv.notify_all();
            return true;
        }
    }
    
    return false;
}

bool ChatWorkspace::CompleteMessage(const std::string& messageId) {
    if (!g_state.initialized.load()) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    for (auto& msg : g_state.messages) {
        if (msg.id == messageId && msg.isStreaming) {
            msg.isStreaming = false;
            msg.isComplete = true;
            g_state.cv.notify_all();
            return true;
        }
    }
    
    return false;
}

std::vector<ChatMessageInfo> ChatWorkspace::GetMessages(size_t limit) const {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    
    std::vector<ChatMessageInfo> result;
    size_t start = (g_state.messages.size() > limit) ? g_state.messages.size() - limit : 0;
    
    for (size_t i = start; i < g_state.messages.size(); ++i) {
        const auto& msg = g_state.messages[i];
        ChatMessageInfo info;
        info.id = msg.id;
        info.role = msg.role;
        info.content = msg.content;
        info.isStreaming = msg.isStreaming;
        info.isComplete = msg.isComplete;
        result.push_back(info);
    }
    
    return result;
}

bool ChatWorkspace::ClearHistory() {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.messages.clear();
    return true;
}

size_t ChatWorkspace::GetMessageCount() const {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.messages.size();
}

void ChatWorkspace::SetModel(const std::string& modelName) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.currentModel = modelName;
}

std::string ChatWorkspace::GetModel() const {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    return g_state.currentModel;
}

void ChatWorkspace::SetMaxHistorySize(size_t size) {
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.maxHistorySize = size;
    
    // Trim if needed
    while (g_state.messages.size() > g_state.maxHistorySize) {
        g_state.messages.erase(g_state.messages.begin());
    }
}

void* ChatWorkspace::getWidgetHandle() const {
    return m_handle;
}

