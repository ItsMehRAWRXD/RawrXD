#pragma once

// C++20 / Win32. Chat workspace; no Qt. Callback for command.

#include <string>
#include <functional>
#include <vector>
#include <atomic>

// Forward declaration for message info
struct ChatMessageInfo {
    std::string id;
    std::string role;
    std::string content;
    bool isStreaming;
    bool isComplete;
};

class ChatWorkspace
{
public:
    using CommandIssuedFn = std::function<void(const std::string& command)>;

    ChatWorkspace(void* parent = nullptr);
    ~ChatWorkspace();
    
    // Initialization
    void initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Message handling
    std::string SubmitMessage(const std::string& message, const std::string& role = "user");
    std::string SubmitStreamingMessage(const std::string& role = "assistant");
    bool AppendToMessage(const std::string& messageId, const std::string& chunk);
    bool CompleteMessage(const std::string& messageId);
    
    // History management
    std::vector<ChatMessageInfo> GetMessages(size_t limit = 100) const;
    bool ClearHistory();
    size_t GetMessageCount() const;
    
    // Model management
    void SetModel(const std::string& modelName);
    std::string GetModel() const;
    void SetMaxHistorySize(size_t size);
    
    // Callbacks
    void setOnCommandIssued(CommandIssuedFn f) { m_onCommandIssued = std::move(f); }
    void* getWidgetHandle() const;

private:
    void* m_parent = nullptr;
    void* m_handle = nullptr;
    std::atomic<bool> m_initialized{false};
    CommandIssuedFn m_onCommandIssued;
};
