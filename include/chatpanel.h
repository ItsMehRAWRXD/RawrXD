<<<<<<< HEAD
// Chat Panel - AI Chat Interface
// Provides chat panel UI integration for all IDE variants

#ifndef CHATPANEL_H_
#define CHATPANEL_H_

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace ChatPanel {

// Chat message structure
struct Message {
    enum class Role { User, Assistant, System, Tool };
    
    Role role = Role::User;
    std::string content;
    int64_t timestamp = 0;
    std::string toolName;    // Set if this is a tool result
    bool isStreaming = false;
};

// Chat session
struct Session {
    std::string id;
    std::string title;
    std::vector<Message> messages;
    int64_t createdAt = 0;
    int64_t updatedAt = 0;
};

// Callbacks for chat events
using MessageCallback = std::function<void(const Message&)>;
using StreamCallback = std::function<void(const std::string& chunk)>;

// Chat panel interface
class IChatPanel {
public:
    virtual ~IChatPanel() = default;
    
    virtual void sendMessage(const std::string& text) = 0;
    virtual void clearHistory() = 0;
    virtual std::vector<Message> getHistory() const = 0;
    virtual void setSystemPrompt(const std::string& prompt) = 0;
    
    virtual void onMessageReceived(MessageCallback callback) = 0;
    virtual void onStreamChunk(StreamCallback callback) = 0;
};

} // namespace ChatPanel

#endif // CHATPANEL_H_
=======
// Chat Panel - Integrated from Cursor IDE Reverse Engineering
// Integrates Cursor's chat panel UI
// Generated: 2026-01-25 06:34:12

#ifndef CHATPANEL_H_
#define CHATPANEL_H_

// TODO: Define interface based on Cursor reverse engineering
// Source: d:\lazy init ide\Cursor_Source_Extracted

#endif // CHATPANEL_H_
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
