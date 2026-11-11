#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include "../backend/ollama_client.h"

namespace RawrXD {
namespace GUI {

// Chat message structure
struct ChatMessage {
    bool isUser;
    std::string content;
    std::string timestamp;
    std::string model;  // Which model generated this
};

// Chat window with full Ollama integration
class ChatWindow {
public:
    ChatWindow();
    ~ChatWindow();

    // Create the chat window as child of parent HWND
    bool Create(HWND parentHwnd, HINSTANCE hInstance, int x, int y, int width, int height);
    
    // Set the Ollama client for this chat window
    void SetOllamaClient(RawrXD::Backend::OllamaClient* client);
    
    // Set available models for dropdown
    void SetAvailableModels(const std::vector<std::string>& models);
    
    // Send a message (called when user clicks Send or presses Enter)
    void SendMessage(const std::string& text);
    
    // Window procedure
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Get the native HWND
    HWND GetHwnd() const { return m_hwnd; }
    
    // Layout management
    void Layout(int width, int height);

private:
    // Message handlers
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    void OnCreate();
    void OnSize(int width, int height);
    void OnCommand(WPARAM wParam, LPARAM lParam);
    void OnSendClicked();
    void OnModelChanged();
    
    // Async response handling
    void OnResponseChunk(const std::string& chunk);
    void OnResponseComplete();
    
    // UI Helpers
    void AddMessageToHistory(const ChatMessage& msg);
    void UpdateHistoryDisplay();
    void ScrollToBottom();
    std::string GetCurrentTimestamp();
    
    // Controls
    HWND m_hwnd = nullptr;
    HWND m_hwndModelDropdown = nullptr;  // Model selection
    HWND m_hwndHistory = nullptr;        // Chat history (ListBox or RichEdit)
    HWND m_hwndInput = nullptr;          // Message input
    HWND m_hwndSendBtn = nullptr;        // Send button
    HWND m_hwndStatus = nullptr;         // Status bar
    
    // Data
    RawrXD::Backend::OllamaClient* m_ollamaClient = nullptr;
    std::vector<std::string> m_availableModels;
    std::string m_currentModel;
    std::vector<ChatMessage> m_messages;
    std::string m_currentResponse;
    bool m_isGenerating = false;
    
    // Layout constants
    static constexpr int MODEL_DROPDOWN_HEIGHT = 28;
    static constexpr int INPUT_HEIGHT = 60;
    static constexpr int STATUS_HEIGHT = 22;
    static constexpr int BUTTON_WIDTH = 80;
    static constexpr int PADDING = 8;
};

} // namespace GUI
} // namespace RawrXD
