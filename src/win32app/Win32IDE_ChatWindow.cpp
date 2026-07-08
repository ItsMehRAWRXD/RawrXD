// ============================================================================
// RawrXD Win32 Chat Window - Complete Implementation
// Provides chat UI with model selection, message history, and Ollama integration
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <queue>
#include <functional>
#include <sstream>
#include <iomanip>

#include "../ollama_client.h"
#include "../chatpanel.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "riched20.lib")

namespace RawrXD {
namespace UI {

// Chat message structure
struct ChatMessage {
    std::string role;      // "user", "assistant", "system"
    std::string content;
    std::string timestamp;
    bool isStreaming = false;
};

// Model info from Ollama
struct OllamaModelInfo {
    std::string name;
    std::string size;
    std::string family;
    std::string quantized;
};

// ============================================================================
// Chat Window Implementation
// ============================================================================
class ChatWindow {
public:
    ChatWindow();
    ~ChatWindow();

    bool Create(HWND hParent, HINSTANCE hInstance);
    void Destroy();
    void Show();
    void Hide();
    bool IsVisible() const { return m_visible; }
    
    // Message handling
    void AddMessage(const std::string& role, const std::string& content);
    void AppendToLastMessage(const std::string& content);
    void ClearHistory();
    
    // Model management
    void RefreshModelList();
    std::string GetSelectedModel() const;
    void SetSelectedModel(const std::string& model);
    
    // Chat operations
    void SendMessage(const std::string& text);
    void CancelGeneration();
    bool IsGenerating() const { return m_isGenerating; }
    
    // Window handle
    HWND GetHwnd() const { return m_hWnd; }

private:
    // Window handles
    HWND m_hWnd = nullptr;
    HWND m_hParent = nullptr;
    HWND m_hEditHistory = nullptr;
    HWND m_hEditInput = nullptr;
    HWND m_hBtnSend = nullptr;
    HWND m_hBtnClear = nullptr;
    HWND m_hBtnCancel = nullptr;
    HWND m_hComboModel = nullptr;
    HWND m_hBtnRefresh = nullptr;
    HWND m_hStatusBar = nullptr;
    
    // State
    bool m_visible = false;
    bool m_isGenerating = false;
    std::vector<ChatMessage> m_messages;
    std::vector<OllamaModelInfo> m_models;
    std::string m_currentModel;
    
    // Ollama client
    std::unique_ptr<Backend::NativeClient> m_ollamaClient;
    std::thread m_generationThread;
    std::mutex m_messagesMutex;
    
    // Window procedure
    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // UI creation
    bool CreateControls(HINSTANCE hInstance);
    void LayoutControls();
    
    // Operations
    void DoSend();
    void DoClear();
    void DoCancel();
    void DoRefreshModels();
    void UpdateStatus(const std::string& status);
    void FormatAndDisplayMessages();
    void AppendMessageToDisplay(const ChatMessage& msg);
    
    // Ollama integration
    void FetchModelsFromOllama();
    void GenerateResponse(const std::string& userMessage);
    
    // Helpers
    static std::string GetTimestamp();
    static std::string EscapeRichText(const std::string& text);
};

// Static instance for window procedure
static ChatWindow* g_pChatWindow = nullptr;

ChatWindow::ChatWindow() {
    m_ollamaClient = std::make_unique<Backend::NativeClient>("http://localhost:11434");
}

ChatWindow::~ChatWindow() {
    Destroy();
}

bool ChatWindow::Create(HWND hParent, HINSTANCE hInstance) {
    if (m_hWnd) return true;
    
    m_hParent = hParent;
    
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"RawrXDChatWindow";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    // Create window
    m_hWnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"RawrXDChatWindow",
        L"RawrXD Chat",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        hParent,
        nullptr,
        hInstance,
        this
    );
    
    if (!m_hWnd) return false;
    
    g_pChatWindow = this;
    
    // Create controls
    if (!CreateControls(hInstance)) {
        Destroy();
        return false;
    }
    
    // Initial model refresh
    DoRefreshModels();
    
    return true;
}

void ChatWindow::Destroy() {
    if (m_generationThread.joinable()) {
        m_isGenerating = false;
        m_generationThread.join();
    }
    
    if (m_hWnd) {
        DestroyWindow(m_hWnd);
        m_hWnd = nullptr;
    }
    
    m_visible = false;
}

void ChatWindow::Show() {
    if (m_hWnd) {
        ShowWindow(m_hWnd, SW_SHOW);
        UpdateWindow(m_hWnd);
        m_visible = true;
        LayoutControls();
    }
}

void ChatWindow::Hide() {
    if (m_hWnd) {
        ShowWindow(m_hWnd, SW_HIDE);
        m_visible = false;
    }
}

bool ChatWindow::CreateControls(HINSTANCE hInstance) {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {};
    iccex.dwSize = sizeof(iccex);
    iccex.dwICC = ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&iccex);
    
    // Load RichEdit
    LoadLibraryW(L"riched20.dll");
    
    // Create model selection dropdown
    m_hComboModel = CreateWindowW(L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_SORT | WS_VSCROLL,
        10, 10, 300, 200,
        m_hWnd,
        (HMENU)1001,
        hInstance,
        nullptr
    );
    
    // Create refresh button
    m_hBtnRefresh = CreateWindowW(L"BUTTON", L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        320, 10, 80, 25,
        m_hWnd,
        (HMENU)1002,
        hInstance,
        nullptr
    );
    
    // Create chat history (RichEdit)
    m_hEditHistory = CreateWindowW(RICHEDIT_CLASSW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | 
        ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        10, 45, 760, 400,
        m_hWnd,
        (HMENU)1003,
        hInstance,
        nullptr
    );
    
    // Set RichEdit options
    ::SendMessage(m_hEditHistory, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
    ::SendMessage(m_hEditHistory, EM_SETEVENTMASK, 0, ENM_LINK);
    
    // Create input edit
    m_hEditInput = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | 
        ES_AUTOVSCROLL | WS_VSCROLL,
        10, 455, 650, 80,
        m_hWnd,
        (HMENU)1004,
        hInstance,
        nullptr
    );
    
    // Create Send button
    m_hBtnSend = CreateWindowW(L"BUTTON", L"Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,
        670, 455, 100, 35,
        m_hWnd,
        (HMENU)1005,
        hInstance,
        nullptr
    );
    
    // Create Clear button
    m_hBtnClear = CreateWindowW(L"BUTTON", L"Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        670, 500, 100, 35,
        m_hWnd,
        (HMENU)1006,
        hInstance,
        nullptr
    );
    
    // Create Cancel button (initially disabled)
    m_hBtnCancel = CreateWindowW(L"BUTTON", L"Cancel",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
        580, 10, 80, 25,
        m_hWnd,
        (HMENU)1007,
        hInstance,
        nullptr
    );
    
    // Create status bar
    m_hStatusBar = CreateWindowW(STATUSCLASSNAMEW, L"Ready",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        m_hWnd,
        (HMENU)1008,
        hInstance,
        nullptr
    );
    
    // Set fonts
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    
    ::SendMessage(m_hComboModel, WM_SETFONT, (WPARAM)hFont, TRUE);
    ::SendMessage(m_hEditHistory, WM_SETFONT, (WPARAM)hFont, TRUE);
    ::SendMessage(m_hEditInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    ::SendMessage(m_hBtnSend, WM_SETFONT, (WPARAM)hFont, TRUE);
    ::SendMessage(m_hBtnClear, WM_SETFONT, (WPARAM)hFont, TRUE);
    ::SendMessage(m_hBtnCancel, WM_SETFONT, (WPARAM)hFont, TRUE);
    ::SendMessage(m_hBtnRefresh, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    return true;
}

void ChatWindow::LayoutControls() {
    RECT rcClient;
    GetClientRect(m_hWnd, &rcClient);
    
    int width = rcClient.right - rcClient.left;
    int height = rcClient.bottom - rcClient.top;
    
    // Status bar height
    int statusHeight = 20;
    
    // Model dropdown and buttons at top
    SetWindowPos(m_hComboModel, nullptr, 10, 10, 300, 200, SWP_NOZORDER);
    SetWindowPos(m_hBtnRefresh, nullptr, 320, 10, 80, 25, SWP_NOZORDER);
    SetWindowPos(m_hBtnCancel, nullptr, 410, 10, 80, 25, SWP_NOZORDER);
    
    // Chat history (middle)
    int historyTop = 45;
    int historyHeight = height - historyTop - 150 - statusHeight;
    SetWindowPos(m_hEditHistory, nullptr, 10, historyTop, width - 20, historyHeight, SWP_NOZORDER);
    
    // Input area (bottom)
    int inputTop = historyTop + historyHeight + 10;
    int inputHeight = 100;
    SetWindowPos(m_hEditInput, nullptr, 10, inputTop, width - 130, inputHeight, SWP_NOZORDER);
    SetWindowPos(m_hBtnSend, nullptr, width - 110, inputTop, 100, 45, SWP_NOZORDER);
    SetWindowPos(m_hBtnClear, nullptr, width - 110, inputTop + 55, 100, 45, SWP_NOZORDER);
    
    // Status bar at very bottom
    SetWindowPos(m_hStatusBar, nullptr, 0, height - statusHeight, width, statusHeight, SWP_NOZORDER);
}

LRESULT CALLBACK ChatWindow::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    ChatWindow* pThis = nullptr;
    
    if (msg == WM_NCCREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        pThis = static_cast<ChatWindow*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hWnd = hWnd;
    } else {
        pThis = reinterpret_cast<ChatWindow*>(GetWindowLongPtr(hWnd, GWLP_USERDATA));
    }
    
    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

LRESULT ChatWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            LayoutControls();
            return 0;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 1002: // Refresh
                    DoRefreshModels();
                    return 0;
                case 1005: // Send
                    DoSend();
                    return 0;
                case 1006: // Clear
                    DoClear();
                    return 0;
                case 1007: // Cancel
                    DoCancel();
                    return 0;
                case 1004: // Input edit
                    if (HIWORD(wParam) == EN_CHANGE) {
                        // Enable/disable send button based on input
                        int len = GetWindowTextLength(m_hEditInput);
                        EnableWindow(m_hBtnSend, len > 0 && !m_isGenerating);
                    }
                    return 0;
            }
            break;
            
        case WM_GETMINMAXINFO: {
            MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x = 600;
            mmi->ptMinTrackSize.y = 400;
            return 0;
        }
        
        case WM_CLOSE:
            Hide();
            return 0;
            
        case WM_DESTROY:
            m_hWnd = nullptr;
            return 0;
    }
    
    return DefWindowProcW(m_hWnd, msg, wParam, lParam);
}

void ChatWindow::DoSend() {
    if (m_isGenerating) return;
    
    // Get input text
    int len = GetWindowTextLengthW(m_hEditInput);
    if (len == 0) return;
    
    std::wstring wtext(len + 1, L'\0');
    GetWindowTextW(m_hEditInput, &wtext[0], len + 1);
    wtext.resize(len);
    
    // Convert to UTF-8
    int utf8len = WideCharToMultiByte(CP_UTF8, 0, wtext.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string text(utf8len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wtext.c_str(), -1, &text[0], utf8len, nullptr, nullptr);
    
    // Clear input
    SetWindowTextW(m_hEditInput, L"");
    
    // Add user message
    AddMessage("user", text);
    
    // Generate response
    GenerateResponse(text);
}

void ChatWindow::DoClear() {
    ClearHistory();
}

void ChatWindow::DoCancel() {
    CancelGeneration();
}

void ChatWindow::DoRefreshModels() {
    UpdateStatus("Refreshing model list...");
    
    std::thread([this]() {
        FetchModelsFromOllama();
    }).detach();
}

void ChatWindow::FetchModelsFromOllama() {
    if (!m_ollamaClient->testConnection()) {
        UpdateStatus("Error: Cannot connect to Ollama");
        return;
    }
    
    auto models = m_ollamaClient->listModels();
    
    // Update UI on main thread
    PostMessage(m_hWnd, WM_APP + 1, 0, 0);
}

void ChatWindow::GenerateResponse(const std::string& userMessage) {
    if (m_isGenerating) return;
    
    m_isGenerating = true;
    EnableWindow(m_hBtnSend, FALSE);
    EnableWindow(m_hBtnCancel, TRUE);
    UpdateStatus("Generating...");
    
    // Get selected model
    std::string model = GetSelectedModel();
    if (model.empty()) {
        model = "llama3.2:3b"; // Default
    }
    
    // Check if model needs special handling (Mistral/LLaMA-2 based models with tokenizer issues)
    std::string lowerModel = model;
    std::transform(lowerModel.begin(), lowerModel.end(), lowerModel.begin(), ::tolower);
    bool useRawMode = (lowerModel.find("bigdaddyg") != std::string::npos ||
                      lowerModel.find("mistral") != std::string::npos ||
                      lowerModel.find("llama2") != std::string::npos ||
                      lowerModel.find("llama-2") != std::string::npos ||
                      lowerModel.find("dolphin") != std::string::npos ||
                      lowerModel.find("openhermes") != std::string::npos ||
                      lowerModel.find("neural") != std::string::npos ||
                      lowerModel.find("uncensored") != std::string::npos);
    
    if (useRawMode) {
        UpdateStatus("Generating (raw mode for " + model + ")...");
    }
    
    m_generationThread = std::thread([this, model, userMessage, useRawMode]() {
        // Add assistant placeholder
        AddMessage("assistant", "");
        
        if (useRawMode) {
            // Use /api/generate with raw=true for problematic models
            // These models need explicit BOS token (\x01) + [INST] tags
            Backend::OllamaGenerateRequest req;
            req.model = model;
            req.prompt = "\x01[INST] " + userMessage + " [/INST]";
            req.stream = true;
            req.raw = true;  // CRITICAL: Tell Ollama not to apply template
            req.options["num_predict"] = 2048;
            req.options["temperature"] = 0.7;
            
            // Stream callback
            std::string accumulated;
            auto onChunk = [this, &accumulated](const std::string& chunk) {
                accumulated += chunk;
                AppendToLastMessage(chunk);
            };
            
            auto onError = [this](const std::string& error) {
                UpdateStatus("Error: " + error);
            };
            
            auto onComplete = [this](const Backend::NativeInferenceResponse& response) {
                m_isGenerating = false;
                EnableWindow(m_hBtnSend, TRUE);
                EnableWindow(m_hBtnCancel, FALSE);
                
                if (response.error) {
                    UpdateStatus("Error: " + response.error_message);
                } else {
                    std::stringstream ss;
                    ss << "Done - " << response.eval_count << " tokens (raw mode)";
                    UpdateStatus(ss.str());
                }
            };
            
            // Send request
            m_ollamaClient->generate(req, onChunk, onError, onComplete);
        } else {
            // Use /api/chat with messages array - Ollama applies template server-side
            Backend::OllamaChatRequest req;
            req.model = model;
            req.stream = true;
            req.options["num_predict"] = 2048;
            req.options["temperature"] = 0.7;
            
            // Add conversation history
            {
                std::lock_guard<std::mutex> lock(m_messagesMutex);
                for (const auto& msg : m_messages) {
                    if (msg.role != "system") {
                        req.messages.push_back({msg.role, msg.content});
                    }
                }
            }
            
            // Add current message
            req.messages.push_back({"user", userMessage});
            
            // Stream callback
            std::string accumulated;
            auto onChunk = [this, &accumulated](const std::string& chunk) {
                accumulated += chunk;
                AppendToLastMessage(chunk);
            };
            
            auto onError = [this](const std::string& error) {
                UpdateStatus("Error: " + error);
            };
            
            auto onComplete = [this](const Backend::NativeInferenceResponse& response) {
                m_isGenerating = false;
                EnableWindow(m_hBtnSend, TRUE);
                EnableWindow(m_hBtnCancel, FALSE);
                
                if (response.error) {
                    UpdateStatus("Error: " + response.error_message);
                } else {
                    std::stringstream ss;
                    ss << "Done - " << response.eval_count << " tokens";
                    UpdateStatus(ss.str());
                }
            };
        
            // Send request
            m_ollamaClient->chat(req, onChunk, onError, onComplete);
        }
    });
    
    m_generationThread.detach();
}

void ChatWindow::AddMessage(const std::string& role, const std::string& content) {
    std::lock_guard<std::mutex> lock(m_messagesMutex);
    
    ChatMessage msg;
    msg.role = role;
    msg.content = content;
    msg.timestamp = GetTimestamp();
    
    m_messages.push_back(msg);
    
    // Update display
    AppendMessageToDisplay(msg);
}

void ChatWindow::AppendToLastMessage(const std::string& content) {
    std::lock_guard<std::mutex> lock(m_messagesMutex);
    
    if (!m_messages.empty()) {
        m_messages.back().content += content;
        
        // Update display
        FormatAndDisplayMessages();
    }
}

void ChatWindow::ClearHistory() {
    {
        std::lock_guard<std::mutex> lock(m_messagesMutex);
        m_messages.clear();
    }
    
    SetWindowTextW(m_hEditHistory, L"");
    UpdateStatus("History cleared");
}

void ChatWindow::FormatAndDisplayMessages() {
    std::wstringstream wss;
    
    // RichEdit header
    wss << L"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Segoe UI;}}\r\n";
    wss << L"{\\colortbl ;\\red200\\green200\\blue200;\\red100\\green180\\blue255;\\red180\\green255\\blue180;}\r\n";
    
    std::lock_guard<std::mutex> lock(m_messagesMutex);
    
    for (const auto& msg : m_messages) {
        // Convert UTF-8 to wide
        int wlen = MultiByteToWideChar(CP_UTF8, 0, msg.content.c_str(), -1, nullptr, 0);
        std::wstring wcontent(wlen - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, msg.content.c_str(), -1, &wcontent[0], wlen);
        
        // Escape special RTF chars
        for (auto& c : wcontent) {
            if (c == L'\\' || c == L'{' || c == L'}') {
                c = L'?';
            }
        }
        
        if (msg.role == "user") {
            wss << L"\\cf2 User: " << wcontent << L"\\par\r\n";
        } else if (msg.role == "assistant") {
            wss << L"\\cf3 Assistant: " << wcontent << L"\\par\r\n";
        } else {
            wss << L"\\cf1 System: " << wcontent << L"\\par\r\n";
        }
        
        wss << L"\\par\r\n";
    }
    
    wss << L"}";
    
    // Set RichEdit text
    std::wstring rtf = wss.str();
    SETTEXTEX stex = {};
    stex.codepage = 1200; // Unicode
    stex.flags = ST_SELECTION;
    ::SendMessage(m_hEditHistory, EM_SETTEXTEX, (WPARAM)&stex, (LPARAM)rtf.c_str());
    
    // Scroll to bottom
    ::SendMessage(m_hEditHistory, EM_SCROLLCARET, 0, 0);
}

void ChatWindow::AppendMessageToDisplay(const ChatMessage& msg) {
    // For single message append, just reformat all
    FormatAndDisplayMessages();
}

std::string ChatWindow::GetSelectedModel() const {
    if (!m_hComboModel) return "";
    
    int sel = (int)::SendMessage(m_hComboModel, CB_GETCURSEL, 0, 0);
    if (sel == CB_ERR) return "";
    
    int len = (int)::SendMessage(m_hComboModel, CB_GETLBTEXTLEN, sel, 0);
    if (len == CB_ERR) return "";
    
    std::wstring wtext(len + 1, L'\0');
    ::SendMessage(m_hComboModel, CB_GETLBTEXT, sel, (LPARAM)&wtext[0]);
    wtext.resize(len);
    
    // Convert to UTF-8
    int utf8len = WideCharToMultiByte(CP_UTF8, 0, wtext.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string text(utf8len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wtext.c_str(), -1, &text[0], utf8len, nullptr, nullptr);
    
    return text;
}

void ChatWindow::SetSelectedModel(const std::string& model) {
    if (!m_hComboModel) return;
    
    // Convert to wide
    int wlen = MultiByteToWideChar(CP_UTF8, 0, model.c_str(), -1, nullptr, 0);
    std::wstring wmodel(wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, model.c_str(), -1, &wmodel[0], wlen);
    
    // Find and select
    int count = (int)::SendMessage(m_hComboModel, CB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; i++) {
        int len = (int)::SendMessage(m_hComboModel, CB_GETLBTEXTLEN, i, 0);
        std::wstring item(len + 1, L'\0');
        ::SendMessage(m_hComboModel, CB_GETLBTEXT, i, (LPARAM)&item[0]);
        item.resize(len);
        
        if (item == wmodel) {
            ::SendMessage(m_hComboModel, CB_SETCURSEL, i, 0);
            return;
        }
    }
}

void ChatWindow::UpdateStatus(const std::string& status) {
    if (!m_hStatusBar) return;
    
    // Convert to wide
    int wlen = MultiByteToWideChar(CP_UTF8, 0, status.c_str(), -1, nullptr, 0);
    std::wstring wstatus(wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, status.c_str(), -1, &wstatus[0], wlen);
    
    SetWindowTextW(m_hStatusBar, wstatus.c_str());
}

std::string ChatWindow::GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    char buf[32];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

std::string ChatWindow::EscapeRichText(const std::string& text) {
    std::string result;
    for (char c : text) {
        if (c == '\\' || c == '{' || c == '}') {
            result += '\\';
        }
        result += c;
    }
    return result;
}

void ChatWindow::CancelGeneration() {
    if (m_ollamaClient) {
        m_ollamaClient->cancelStream();
    }
    m_isGenerating = false;
    EnableWindow(m_hBtnSend, TRUE);
    EnableWindow(m_hBtnCancel, FALSE);
    UpdateStatus("Cancelled");
}

void ChatWindow::SendMessage(const std::string& text) {
    if (!text.empty()) {
        // Set input text
        int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
        std::wstring wtext(wlen - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wtext[0], wlen);
        SetWindowTextW(m_hEditInput, wtext.c_str());
        
        // Send
        DoSend();
    }
}

void ChatWindow::RefreshModelList() {
    DoRefreshModels();
}

} // namespace UI
} // namespace RawrXD

// ============================================================================
// C API for integration with existing IDE
// ============================================================================

extern "C" {

typedef void* RawrXDChatWindowHandle;

typedef void (*RawrXDChatMessageCallback)(const char* role, const char* content);
typedef void (*RawrXDChatStatusCallback)(const char* status);

__declspec(dllexport) RawrXDChatWindowHandle RawrXDChatWindow_Create(HWND hParent, HINSTANCE hInstance) {
    auto* window = new RawrXD::UI::ChatWindow();
    if (!window->Create(hParent, hInstance)) {
        delete window;
        return nullptr;
    }
    return window;
}

__declspec(dllexport) void RawrXDChatWindow_Destroy(RawrXDChatWindowHandle handle) {
    if (handle) {
        delete static_cast<RawrXD::UI::ChatWindow*>(handle);
    }
}

__declspec(dllexport) void RawrXDChatWindow_Show(RawrXDChatWindowHandle handle) {
    if (handle) {
        static_cast<RawrXD::UI::ChatWindow*>(handle)->Show();
    }
}

__declspec(dllexport) void RawrXDChatWindow_Hide(RawrXDChatWindowHandle handle) {
    if (handle) {
        static_cast<RawrXD::UI::ChatWindow*>(handle)->Hide();
    }
}

__declspec(dllexport) void RawrXDChatWindow_SendMessage(RawrXDChatWindowHandle handle, const char* message) {
    if (handle && message) {
        static_cast<RawrXD::UI::ChatWindow*>(handle)->SendMessage(message);
    }
}

__declspec(dllexport) void RawrXDChatWindow_ClearHistory(RawrXDChatWindowHandle handle) {
    if (handle) {
        static_cast<RawrXD::UI::ChatWindow*>(handle)->ClearHistory();
    }
}

__declspec(dllexport) void RawrXDChatWindow_SetModel(RawrXDChatWindowHandle handle, const char* model) {
    if (handle && model) {
        static_cast<RawrXD::UI::ChatWindow*>(handle)->SetSelectedModel(model);
    }
}

__declspec(dllexport) const char* RawrXDChatWindow_GetModel(RawrXDChatWindowHandle handle) {
    if (handle) {
        static std::string model;
        model = static_cast<RawrXD::UI::ChatWindow*>(handle)->GetSelectedModel();
        return model.c_str();
    }
    return "";
}

__declspec(dllexport) HWND RawrXDChatWindow_GetHwnd(RawrXDChatWindowHandle handle) {
    if (handle) {
        return static_cast<RawrXD::UI::ChatWindow*>(handle)->GetHwnd();
    }
    return nullptr;
}

} // extern "C"