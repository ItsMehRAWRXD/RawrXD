#include "RawrXD_ChatWindow.h"
#include <commctrl.h>
#include <ctime>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {
namespace GUI {

// Static window class registration
static const wchar_t* CHAT_WINDOW_CLASS = L"RawrXD_ChatWindow";
static bool s_classRegistered = false;

ChatWindow::ChatWindow() = default;

ChatWindow::~ChatWindow() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
    }
}

bool ChatWindow::Create(HWND parentHwnd, HINSTANCE hInstance, int x, int y, int width, int height) {
    // Register window class if not already done
    if (!s_classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = ChatWindow::WndProc;
        wc.hInstance = hInstance;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = CHAT_WINDOW_CLASS;
        
        if (!RegisterClassExW(&wc)) {
            return false;
        }
        s_classRegistered = true;
    }
    
    // Create the chat window
    m_hwnd = CreateWindowExW(
        WS_EX_CONTROLPARENT,
        CHAT_WINDOW_CLASS,
        L"Chat",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, width, height,
        parentHwnd,
        nullptr,
        hInstance,
        this
    );
    
    return m_hwnd != nullptr;
}

void ChatWindow::SetOllamaClient(RawrXD::Backend::OllamaClient* client) {
    m_ollamaClient = client;
}

void ChatWindow::SetAvailableModels(const std::vector<std::string>& models) {
    m_availableModels = models;
    
    // Populate dropdown
    if (m_hwndModelDropdown) {
        SendMessage(m_hwndModelDropdown, CB_RESETCONTENT, 0, 0);
        for (const auto& model : models) {
            std::wstring wmodel(model.begin(), model.end());
            SendMessageW(m_hwndModelDropdown, CB_ADDSTRING, 0, (LPARAM)wmodel.c_str());
        }
        if (!models.empty()) {
            SendMessage(m_hwndModelDropdown, CB_SETCURSEL, 0, 0);
            m_currentModel = models[0];
        }
    }
}

void ChatWindow::SendMessage(const std::string& text) {
    if (text.empty() || m_isGenerating || !m_ollamaClient) {
        return;
    }
    
    // Add user message to history
    ChatMessage userMsg;
    userMsg.isUser = true;
    userMsg.content = text;
    userMsg.timestamp = GetCurrentTimestamp();
    userMsg.model = "";
    AddMessageToHistory(userMsg);
    
    // Clear input
    SetWindowTextA(m_hwndInput, "");
    
    // Start generation
    m_isGenerating = true;
    m_currentResponse.clear();
    SetWindowTextA(m_hwndStatus, "Generating...");
    
    // Create AI request
    RawrXD::Backend::OllamaGenerateRequest request;
    request.model = m_currentModel;
    request.prompt = text;
    request.stream = true;
    request.options["num_predict"] = 2048;  // Default max tokens
    
    // Send request (async callback)
    m_ollamaClient->generate(request,
        [this](const std::string& chunk) {
            // Stream chunk callback - marshal to UI thread
            if (m_hwnd) {
                // Copy chunk to heap for LPARAM
                std::string* chunkCopy = new std::string(chunk);
                PostMessage(m_hwnd, WM_APP + 1, 0, (LPARAM)chunkCopy);
            }
        },
        [this](bool success, const std::string& response) {
            // Completion callback
            if (m_hwnd) {
                PostMessage(m_hwnd, WM_APP + 2, success ? 1 : 0, 0);
            }
        }
    );
}

LRESULT CALLBACK ChatWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    ChatWindow* pThis = nullptr;
    
    if (msg == WM_CREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        pThis = reinterpret_cast<ChatWindow*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hwnd = hwnd;
        pThis->OnCreate();
        return 0;
    }
    
    pThis = reinterpret_cast<ChatWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT ChatWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
            
        case WM_COMMAND:
            OnCommand(wParam, lParam);
            return 0;
            
        case WM_APP + 1:  // Stream chunk
            if (lParam) {
                std::string* chunk = reinterpret_cast<std::string*>(lParam);
                OnResponseChunk(*chunk);
                delete chunk;
            }
            return 0;
            
        case WM_APP + 2:  // Response complete
            OnResponseComplete();
            return 0;
            
        case WM_CTLCOLORSTATIC:
            // Give history area a white background
            return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
            
        case WM_DESTROY:
            m_hwnd = nullptr;
            return 0;
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

void ChatWindow::OnCreate() {
    HINSTANCE hInst = GetModuleHandle(nullptr);
    
    // Model dropdown label
    CreateWindowW(L"STATIC", L"Model:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        PADDING, PADDING, 50, 20,
        m_hwnd, nullptr, hInst, nullptr);
    
    // Model dropdown
    m_hwndModelDropdown = CreateWindowW(L"COMBOBOX", L"",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | CBS_SORT | WS_VSCROLL,
        PADDING + 55, PADDING, 200, 200,
        m_hwnd, (HMENU)1001, hInst, nullptr);
    
    // Refresh models button
    CreateWindowW(L"BUTTON", L"Refresh",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        PADDING + 260, PADDING, 70, 24,
        m_hwnd, (HMENU)1002, hInst, nullptr);
    
    // Chat history (RichEdit for formatting)
    LoadLibraryW(L"Msftedit.dll");
    m_hwndHistory = CreateWindowW(L"RICHEDIT50W", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | 
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_WANTRETURN,
        PADDING, PADDING + MODEL_DROPDOWN_HEIGHT + PADDING, 
        400, 300,  // Will be resized in OnSize
        m_hwnd, nullptr, hInst, nullptr);
    
    // Set history background to white
    SendMessage(m_hwndHistory, EM_SETBKGNDCOLOR, 0, RGB(255, 255, 255));
    
    // Input area
    m_hwndInput = CreateWindowW(L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | 
        ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
        PADDING, 400, 300, INPUT_HEIGHT,
        m_hwnd, (HMENU)1003, hInst, nullptr);
    
    // Send button
    m_hwndSendBtn = CreateWindowW(L"BUTTON", L"Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,
        320, 400, BUTTON_WIDTH, 30,
        m_hwnd, (HMENU)1004, hInst, nullptr);
    
    // Status bar
    m_hwndStatus = CreateWindowW(L"STATIC", L"Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN,
        PADDING, 470, 400, STATUS_HEIGHT,
        m_hwnd, nullptr, hInst, nullptr);
    
    // Add welcome message
    SetWindowTextA(m_hwndHistory, 
        "Welcome to RawrXD IDE Chat!\r\n"
        "Select a model from the dropdown and start chatting.\r\n"
        "Press Enter to send, Shift+Enter for new line.\r\n\r\n");
}

void ChatWindow::OnSize(int width, int height) {
    if (width < 100 || height < 100) return;
    
    int contentWidth = width - (PADDING * 2);
    int contentHeight = height - (PADDING * 2);
    
    // Model dropdown stays at top
    SetWindowPos(m_hwndModelDropdown, nullptr, 
        PADDING + 55, PADDING, contentWidth - 55 - 80, 200,
        SWP_NOZORDER);
    
    // Refresh button
    HWND hwndRefresh = GetDlgItem(m_hwnd, 1002);
    if (hwndRefresh) {
        SetWindowPos(hwndRefresh, nullptr,
            width - PADDING - 70, PADDING, 70, 24,
            SWP_NOZORDER);
    }
    
    // History takes most space
    int historyTop = PADDING + MODEL_DROPDOWN_HEIGHT + PADDING;
    int historyHeight = height - historyTop - INPUT_HEIGHT - STATUS_HEIGHT - (PADDING * 3);
    SetWindowPos(m_hwndHistory, nullptr,
        PADDING, historyTop, contentWidth, historyHeight,
        SWP_NOZORDER);
    
    // Input at bottom
    int inputTop = historyTop + historyHeight + PADDING;
    SetWindowPos(m_hwndInput, nullptr,
        PADDING, inputTop, contentWidth - BUTTON_WIDTH - PADDING, INPUT_HEIGHT,
        SWP_NOZORDER);
    
    // Send button next to input
    SetWindowPos(m_hwndSendBtn, nullptr,
        PADDING + contentWidth - BUTTON_WIDTH, inputTop, BUTTON_WIDTH, INPUT_HEIGHT,
        SWP_NOZORDER);
    
    // Status at very bottom
    int statusTop = inputTop + INPUT_HEIGHT + PADDING;
    SetWindowPos(m_hwndStatus, nullptr,
        PADDING, statusTop, contentWidth, STATUS_HEIGHT,
        SWP_NOZORDER);
}

void ChatWindow::OnCommand(WPARAM wParam, LPARAM lParam) {
    int id = LOWORD(wParam);
    int code = HIWORD(wParam);
    
    switch (id) {
        case 1001:  // Model dropdown
            if (code == CBN_SELCHANGE) {
                OnModelChanged();
            }
            break;
            
        case 1002:  // Refresh button
            // TODO: Fetch models from Ollama
            SetWindowTextA(m_hwndStatus, "Models refreshed");
            break;
            
        case 1003:  // Input edit
            if (code == EN_CHANGE) {
                // Enable/disable send button based on content
            }
            break;
            
        case 1004:  // Send button
            OnSendClicked();
            break;
    }
}

void ChatWindow::OnSendClicked() {
    char buffer[4096];
    GetWindowTextA(m_hwndInput, buffer, sizeof(buffer));
    if (strlen(buffer) > 0) {
        SendMessage(buffer);
    }
}

void ChatWindow::OnModelChanged() {
    int sel = (int)SendMessage(m_hwndModelDropdown, CB_GETCURSEL, 0, 0);
    if (sel >= 0) {
        char buffer[256];
        SendMessageA(m_hwndModelDropdown, CB_GETLBTEXT, sel, (LPARAM)buffer);
        m_currentModel = buffer;
        
        char status[512];
        snprintf(status, sizeof(status), "Model selected: %s", m_currentModel.c_str());
        SetWindowTextA(m_hwndStatus, status);
    }
}

void ChatWindow::OnResponseChunk(const std::string& chunk) {
    m_currentResponse += chunk;
    
    // Update display with streaming response
    std::string display = "AI [" + m_currentModel + "]: " + m_currentResponse;
    
    // Append to RichEdit
    CHARRANGE cr;
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessageA(m_hwndHistory, EM_EXSETSEL, 0, (LPARAM)&cr);
    
    // Format: AI message in different color
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = RGB(0, 100, 200);  // Blue for AI
    SendMessage(m_hwndHistory, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    
    SendMessageA(m_hwndHistory, EM_REPLACESEL, 0, (LPARAM)chunk.c_str());
    ScrollToBottom();
}

void ChatWindow::OnResponseComplete() {
    m_isGenerating = false;
    
    // Add complete message to history
    ChatMessage aiMsg;
    aiMsg.isUser = false;
    aiMsg.content = m_currentResponse;
    aiMsg.timestamp = GetCurrentTimestamp();
    aiMsg.model = m_currentModel;
    AddMessageToHistory(aiMsg);
    
    SetWindowTextA(m_hwndStatus, "Ready");
    m_currentResponse.clear();
}

void ChatWindow::AddMessageToHistory(const ChatMessage& msg) {
    m_messages.push_back(msg);
    UpdateHistoryDisplay();
}

void ChatWindow::UpdateHistoryDisplay() {
    // Build formatted text
    std::string text;
    for (const auto& msg : m_messages) {
        text += "[" + msg.timestamp + "] ";
        if (msg.isUser) {
            text += "You: " + msg.content + "\r\n\r\n";
        } else {
            text += "AI [" + msg.model + "]: " + msg.content + "\r\n\r\n";
        }
    }
    
    SetWindowTextA(m_hwndHistory, text.c_str());
    ScrollToBottom();
}

void ChatWindow::ScrollToBottom() {
    SendMessage(m_hwndHistory, WM_VSCROLL, SB_BOTTOM, 0);
}

std::string ChatWindow::GetCurrentTimestamp() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%H:%M:%S");
    return oss.str();
}

} // namespace GUI
} // namespace RawrXD
