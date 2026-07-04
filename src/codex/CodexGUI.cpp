// ============================================================================
// RawrXD GPT/Codex GUI Implementation
// Win32-based GUI for OpenAI GPT and GitHub Copilot
// ============================================================================

#include "CodexGUI.hpp"

// MinGW compatibility: Use system commctrl.h if available, otherwise minimal definitions
#ifdef __MINGW32__
    #include <windows.h>
    // Minimal commctrl definitions for MinGW
    #ifndef ICC_WIN95_CLASSES
        #define ICC_WIN95_CLASSES 0x00000001
    #endif
    #ifndef ICC_STANDARD_CLASSES
        #define ICC_STANDARD_CLASSES 0x00004000
    #endif
    typedef struct tagINITCOMMONCONTROLSEX {
        DWORD dwSize;
        DWORD dwICC;
    } INITCOMMONCONTROLSEX, *LPINITCOMMONCONTROLSEX;
    BOOL WINAPI InitCommonControlsEx(LPINITCOMMONCONTROLSEX);
#else
    #include <commctrl.h>
    #include <richedit.h>
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

namespace RawrXD {
namespace Codex {

CodexGUI::CodexGUI() = default;
CodexGUI::~CodexGUI() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
    }
}

bool CodexGUI::Initialize(HINSTANCE hInstance, int nCmdShow) {
    m_hInstance = hInstance;
    
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassExW(&wc)) {
        return false;
    }
    
    // Create main window
    m_hwnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"RawrXD Codex GUI",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 700,
        nullptr,
        nullptr,
        hInstance,
        this
    );
    
    if (!m_hwnd) {
        return false;
    }
    
    // Create layout
    if (!CreateLayout()) {
        return false;
    }
    
    ShowWindow(m_hwnd, nCmdShow);
    UpdateWindow(m_hwnd);
    
    m_running = true;
    return true;
}

bool CodexGUI::CreateLayout() {
    // Output area (RichEdit)
    m_hwndOutput = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY |
        ES_WANTRETURN,
        10, 10,
        860, 500,
        m_hwnd,
        (HMENU)100,
        m_hInstance,
        nullptr
    );
    
    if (!m_hwndOutput) return false;
    
    // Set font
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                              DEFAULT_PITCH | FF_SWISS, L"Consolas");
    SendMessage(m_hwndOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Input area
    m_hwndInput = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER |
        ES_AUTOHSCROLL | ES_WANTRETURN,
        10, 520,
        700, 30,
        m_hwnd,
        (HMENU)101,
        m_hInstance,
        nullptr
    );
    
    if (!m_hwndInput) return false;
    SendMessage(m_hwndInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Send button
    m_hwndSendBtn = CreateWindowExW(
        0,
        L"BUTTON",
        L"Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        720, 520,
        70, 30,
        m_hwnd,
        (HMENU)102,
        m_hInstance,
        nullptr
    );
    
    if (!m_hwndSendBtn) return false;
    
    // Clear button
    CreateWindowExW(
        0,
        L"BUTTON",
        L"Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        800, 520,
        70, 30,
        m_hwnd,
        (HMENU)103,
        m_hInstance,
        nullptr
    );
    
    // Status bar
    m_hwndStatus = CreateWindowExW(
        0,
        L"STATIC",
        L"Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        10, 560,
        860, 20,
        m_hwnd,
        (HMENU)104,
        m_hInstance,
        nullptr
    );
    
    // Set focus to input
    SetFocus(m_hwndInput);
    
    return true;
}

int CodexGUI::Run() {
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK CodexGUI::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    CodexGUI* pThis = nullptr;
    
    if (uMsg == WM_CREATE) {
        auto* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        pThis = static_cast<CodexGUI*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hwnd = hwnd;
        return 0;
    } else {
        pThis = reinterpret_cast<CodexGUI*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (!pThis) {
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    
    switch (uMsg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case 102: // Send
                    pThis->OnSend();
                    return 0;
                case 103: // Clear
                    pThis->OnClear();
                    return 0;
            }
            break;
            
        case WM_SIZE:
            // Resize controls
            if (pThis->m_hwndOutput && pThis->m_hwndInput) {
                int width = LOWORD(lParam);
                int height = HIWORD(lParam);
                
                SetWindowPos(pThis->m_hwndOutput, nullptr, 10, 10,
                           width - 40, height - 220, SWP_NOZORDER);
                SetWindowPos(pThis->m_hwndInput, nullptr, 10, height - 200,
                           width - 220, 30, SWP_NOZORDER);
                SetWindowPos(pThis->m_hwndSendBtn, nullptr, width - 200, height - 200,
                           70, 30, SWP_NOZORDER);
            }
            return 0;
            
        case WM_GETMINMAXINFO: {
            auto* pMMI = reinterpret_cast<MINMAXINFO*>(lParam);
            pMMI->ptMinTrackSize.x = 600;
            pMMI->ptMinTrackSize.y = 400;
            return 0;
        }
        
        case WM_CLOSE:
            pThis->m_running = false;
            DestroyWindow(hwnd);
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        case WM_CODEX_STREAM_CHUNK: {
            // Worker thread has sent us a chunk - take ownership and display
            auto* wChunk = reinterpret_cast<std::wstring*>(lParam);
            if (wChunk) {
                pThis->OnStreamChunk(*wChunk);
                delete wChunk; // Reclaim memory on UI thread boundary
            }
            return 0;
        }
        
        case WM_CODEX_STREAM_DONE: {
            // Streaming complete - re-enable UI
            pThis->OnStreamDone();
            return 0;
        }
        
        case WM_CODEX_STREAM_ERROR: {
            // Error occurred - display and re-enable UI
            auto* wError = reinterpret_cast<std::wstring*>(lParam);
            if (wError) {
                pThis->OnStreamError(*wError);
                delete wError;
            }
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

void CodexGUI::OnSend() {
    if (m_processing) return;
    
    // Get input text
    wchar_t wInput[4096] = {};
    GetWindowTextW(m_hwndInput, wInput, 4096);
    
    if (wcslen(wInput) == 0) return;
    
    // Convert to UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, wInput, -1, nullptr, 0, nullptr, nullptr);
    std::string input(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wInput, -1, &input[0], len, nullptr, nullptr);
    
    // Clear input
    SetWindowTextW(m_hwndInput, L"");
    
    // Append to output
    AppendOutput("\n\n> " + input + "\n\n");
    
    // Process in background thread
    m_processing = true;
    SetStatus("Processing...");
    EnableWindow(m_hwndSendBtn, FALSE);
    
    auto* param = new std::pair<CodexGUI*, std::string>(this, input);
    CloseHandle(CreateThread(nullptr, 0, ProcessThread, param, 0, nullptr));
}

void CodexGUI::OnClear() {
    SetWindowTextW(m_hwndOutput, L"");
}

void CodexGUI::AppendOutput(const std::string& text) {
    // Convert to wide
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring wtext(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wtext[0], len);
    
    // Append to edit control
    int nLength = GetWindowTextLengthW(m_hwndOutput);
    SendMessageW(m_hwndOutput, EM_SETSEL, nLength, nLength);
    SendMessageW(m_hwndOutput, EM_REPLACESEL, 0, reinterpret_cast<LPARAM>(wtext.c_str()));
    SendMessage(m_hwndOutput, EM_SCROLLCARET, 0, 0);
}

void CodexGUI::SetStatus(const std::string& status) {
    int len = MultiByteToWideChar(CP_UTF8, 0, status.c_str(), -1, nullptr, 0);
    std::wstring wstatus(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, status.c_str(), -1, &wstatus[0], len);
    SetWindowTextW(m_hwndStatus, wstatus.c_str());
}

void CodexGUI::ProcessResponse(const std::string& prompt) {
    if (!m_cli) {
        AppendOutput("Error: CLI not initialized\n");
        return;
    }
    
    // For GUI mode, use streaming with cross-thread marshalling
    m_cli->CompleteStreaming(prompt, [this](const std::string& chunk, bool isFinal) {
        if (isFinal) {
            // Signal completion via PostMessage
            PostMessageW(m_hwnd, WM_CODEX_STREAM_DONE, 0, 0);
        } else if (!chunk.empty()) {
            // Marshal chunk to UI thread via heap-allocated string
            int len = MultiByteToWideChar(CP_UTF8, 0, chunk.c_str(), -1, nullptr, 0);
            auto* wChunk = new std::wstring(len, 0);
            MultiByteToWideChar(CP_UTF8, 0, chunk.c_str(), -1, &(*wChunk)[0], len);
            PostMessageW(m_hwnd, WM_CODEX_STREAM_CHUNK, 0, reinterpret_cast<LPARAM>(wChunk));
        }
    });
}

void CodexGUI::OnStreamChunk(const std::wstring& chunk) {
    // Append chunk to output (called on UI thread)
    int nLength = GetWindowTextLengthW(m_hwndOutput);
    SendMessageW(m_hwndOutput, EM_SETSEL, nLength, nLength);
    SendMessageW(m_hwndOutput, EM_REPLACESEL, 0, reinterpret_cast<LPARAM>(chunk.c_str()));
    SendMessage(m_hwndOutput, EM_SCROLLCARET, 0, 0);
}

void CodexGUI::OnStreamDone() {
    // Re-enable UI (called on UI thread)
    m_processing = false;
    SetStatus("Ready");
    EnableWindow(m_hwndSendBtn, TRUE);
    SetFocus(m_hwndInput);
    
    // Append newline after completion
    AppendOutput("\n");
}

void CodexGUI::OnStreamError(const std::wstring& error) {
    // Display error (called on UI thread)
    int nLength = GetWindowTextLengthW(m_hwndOutput);
    SendMessageW(m_hwndOutput, EM_SETSEL, nLength, nLength);
    std::wstring errMsg = L"\n[Error: " + error + L"]\n";
    SendMessageW(m_hwndOutput, EM_REPLACESEL, 0, reinterpret_cast<LPARAM>(errMsg.c_str()));
    
    m_processing = false;
    SetStatus("Error");
    EnableWindow(m_hwndSendBtn, TRUE);
}

DWORD WINAPI CodexGUI::ProcessThread(LPVOID param) {
    auto* p = reinterpret_cast<std::pair<CodexGUI*, std::string>*>(param);
    auto* gui = p->first;
    std::string prompt = std::move(p->second);
    delete p;
    
    gui->ProcessResponse(prompt);
    
    return 0;
}

} // namespace Codex
} // namespace RawrXD
