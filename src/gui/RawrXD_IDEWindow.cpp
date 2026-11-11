#include "RawrXD_IDEWindow.h"
#include "../backend/ollama_client.h"
#include <commctrl.h>
#include <windowsx.h>
#include <shellapi.h>
#include <fstream>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {
namespace GUI {

static const wchar_t* IDE_WINDOW_CLASS = L"RawrXD_IDEWindow";
static bool s_classRegistered = false;

IDEWindow::IDEWindow() = default;

IDEWindow::~IDEWindow() {
    // Panels auto-destroy via unique_ptr
}

bool IDEWindow::Create(HINSTANCE hInstance, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {};
    iccex.dwSize = sizeof(iccex);
    iccex.dwICC = ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&iccex);
    
    // Register window class
    if (!s_classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = IDEWindow::WndProc;
        wc.hInstance = hInstance;
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = IDE_WINDOW_CLASS;
        wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
        
        if (!RegisterClassExW(&wc)) {
            MessageBoxW(nullptr, L"Failed to register window class", L"Error", MB_OK);
            return false;
        }
        s_classRegistered = true;
    }
    
    // Create main window
    m_hwnd = CreateWindowExW(
        WS_EX_OVERLAPPEDWINDOW,
        IDE_WINDOW_CLASS,
        L"RawrXD IDE v1.0 - AI-Powered Development Environment",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        MIN_WIDTH, MIN_HEIGHT,
        nullptr,
        nullptr,
        hInstance,
        this
    );
    
    if (!m_hwnd) {
        MessageBoxW(nullptr, L"Failed to create window", L"Error", MB_OK);
        return false;
    }
    
    ShowWindow(m_hwnd, nCmdShow);
    UpdateWindow(m_hwnd);
    
    return true;
}

int IDEWindow::Run() {
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

void IDEWindow::SetOllamaClient(std::shared_ptr<RawrXD::Backend::OllamaClient> client) {
    m_ollamaClient = client;
    if (m_chatWindow && m_ollamaClient) {
        m_chatWindow->SetOllamaClient(m_ollamaClient.get());
    }
}

LRESULT CALLBACK IDEWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    IDEWindow* pThis = nullptr;
    
    if (msg == WM_CREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        pThis = reinterpret_cast<IDEWindow*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hwnd = hwnd;
        pThis->OnCreate();
        return 0;
    }
    
    pThis = reinterpret_cast<IDEWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT IDEWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
            
        case WM_COMMAND:
            OnCommand(wParam, lParam);
            return 0;
            
        case WM_DESTROY:
            OnDestroy();
            return 0;
            
        case WM_GETMINMAXINFO: {
            MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
            mmi->ptMinTrackSize.x = MIN_WIDTH;
            mmi->ptMinTrackSize.y = MIN_HEIGHT;
            return 0;
        }
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

void IDEWindow::OnCreate() {
    HINSTANCE hInst = GetModuleHandle(nullptr);
    
    // Create menu bar
    CreateMenuBar();
    
    // Create status bar
    m_hwndStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0,
        m_hwnd, (HMENU)100, hInst, nullptr);
    
    // Set status bar parts
    int parts[] = { 200, 400, -1 };
    SendMessage(m_hwndStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    SendMessage(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Ready");
    SendMessage(m_hwndStatusBar, SB_SETTEXTW, 1, (LPARAM)L"Ollama: localhost:11434");
    SendMessage(m_hwndStatusBar, SB_SETTEXTW, 2, (LPARAM)L"No file open");
    
    // Create simple editor (multiline edit for now)
    m_hwndEditor = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
        0, 0, 400, 400,
        m_hwnd, (HMENU)101, hInst, nullptr);
    
    // Set editor font
    HFONT hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessage(m_hwndEditor, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Create file browser panel
    m_fileBrowser = std::make_unique<FileBrowser>();
    m_fileBrowser->Create(m_hwnd, hInst, 0, 0, m_fileBrowserWidth, 400);
    m_fileBrowser->OnFileSelected([this](const std::string& path) {
        OnFileSelected(path);
    });
    
    // Create chat panel
    m_chatWindow = std::make_unique<ChatWindow>();
    m_chatWindow->Create(m_hwnd, hInst, 0, 0, m_chatWidth, 400);
    
    if (m_ollamaClient) {
        m_chatWindow->SetOllamaClient(m_ollamaClient.get());
    }
    
    // Fetch available models from Ollama
    // For now, add some common models
    std::vector<std::string> defaultModels = {
        "llama3.2:3b",
        "phi3:mini",
        "codellama:7b",
        "qwen2.5:14b"
    };
    m_chatWindow->SetAvailableModels(defaultModels);
    
    // Set initial file browser root
    m_fileBrowser->SetRootPath(".");
    
    // Initial layout
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    LayoutPanels(rc.right - rc.left, rc.bottom - rc.top);
}

void IDEWindow::OnSize(int width, int height) {
    // Send size to status bar
    SendMessage(m_hwndStatusBar, WM_SIZE, 0, 0);
    
    // Layout the panels
    LayoutPanels(width, height);
}

void IDEWindow::OnCommand(WPARAM wParam, LPARAM lParam) {
    int id = LOWORD(wParam);
    
    switch (id) {
        // File menu
        case 1000: {  // File > New
            SetWindowTextW(m_hwndEditor, L"");
            m_currentFile.clear();
            m_fileModified = false;
            SendMessage(m_hwndStatusBar, SB_SETTEXTW, 2, (LPARAM)L"New file");
            break;
        }
        
        case 1001: {  // File > Open
            wchar_t filename[MAX_PATH] = {};
            OPENFILENAMEW ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = m_hwnd;
            ofn.lpstrFile = filename;
            ofn.nMaxFile = MAX_PATH;
            ofn.lpstrFilter = L"All Files\0*.*\0Text Files\0*.txt\0Code Files\0*.cpp;*.h;*.hpp;*.c\0";
            ofn.Flags = OFN_FILEMUSTEXIST;
            
            if (GetOpenFileNameW(&ofn)) {
                // Read file
                std::wifstream file(filename);
                if (file) {
                    std::wstring content((std::istreambuf_iterator<wchar_t>(file)),
                                          std::istreambuf_iterator<wchar_t>());
                    SetWindowTextW(m_hwndEditor, content.c_str());
                    
                    char narrowPath[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, filename, -1, narrowPath, MAX_PATH, nullptr, nullptr);
                    m_currentFile = narrowPath;
                    m_fileModified = false;
                    
                    std::wstring status = L"Opened: " + std::wstring(filename);
                    SendMessage(m_hwndStatusBar, SB_SETTEXTW, 2, (LPARAM)status.c_str());
                }
            }
            break;
        }
        
        case 1002: {  // File > Save
            if (!m_currentFile.empty()) {
                int len = GetWindowTextLengthW(m_hwndEditor);
                std::wstring content(len + 1, L'\0');
                GetWindowTextW(m_hwndEditor, &content[0], len + 1);
                
                std::wofstream file(std::wstring(m_currentFile.begin(), m_currentFile.end()));
                if (file) {
                    file << content;
                    m_fileModified = false;
                    SendMessage(m_hwndStatusBar, SB_SETTEXTW, 0, (LPARAM)L"File saved");
                }
            }
            break;
        }
        
        case 1003:  // File > Exit
            PostQuitMessage(0);
            break;
            
        // View menu
        case 1100:  // View > File Browser
            m_showFileBrowser = !m_showFileBrowser;
            CheckMenuItem(GetMenu(m_hwnd), 1100, 
                m_showFileBrowser ? MF_CHECKED : MF_UNCHECKED);
            {
                RECT rc;
                GetClientRect(m_hwnd, &rc);
                LayoutPanels(rc.right - rc.left, rc.bottom - rc.top);
            }
            break;
            
        case 1101:  // View > Chat Panel
            m_showChat = !m_showChat;
            CheckMenuItem(GetMenu(m_hwnd), 1101,
                m_showChat ? MF_CHECKED : MF_UNCHECKED);
            {
                RECT rc;
                GetClientRect(m_hwnd, &rc);
                LayoutPanels(rc.right - rc.left, rc.bottom - rc.top);
            }
            break;
            
        // Help menu
        case 1200:  // Help > About
            MessageBoxW(m_hwnd, 
                L"RawrXD IDE v1.0\n"
                L"AI-Powered Development Environment\n\n"
                L"Features:\n"
                L"- Integrated Chat with Ollama\n"
                L"- File Browser\n"
                L"- Code Editor\n"
                L"- Model Selection\n\n"
                L"(c) 2026 RawrXD Team",
                L"About RawrXD IDE",
                MB_OK | MB_ICONINFORMATION);
            break;
    }
}

void IDEWindow::OnDestroy() {
    // Cleanup
    m_chatWindow.reset();
    m_fileBrowser.reset();
    PostQuitMessage(0);
}

void IDEWindow::OnFileSelected(const std::string& path) {
    // Check if file or directory
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        // Directory - navigate into it
        m_fileBrowser->SetRootPath(path);
    } else {
        // File - open in editor
        std::ifstream file(path);
        if (file) {
            std::string content((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
            
            // Convert to wide string
            int wlen = MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, nullptr, 0);
            std::wstring wcontent(wlen, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, content.c_str(), -1, &wcontent[0], wlen);
            
            SetWindowTextW(m_hwndEditor, wcontent.c_str());
            m_currentFile = path;
            m_fileModified = false;
            
            std::wstring status = L"Editing: " + std::wstring(path.begin(), path.end());
            SendMessage(m_hwndStatusBar, SB_SETTEXTW, 2, (LPARAM)status.c_str());
        }
    }
}

void IDEWindow::LayoutPanels(int width, int height) {
    if (!m_hwnd) return;
    
    // Get status bar height
    RECT rcStatus;
    GetWindowRect(m_hwndStatusBar, &rcStatus);
    int statusHeight = rcStatus.bottom - rcStatus.top;
    
    // Available client area
    int clientHeight = height - statusHeight;
    
    // Calculate positions
    int x = 0;
    int editorX = 0;
    int editorWidth = width;
    
    // File browser on left
    if (m_showFileBrowser && m_fileBrowser) {
        SetWindowPos(m_fileBrowser->GetHwnd(), nullptr,
            x, 0, m_fileBrowserWidth, clientHeight,
            SWP_NOZORDER | SWP_SHOWWINDOW);
        x += m_fileBrowserWidth + SPLITTER_WIDTH;
        editorX = x;
        editorWidth -= m_fileBrowserWidth + SPLITTER_WIDTH;
    } else if (m_fileBrowser) {
        ShowWindow(m_fileBrowser->GetHwnd(), SW_HIDE);
    }
    
    // Chat panel on right
    if (m_showChat && m_chatWindow) {
        editorWidth -= m_chatWidth + SPLITTER_WIDTH;
        SetWindowPos(m_chatWindow->GetHwnd(), nullptr,
            width - m_chatWidth, 0, m_chatWidth, clientHeight,
            SWP_NOZORDER | SWP_SHOWWINDOW);
    } else if (m_chatWindow) {
        ShowWindow(m_chatWindow->GetHwnd(), SW_HIDE);
    }
    
    // Editor in middle
    if (m_hwndEditor) {
        SetWindowPos(m_hwndEditor, nullptr,
            editorX, 0, editorWidth, clientHeight,
            SWP_NOZORDER);
    }
}

void IDEWindow::CreateMenuBar() {
    HMENU hMenu = CreateMenu();
    
    // File menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuW(hFileMenu, MF_STRING, 1000, L"&New\tCtrl+N");
    AppendMenuW(hFileMenu, MF_STRING, 1001, L"&Open...\tCtrl+O");
    AppendMenuW(hFileMenu, MF_STRING, 1002, L"&Save\tCtrl+S");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, 1003, L"E&xit\tAlt+F4");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");
    
    // View menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, 1100, L"&File Browser\tCtrl+Shift+F");
    AppendMenuW(hViewMenu, MF_STRING | MF_CHECKED, 1101, L"&Chat Panel\tCtrl+Shift+C");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hViewMenu, L"&View");
    
    // Help menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuW(hHelpMenu, MF_STRING, 1200, L"&About");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Help");
    
    SetMenu(m_hwnd, hMenu);
}

} // namespace GUI
} // namespace RawrXD
