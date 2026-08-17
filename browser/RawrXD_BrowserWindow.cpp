// RawrXD_BrowserWindow.cpp - Browser Window Implementation
// Win32 window creation and message handling

#include "RawrXD_Browser.h"
#include <string>

namespace RawrXD {

// Static member for window procedure
static BrowserWindow* g_currentWindow = nullptr;

// Window class name
static const wchar_t* BROWSER_CLASS_NAME = L"RawrXD_BrowserWindow";
static bool g_classRegistered = false;

// Control IDs
#define IDC_ADDRESS_BAR     1001
#define IDC_GO_BUTTON       1002
#define IDC_BACK_BUTTON     1003
#define IDC_FORWARD_BUTTON  1004
#define IDC_REFRESH_BUTTON  1005
#define IDC_STATUS_BAR      1006

// ============================================================================
// BrowserWindow Implementation
// ============================================================================

BrowserWindow::BrowserWindow() {
    network = std::make_unique<NetworkEngine>();
    htmlParser = std::make_unique<HTMLParser>();
    cssParser = std::make_unique<CSSParser>();
    layout = std::make_unique<LayoutEngine>();
    renderer = std::make_unique<Renderer>();
}

BrowserWindow::~BrowserWindow() {
    if (hwnd) {
        DestroyWindow(hwnd);
    }
}

LRESULT CALLBACK BrowserWindow::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    BrowserWindow* window = nullptr;
    
    if (msg == WM_CREATE) {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        window = reinterpret_cast<BrowserWindow*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(window));
        g_currentWindow = window;
    } else {
        window = reinterpret_cast<BrowserWindow*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (window) {
        return window->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT BrowserWindow::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            CreateControls();
            network->Initialize();
            return 0;
            
        case WM_SIZE:
            LayoutControls();
            if (document) {
                RECT clientRect;
                GetClientRect(hwnd, &clientRect);
                int contentHeight = clientRect.bottom - 60; // Account for toolbar
                renderer->Resize(clientRect.right, contentHeight);
                layout->CalculateLayout(document, clientRect.right, contentHeight);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
            
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Render document
            if (document) {
                renderer->Render(document);
            }
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            int notifyCode = HIWORD(wParam);
            
            switch (id) {
                case IDC_GO_BUTTON:
                case IDC_ADDRESS_BAR:
                    if (id == IDC_GO_BUTTON || notifyCode == EN_RETURN) {
                        char url[2048];
                        GetWindowTextA(hwndAddressBar, url, sizeof(url));
                        Navigate(std::string(url));
                    }
                    return 0;
                    
                case IDC_BACK_BUTTON:
                    NavigateBack();
                    return 0;
                    
                case IDC_FORWARD_BUTTON:
                    NavigateForward();
                    return 0;
                    
                case IDC_REFRESH_BUTTON:
                    Reload();
                    return 0;
            }
            return 0;
        }
        
        case WM_LBUTTONDOWN: {
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            
            // Adjust for toolbar
            y -= 40;
            
            if (document && y > 0) {
                auto node = layout->HitTest(document, x + renderer->GetScrollOffset().x, 
                                               y + renderer->GetScrollOffset().y);
                if (node) {
                    std::string href = node->GetAttribute("href");
                    if (!href.empty()) {
                        HandleLinkClick(href);
                    }
                }
            }
            return 0;
        }
        
        case WM_MOUSEWHEEL: {
            int delta = GET_WHEEL_DELTA_WPARAM(wParam);
            auto offset = renderer->GetScrollOffset();
            offset.y -= delta / 4;
            if (offset.y < 0) offset.y = 0;
            renderer->SetScrollOffset(offset.x, offset.y);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        
        case WM_KEYDOWN:
            if (wParam == VK_F5) {
                Reload();
                return 0;
            }
            if (wParam == VK_ESCAPE) {
                Stop();
                return 0;
            }
            return 0;
            
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
            
        case WM_DESTROY:
            hwnd = nullptr;
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

bool BrowserWindow::Create(int width, int height, const std::string& title) {
    HINSTANCE hInstance = GetModuleHandle(nullptr);
    
    // Register window class if not already done
    if (!g_classRegistered) {
        WNDCLASSEXW wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = BROWSER_CLASS_NAME;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        
        if (!RegisterClassExW(&wc)) {
            return false;
        }
        g_classRegistered = true;
    }
    
    // Create window
    std::wstring wtitle = BrowserUtils::StringToWString(title);
    
    hwnd = CreateWindowExW(
        0,
        BROWSER_CLASS_NAME,
        wtitle.c_str(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        width, height,
        nullptr, nullptr,
        hInstance,
        this
    );
    
    if (!hwnd) {
        return false;
    }
    
    // Initialize renderer
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    renderer->Initialize(hwnd);
    
    return true;
}

void BrowserWindow::CreateControls() {
    HINSTANCE hInstance = GetModuleHandle(nullptr);
    
    // Create toolbar
    hwndToolbar = CreateWindowExW(0, L"STATIC", nullptr,
                                   WS_CHILD | WS_VISIBLE | SS_BLACKRECT,
                                   0, 0, 0, 40, hwnd, nullptr, hInstance, nullptr);
    
    // Back button
    HWND hwndBack = CreateWindowExW(0, L"BUTTON", L"<",
                                     WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                     5, 8, 30, 24, hwnd, (HMENU)IDC_BACK_BUTTON, hInstance, nullptr);
    
    // Forward button
    HWND hwndForward = CreateWindowExW(0, L"BUTTON", L">",
                                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        40, 8, 30, 24, hwnd, (HMENU)IDC_FORWARD_BUTTON, hInstance, nullptr);
    
    // Refresh button
    HWND hwndRefresh = CreateWindowExW(0, L"BUTTON", L"↻",
                                         WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                         75, 8, 30, 24, hwnd, (HMENU)IDC_REFRESH_BUTTON, hInstance, nullptr);
    
    // Address bar
    hwndAddressBar = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                      110, 8, 0, 24, hwnd, (HMENU)IDC_ADDRESS_BAR, hInstance, nullptr);
    
    // Go button
    HWND hwndGo = CreateWindowExW(0, L"BUTTON", L"Go",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   0, 8, 50, 24, hwnd, (HMENU)IDC_GO_BUTTON, hInstance, nullptr);
    
    // Status bar
    hwndStatusBar = CreateWindowExW(0, L"STATIC", L"Ready",
                                       WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
                                       0, 0, 0, 20, hwnd, (HMENU)IDC_STATUS_BAR, hInstance, nullptr);
    
    // Set font for controls
    HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    
    SendMessage(hwndAddressBar, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hwndStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);
}

void BrowserWindow::LayoutControls() {
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int width = clientRect.right;
    int height = clientRect.bottom;
    
    // Position address bar
    SetWindowPos(hwndAddressBar, nullptr, 110, 8, width - 170, 24, SWP_NOZORDER);
    
    // Position Go button
    HWND hwndGo = GetDlgItem(hwnd, IDC_GO_BUTTON);
    SetWindowPos(hwndGo, nullptr, width - 55, 8, 50, 24, SWP_NOZORDER);
    
    // Position status bar at bottom
    SetWindowPos(hwndStatusBar, nullptr, 0, height - 20, width, 20, SWP_NOZORDER);
}

void BrowserWindow::Show() {
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
}

void BrowserWindow::Hide() {
    ShowWindow(hwnd, SW_HIDE);
}

void BrowserWindow::Close() {
    if (hwnd) {
        DestroyWindow(hwnd);
        hwnd = nullptr;
    }
}

void BrowserWindow::Navigate(const std::string& url) {
    if (url.empty()) return;
    
    std::string fullURL = url;
    if (!BrowserUtils::IsAbsoluteURL(url)) {
        // Add https:// if no protocol specified
        fullURL = "https://" + url;
    }
    
    currentURL = fullURL;
    SetAddressBarText(fullURL);
    
    if (onNavigationStarted) {
        onNavigationStarted(fullURL);
    }
    
    isLoading = true;
    SetWindowTextA(hwndStatusBar, "Loading...");
    
    // Fetch page
    HTTPResponse response = network->Get(fullURL);
    
    isLoading = false;
    
    if (response.success) {
        LoadHTML(response.body, fullURL);
        
        // Add to history
        if (historyIndex < 0 || history[historyIndex] != fullURL) {
            // Remove forward history
            if (historyIndex + 1 < static_cast<int>(history.size())) {
                history.resize(historyIndex + 1);
            }
            history.push_back(fullURL);
            historyIndex++;
        }
        
        UpdateHistoryButtons();
        
        if (onPageLoaded) {
            onPageLoaded(fullURL);
        }
        
        SetWindowTextA(hwndStatusBar, "Done");
    } else {
        std::string errorHTML = "<html><body><h1>Error</h1><p>" + 
                                response.errorMessage + "</p></body></html>";
        LoadHTML(errorHTML, fullURL);
        
        if (onError) {
            onError(response.errorMessage);
        }
        
        SetWindowTextA(hwndStatusBar, "Error loading page");
    }
}

void BrowserWindow::NavigateBack() {
    if (historyIndex > 0) {
        historyIndex--;
        std::string url = history[historyIndex];
        currentURL = url;
        SetAddressBarText(url);
        
        HTTPResponse response = network->Get(url);
        if (response.success) {
            LoadHTML(response.body, url);
        }
        
        UpdateHistoryButtons();
    }
}

void BrowserWindow::NavigateForward() {
    if (historyIndex + 1 < static_cast<int>(history.size())) {
        historyIndex++;
        std::string url = history[historyIndex];
        currentURL = url;
        SetAddressBarText(url);
        
        HTTPResponse response = network->Get(url);
        if (response.success) {
            LoadHTML(response.body, url);
        }
        
        UpdateHistoryButtons();
    }
}

void BrowserWindow::Reload() {
    if (!currentURL.empty()) {
        Navigate(currentURL);
    }
}

void BrowserWindow::Stop() {
    // TODO: Cancel pending requests
    isLoading = false;
    SetWindowTextA(hwndStatusBar, "Stopped");
}

void BrowserWindow::LoadHTML(const std::string& html, const std::string& baseURL) {
    // Parse HTML
    document = htmlParser->Parse(html);
    
    // Extract title
    auto titleElements = document->GetElementsByTagName("title");
    if (!titleElements.empty() && !titleElements[0]->children.empty()) {
        pageTitle = titleElements[0]->children[0]->textContent;
    } else {
        pageTitle = baseURL;
    }
    
    UpdateTitle();
    
    // Calculate layout
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);
    int contentWidth = clientRect.right;
    int contentHeight = clientRect.bottom - 60;
    
    renderer->Resize(contentWidth, contentHeight);
    layout->CalculateLayout(document, contentWidth, contentHeight);
    
    // Render
    InvalidateRect(hwnd, nullptr, FALSE);
}

void BrowserWindow::HandleLinkClick(const std::string& url) {
    std::string resolvedURL = BrowserUtils::ResolveURL(currentURL, url);
    
    if (onLinkClicked) {
        onLinkClicked(resolvedURL);
    }
    
    Navigate(resolvedURL);
}

void BrowserWindow::UpdateTitle() {
    std::string title = pageTitle + " - RawrXD Browser";
    SetWindowTextA(hwnd, title.c_str());
}

void BrowserWindow::UpdateHistoryButtons() {
    HWND hwndBack = GetDlgItem(hwnd, IDC_BACK_BUTTON);
    HWND hwndForward = GetDlgItem(hwnd, IDC_FORWARD_BUTTON);
    
    EnableWindow(hwndBack, historyIndex > 0);
    EnableWindow(hwndForward, historyIndex + 1 < static_cast<int>(history.size()));
}

void BrowserWindow::SetAddressBarText(const std::string& text) {
    SetWindowTextA(hwndAddressBar, text.c_str());
}

std::string BrowserWindow::GetAddressBarText() const {
    char buffer[2048];
    GetWindowTextA(hwndAddressBar, buffer, sizeof(buffer));
    return std::string(buffer);
}

std::string BrowserWindow::ExecuteJS(const std::string& script) {
    // TODO: Implement JavaScript execution
    return "";
}

} // namespace RawrXD
