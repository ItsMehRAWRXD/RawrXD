// RawrXD_Browser.h - Zero-Dependency Built-in Browser
// Pure Win32 implementation - no Qt, no external dependencies
// Target: HTTP/HTTPS, HTML parsing, basic CSS, text rendering

#ifndef RAWRXD_BROWSER_H
#define RAWRXD_BROWSER_H

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

// Link required libraries
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

namespace RawrXD {

// Forward declarations
class BrowserEngine;
class HTMLParser;
class CSSParser;
class LayoutEngine;
class Renderer;

// ============================================================================
// Core Types
// ============================================================================

struct Color {
    uint8_t r, g, b, a;
    Color(uint8_t r=0, uint8_t g=0, uint8_t b=0, uint8_t a=255) 
        : r(r), g(g), b(b), a(a) {}
    COLORREF ToCOLORREF() const { return RGB(r, g, b); }
};

struct Point { int x, y; };
struct Size { int width, height; };
struct Rect { int x, y, width, height; };

// ============================================================================
// DOM Node Types
// ============================================================================

enum class NodeType {
    DOCUMENT,
    ELEMENT,
    TEXT,
    COMMENT
};

class DOMNode : public std::enable_shared_from_this<DOMNode> {
public:
    NodeType type;
    std::string tagName;
    std::string textContent;
    std::vector<std::pair<std::string, std::string>> attributes;
    std::vector<std::shared_ptr<DOMNode>> children;
    std::weak_ptr<DOMNode> parent;
    
    // Layout properties (computed)
    Rect layoutRect;
    Color backgroundColor{255, 255, 255};
    Color textColor{0, 0, 0};
    int fontSize{16};
    bool isBlock{false};
    bool visible{true};
    
    DOMNode(NodeType t = NodeType::ELEMENT) : type(t) {}
    
    std::string GetAttribute(const std::string& name) const;
    void SetAttribute(const std::string& name, const std::string& value);
    std::shared_ptr<DOMNode> GetElementById(const std::string& id);
    std::vector<std::shared_ptr<DOMNode>> GetElementsByTagName(const std::string& tag);
};

// ============================================================================
// HTTP Response
// ============================================================================

struct HTTPResponse {
    int statusCode{0};
    std::string contentType;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
    bool success{false};
    std::string errorMessage;
};

// ============================================================================
// Network Engine - WinHTTP-based
// ============================================================================

class NetworkEngine {
public:
    NetworkEngine();
    ~NetworkEngine();
    
    bool Initialize();
    void Shutdown();
    
    HTTPResponse Get(const std::string& url);
    HTTPResponse Post(const std::string& url, const std::string& data, 
                      const std::string& contentType = "application/x-www-form-urlencoded");
    
    void SetTimeout(int connectMs, int sendMs, int receiveMs);
    void SetUserAgent(const std::string& ua);
    
private:
    HINTERNET hSession{nullptr};
    std::string userAgent{"RawrXD-Browser/1.0"};
    int connectTimeout{30000};
    int sendTimeout{30000};
    int receiveTimeout{60000};
    
    bool ParseURL(const std::string& url, std::wstring& host, 
                  std::wstring& path, int& port, bool& isHTTPS);
};

// ============================================================================
// HTML Parser - Minimal but functional
// ============================================================================

class HTMLParser {
public:
    HTMLParser();
    
    std::shared_ptr<DOMNode> Parse(const std::string& html);
    std::string ExtractText(const std::string& html);
    
private:
    size_t pos{0};
    std::string input;
    
    void SkipWhitespace();
    bool Match(const std::string& str);
    std::string ParseTagName();
    std::string ParseAttributeValue();
    void ParseAttributes(std::shared_ptr<DOMNode> node);
    std::shared_ptr<DOMNode> ParseElement();
    std::shared_ptr<DOMNode> ParseText();
    std::shared_ptr<DOMNode> ParseComment();
    std::shared_ptr<DOMNode> ParseNode();
};

// ============================================================================
// CSS Parser - Basic styling support
// ============================================================================

struct CSSRule {
    std::string selector;
    std::vector<std::pair<std::string, std::string>> declarations;
};

class CSSParser {
public:
    std::vector<CSSRule> Parse(const std::string& css);
    void ApplyStyles(std::shared_ptr<DOMNode> root, const std::vector<CSSRule>& rules);
};

// ============================================================================
// Layout Engine - Box model
// ============================================================================

class LayoutEngine {
public:
    LayoutEngine();
    
    void CalculateLayout(std::shared_ptr<DOMNode> root, int viewportWidth, int viewportHeight);
    std::shared_ptr<DOMNode> HitTest(std::shared_ptr<DOMNode> root, int x, int y);
    
    void SetDefaultFont(HFONT font) { defaultFont = font; }
    
private:
    HFONT defaultFont{nullptr};
    int currentY{0};
    int viewportW{800};
    int viewportH{600};
    
    void LayoutNode(std::shared_ptr<DOMNode> node, int x, int y, int availableWidth);
    int MeasureTextWidth(const std::string& text, HFONT font);
    int MeasureTextHeight(const std::string& text, int width, HFONT font);
};

// ============================================================================
// Renderer - GDI-based
// ============================================================================

class Renderer {
public:
    Renderer();
    ~Renderer();
    
    bool Initialize(HWND hwnd);
    void Resize(int width, int height);
    void Render(std::shared_ptr<DOMNode> root);
    void RenderToDC(HDC hdc, std::shared_ptr<DOMNode> root);
    
    void SetScrollOffset(int x, int y);
    Point GetScrollOffset() const { return {scrollX, scrollY}; }
    
    // Drawing primitives
    void DrawRect(const Rect& rect, Color fill, Color border, int borderWidth = 1);
    void DrawText(const std::string& text, const Rect& rect, Color color, 
                  int fontSize = 16, bool bold = false);
    void DrawImage(const Rect& rect, HBITMAP bitmap);
    
private:
    HWND hwnd{nullptr};
    HDC memDC{nullptr};
    HBITMAP memBitmap{nullptr};
    HBITMAP oldBitmap{nullptr};
    int width{800};
    int height{600};
    int scrollX{0};
    int scrollY{0};
    
    std::vector<HFONT> fontCache;
    
    HFONT GetFont(int size, bool bold);
    void RenderNode(HDC hdc, std::shared_ptr<DOMNode> node);
    void RenderElement(HDC hdc, std::shared_ptr<DOMNode> node);
    void RenderText(HDC hdc, std::shared_ptr<DOMNode> node);
};

// ============================================================================
// Main Browser Window
// ============================================================================

class BrowserWindow {
public:
    BrowserWindow();
    ~BrowserWindow();
    
    bool Create(int width = 1024, int height = 768, const std::string& title = "RawrXD Browser");
    void Show();
    void Hide();
    void Close();
    
    void Navigate(const std::string& url);
    void NavigateBack();
    void NavigateForward();
    void Reload();
    void Stop();
    
    void SetAddressBarText(const std::string& text);
    std::string GetAddressBarText() const;
    
    // JavaScript execution (minimal)
    std::string ExecuteJS(const std::string& script);
    
    // Event callbacks
    std::function<void(const std::string&)> onPageLoaded;
    std::function<void(const std::string&)> onNavigationStarted;
    std::function<void(const std::string&)> onError;
    std::function<void(const std::string&)> onLinkClicked;
    
    // Getters
    HWND GetHWND() const { return hwnd; }
    std::shared_ptr<DOMNode> GetDocument() const { return document; }
    std::string GetCurrentURL() const { return currentURL; }
    std::string GetPageTitle() const { return pageTitle; }
    
    // Static message handler
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
private:
    HWND hwnd{nullptr};
    HWND hwndAddressBar{nullptr};
    HWND hwndStatusBar{nullptr};
    HWND hwndToolbar{nullptr};
    
    std::unique_ptr<NetworkEngine> network;
    std::unique_ptr<HTMLParser> htmlParser;
    std::unique_ptr<CSSParser> cssParser;
    std::unique_ptr<LayoutEngine> layout;
    std::unique_ptr<Renderer> renderer;
    
    std::shared_ptr<DOMNode> document;
    std::string currentURL;
    std::string pageTitle{"RawrXD Browser"};
    std::vector<std::string> history;
    int historyIndex{-1};
    bool isLoading{false};
    
    // Window state
    bool isFullscreen{false};
    WINDOWPLACEMENT windowPlacement;
    
    void CreateControls();
    void LayoutControls();
    void LoadHTML(const std::string& html, const std::string& baseURL);
    void HandleLinkClick(const std::string& url);
    void UpdateTitle();
    void UpdateHistoryButtons();
    
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
};

// ============================================================================
// Browser Engine - High-level API
// ============================================================================

class BrowserEngine {
public:
    BrowserEngine();
    ~BrowserEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Create browser windows
    BrowserWindow* CreateWindow(int width = 1024, int height = 768);
    void DestroyWindow(BrowserWindow* window);
    
    // Message loop
    void RunMessageLoop();
    void ProcessMessages(); // Non-blocking
    void Quit();
    
    // Global settings
    void SetDefaultUserAgent(const std::string& ua);
    void EnableJavaScript(bool enable);
    void EnableCookies(bool enable);
    void SetProxy(const std::string& proxy);
    
private:
    std::vector<std::unique_ptr<BrowserWindow>> windows;
    std::string defaultUserAgent;
    bool jsEnabled{true};
    bool cookiesEnabled{true};
    bool running{false};
    
    static BrowserEngine* instance;
    static LRESULT CALLBACK GlobalWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace BrowserUtils {
    std::string WStringToString(const std::wstring& wstr);
    std::wstring StringToWString(const std::string& str);
    std::string URLEncode(const std::string& str);
    std::string URLDecode(const std::string& str);
    std::string GetBaseURL(const std::string& url);
    std::string ResolveURL(const std::string& base, const std::string& relative);
    bool IsAbsoluteURL(const std::string& url);
    std::string GetFileExtension(const std::string& path);
    std::string ToLower(const std::string& str);
    std::string Trim(const std::string& str);
    std::vector<std::string> Split(const std::string& str, char delimiter);
}

} // namespace RawrXD

#endif // RAWRXD_BROWSER_H
