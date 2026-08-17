// RawrXD_Browser.cpp - Zero-Dependency Built-in Browser Implementation
// Pure Win32 implementation - no Qt, no external dependencies

#include "RawrXD_Browser.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RawrXD {

// ============================================================================
// BrowserUtils Implementation
// ============================================================================

namespace BrowserUtils {

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], size);
    return result;
}

std::string URLEncode(const std::string& str) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    
    for (char c : str) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
            escaped << std::nouppercase;
        }
    }
    return escaped.str();
}

std::string URLDecode(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int hex = std::stoi(str.substr(i + 1, 2), nullptr, 16);
            result += static_cast<char>(hex);
            i += 2;
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

std::string GetBaseURL(const std::string& url) {
    size_t protocolEnd = url.find("://");
    if (protocolEnd == std::string::npos) return url;
    
    size_t pathStart = url.find('/', protocolEnd + 3);
    if (pathStart == std::string::npos) return url;
    
    return url.substr(0, pathStart);
}

std::string ResolveURL(const std::string& base, const std::string& relative) {
    if (IsAbsoluteURL(relative)) return relative;
    
    if (relative.empty()) return base;
    if (relative[0] == '/') {
        // Absolute path
        size_t protocolEnd = base.find("://");
        if (protocolEnd == std::string::npos) return relative;
        size_t hostEnd = base.find('/', protocolEnd + 3);
        if (hostEnd == std::string::npos) return base + relative;
        return base.substr(0, hostEnd) + relative;
    }
    
    // Relative path
    size_t lastSlash = base.rfind('/');
    if (lastSlash == std::string::npos || lastSlash < base.find("://") + 3) {
        return base + "/" + relative;
    }
    return base.substr(0, lastSlash + 1) + relative;
}

bool IsAbsoluteURL(const std::string& url) {
    return url.find("://") != std::string::npos || url.find("//") == 0;
}

std::string GetFileExtension(const std::string& path) {
    size_t dot = path.rfind('.');
    if (dot == std::string::npos) return "";
    size_t slash = path.rfind('/');
    if (slash != std::string::npos && dot < slash) return "";
    return ToLower(path.substr(dot + 1));
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), 
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string Trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> Split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

} // namespace BrowserUtils

// ============================================================================
// DOMNode Implementation
// ============================================================================

std::string DOMNode::GetAttribute(const std::string& name) const {
    for (const auto& attr : attributes) {
        if (BrowserUtils::ToLower(attr.first) == BrowserUtils::ToLower(name)) {
            return attr.second;
        }
    }
    return "";
}

void DOMNode::SetAttribute(const std::string& name, const std::string& value) {
    for (auto& attr : attributes) {
        if (BrowserUtils::ToLower(attr.first) == BrowserUtils::ToLower(name)) {
            attr.second = value;
            return;
        }
    }
    attributes.push_back({name, value});
}

std::shared_ptr<DOMNode> DOMNode::GetElementById(const std::string& id) {
    if (GetAttribute("id") == id) {
        return shared_from_this();
    }
    for (auto& child : children) {
        auto result = child->GetElementById(id);
        if (result) return result;
    }
    return nullptr;
}

std::vector<std::shared_ptr<DOMNode>> DOMNode::GetElementsByTagName(const std::string& tag) {
    std::vector<std::shared_ptr<DOMNode>> results;
    std::string lowerTag = BrowserUtils::ToLower(tag);
    
    if (BrowserUtils::ToLower(tagName) == lowerTag) {
        results.push_back(shared_from_this());
    }
    
    for (auto& child : children) {
        auto childResults = child->GetElementsByTagName(tag);
        results.insert(results.end(), childResults.begin(), childResults.end());
    }
    
    return results;
}

// ============================================================================
// NetworkEngine Implementation
// ============================================================================

NetworkEngine::NetworkEngine() = default;

NetworkEngine::~NetworkEngine() {
    Shutdown();
}

bool NetworkEngine::Initialize() {
    hSession = WinHttpOpen(
        BrowserUtils::StringToWString(userAgent).c_str(),
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    return hSession != nullptr;
}

void NetworkEngine::Shutdown() {
    if (hSession) {
        WinHttpCloseHandle(hSession);
        hSession = nullptr;
    }
}

bool NetworkEngine::ParseURL(const std::string& url, std::wstring& host, 
                               std::wstring& path, int& port, bool& isHTTPS) {
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    
    wchar_t hostName[256] = {0};
    wchar_t urlPath[2048] = {0};
    
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = ARRAYSIZE(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = ARRAYSIZE(urlPath);
    
    std::wstring wurl = BrowserUtils::StringToWString(url);
    
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComp)) {
        return false;
    }
    
    host = hostName;
    path = urlPath;
    if (path.empty()) path = L"/";
    port = urlComp.nPort;
    isHTTPS = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
    
    return true;
}

HTTPResponse NetworkEngine::Get(const std::string& url) {
    HTTPResponse response;
    
    if (!hSession && !Initialize()) {
        response.errorMessage = "Failed to initialize WinHTTP";
        return response;
    }
    
    std::wstring host, path;
    int port;
    bool isHTTPS;
    
    if (!ParseURL(url, host, path, port, isHTTPS)) {
        response.errorMessage = "Failed to parse URL: " + url;
        return response;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        response.errorMessage = "Failed to connect to host";
        return response;
    }
    
    DWORD flags = isHTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), 
                                               nullptr, WINHTTP_NO_REFERER, 
                                               WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        response.errorMessage = "Failed to open request";
        return response;
    }
    
    // Set timeouts
    WinHttpSetTimeouts(hRequest, connectTimeout, connectTimeout, sendTimeout, receiveTimeout);
    
    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        response.errorMessage = "Failed to send request";
        return response;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        response.errorMessage = "Failed to receive response";
        return response;
    }
    
    // Get status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    response.statusCode = static_cast<int>(statusCode);
    
    // Get content type
    wchar_t contentType[256] = {0};
    size = ARRAYSIZE(contentType) * sizeof(wchar_t);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_TYPE,
                        WINHTTP_HEADER_NAME_BY_INDEX, contentType, &size, WINHTTP_NO_HEADER_INDEX);
    response.contentType = BrowserUtils::WStringToString(contentType);
    
    // Read response body
    std::string body;
    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<char> buffer(bytesAvailable + 1);
        DWORD bytesRead = 0;
        if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
            body.append(buffer.data(), bytesRead);
        }
    }
    response.body = body;
    response.success = (response.statusCode >= 200 && response.statusCode < 300);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    
    return response;
}

HTTPResponse NetworkEngine::Post(const std::string& url, const std::string& data,
                                  const std::string& contentType) {
    HTTPResponse response;
    // TODO: Implement POST
    response.errorMessage = "POST not yet implemented";
    return response;
}

void NetworkEngine::SetTimeout(int connectMs, int sendMs, int receiveMs) {
    connectTimeout = connectMs;
    sendTimeout = sendMs;
    receiveTimeout = receiveMs;
}

void NetworkEngine::SetUserAgent(const std::string& ua) {
    userAgent = ua;
}

// ============================================================================
// HTMLParser Implementation
// ============================================================================

HTMLParser::HTMLParser() = default;

void HTMLParser::SkipWhitespace() {
    while (pos < input.length() && isspace(static_cast<unsigned char>(input[pos]))) {
        ++pos;
    }
}

bool HTMLParser::Match(const std::string& str) {
    if (pos + str.length() > input.length()) return false;
    return input.compare(pos, str.length(), str) == 0;
}

std::string HTMLParser::ParseTagName() {
    SkipWhitespace();
    size_t start = pos;
    while (pos < input.length() && 
           (isalnum(static_cast<unsigned char>(input[pos])) || input[pos] == '-' || input[pos] == '_')) {
        ++pos;
    }
    return input.substr(start, pos - start);
}

std::string HTMLParser::ParseAttributeValue() {
    SkipWhitespace();
    if (pos >= input.length()) return "";
    
    char quote = input[pos];
    if (quote == '"' || quote == '\'') {
        ++pos;
        size_t start = pos;
        while (pos < input.length() && input[pos] != quote) {
            ++pos;
        }
        std::string value = input.substr(start, pos - start);
        if (pos < input.length()) ++pos; // Skip closing quote
        return value;
    } else {
        // Unquoted value
        size_t start = pos;
        while (pos < input.length() && 
               !isspace(static_cast<unsigned char>(input[pos])) && 
               input[pos] != '>') {
            ++pos;
        }
        return input.substr(start, pos - start);
    }
}

void HTMLParser::ParseAttributes(std::shared_ptr<DOMNode> node) {
    while (pos < input.length() && input[pos] != '>' && !Match("/>")) {
        SkipWhitespace();
        if (pos >= input.length() || input[pos] == '>' || Match("/>")) break;
        
        std::string name = ParseTagName();
        if (name.empty()) break;
        
        SkipWhitespace();
        std::string value;
        if (Match("=")) {
            pos++;
            value = ParseAttributeValue();
        }
        
        node->SetAttribute(name, value);
    }
}

std::shared_ptr<DOMNode> HTMLParser::ParseElement() {
    if (!Match("<")) return nullptr;
    pos++;
    
    std::string tagName = ParseTagName();
    if (tagName.empty()) return nullptr;
    
    auto node = std::make_shared<DOMNode>(NodeType::ELEMENT);
    node->tagName = BrowserUtils::ToLower(tagName);
    
    ParseAttributes(node);
    
    SkipWhitespace();
    bool selfClosing = Match("/>");
    if (selfClosing) {
        pos += 2;
        return node;
    }
    
    if (Match(">")) {
        pos++;
    }
    
    // Parse children
    while (pos < input.length() && !Match("</")) {
        auto child = ParseNode();
        if (child) {
            child->parent = node;
            node->children.push_back(child);
        }
    }
    
    // Parse closing tag
    if (Match("</")) {
        pos += 2;
        std::string closeTag = ParseTagName();
        SkipWhitespace();
        if (Match(">")) pos++;
    }
    
    return node;
}

std::shared_ptr<DOMNode> HTMLParser::ParseText() {
    size_t start = pos;
    while (pos < input.length() && input[pos] != '<') {
        ++pos;
    }
    
    std::string text = input.substr(start, pos - start);
    text = BrowserUtils::Trim(text);
    
    if (text.empty()) return nullptr;
    
    auto node = std::make_shared<DOMNode>(NodeType::TEXT);
    node->textContent = text;
    return node;
}

std::shared_ptr<DOMNode> HTMLParser::ParseComment() {
    if (!Match("<!--")) return nullptr;
    pos += 4;
    
    size_t end = input.find("-->", pos);
    if (end == std::string::npos) {
        pos = input.length();
        return nullptr;
    }
    
    pos = end + 3;
    return nullptr; // Comments are ignored
}

std::shared_ptr<DOMNode> HTMLParser::ParseNode() {
    if (Match("<!--")) {
        return ParseComment();
    }
    if (Match("<")) {
        return ParseElement();
    }
    return ParseText();
}

std::shared_ptr<DOMNode> HTMLParser::Parse(const std::string& html) {
    input = html;
    pos = 0;
    
    auto document = std::make_shared<DOMNode>(NodeType::DOCUMENT);
    document->tagName = "#document";
    
    while (pos < input.length()) {
        auto node = ParseNode();
        if (node) {
            node->parent = document;
            document->children.push_back(node);
        }
    }
    
    return document;
}

std::string HTMLParser::ExtractText(const std::string& html) {
    std::string text;
    size_t pos = 0;
    
    while (pos < html.length()) {
        // Skip tags
        if (html[pos] == '<') {
            size_t end = html.find('>', pos);
            if (end == std::string::npos) break;
            pos = end + 1;
            continue;
        }
        
        // Collect text
        size_t start = pos;
        while (pos < html.length() && html[pos] != '<') {
            ++pos;
        }
        text += html.substr(start, pos - start);
    }
    
    return BrowserUtils::Trim(text);
}

// ============================================================================
// CSSParser Implementation
// ============================================================================

std::vector<CSSRule> CSSParser::Parse(const std::string& css) {
    std::vector<CSSRule> rules;
    // TODO: Implement CSS parsing
    return rules;
}

void CSSParser::ApplyStyles(std::shared_ptr<DOMNode> root, const std::vector<CSSRule>& rules) {
    // TODO: Apply CSS styles to DOM
}

// ============================================================================
// LayoutEngine Implementation
// ============================================================================

LayoutEngine::LayoutEngine() = default;

void LayoutEngine::CalculateLayout(std::shared_ptr<DOMNode> root, int viewportWidth, int viewportHeight) {
    viewportW = viewportWidth;
    viewportH = viewportHeight;
    currentY = 0;
    
    if (root) {
        LayoutNode(root, 0, 0, viewportWidth);
    }
}

void LayoutEngine::LayoutNode(std::shared_ptr<DOMNode> node, int x, int y, int availableWidth) {
    if (!node->visible) return;
    
    // Block-level elements
    static const std::vector<std::string> blockElements = {
        "div", "p", "h1", "h2", "h3", "h4", "h5", "h6", 
        "ul", "ol", "li", "section", "article", "header", "footer"
    };
    
    bool isBlock = std::find(blockElements.begin(), blockElements.end(), 
                              BrowserUtils::ToLower(node->tagName)) != blockElements.end();
    
    if (node->type == NodeType::TEXT) {
        // Text layout
        HDC hdc = GetDC(nullptr);
        HFONT font = CreateFont(node->fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT oldFont = (HFONT)SelectObject(hdc, font);
        
        RECT rect = {x, y, x + availableWidth, y + 1000};
        DrawTextA(hdc, node->textContent.c_str(), -1, &rect, 
                  DT_LEFT | DT_TOP | DT_WORDBREAK | DT_CALCRECT);
        
        node->layoutRect = {x, y, rect.right - rect.left, rect.bottom - rect.top};
        
        SelectObject(hdc, oldFont);
        DeleteObject(font);
        ReleaseDC(nullptr, hdc);
        
        currentY = y + node->layoutRect.height;
    } else if (node->type == NodeType::ELEMENT) {
        // Element layout
        if (isBlock) {
            node->layoutRect = {x, y, availableWidth, 0};
            int childY = y + 10; // Padding
            
            for (auto& child : node->children) {
                LayoutNode(child, x + 10, childY, availableWidth - 20);
                if (child->visible) {
                    childY += child->layoutRect.height + 5;
                }
            }
            
            node->layoutRect.height = childY - y + 10;
            currentY = y + node->layoutRect.height;
        } else {
            // Inline elements
            int childX = x;
            int maxHeight = 0;
            
            for (auto& child : node->children) {
                LayoutNode(child, childX, y, availableWidth - (childX - x));
                if (child->visible) {
                    childX += child->layoutRect.width + 5;
                    maxHeight = std::max(maxHeight, child->layoutRect.height);
                }
            }
            
            node->layoutRect = {x, y, childX - x, maxHeight};
        }
    }
}

std::shared_ptr<DOMNode> LayoutEngine::HitTest(std::shared_ptr<DOMNode> root, int x, int y) {
    // TODO: Implement hit testing
    return nullptr;
}

int LayoutEngine::MeasureTextWidth(const std::string& text, HFONT font) {
    HDC hdc = GetDC(nullptr);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    SIZE size;
    GetTextExtentPoint32A(hdc, text.c_str(), static_cast<int>(text.length()), &size);
    SelectObject(hdc, oldFont);
    ReleaseDC(nullptr, hdc);
    return size.cx;
}

int LayoutEngine::MeasureTextHeight(const std::string& text, int width, HFONT font) {
    HDC hdc = GetDC(nullptr);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    RECT rect = {0, 0, width, 10000};
    DrawTextA(hdc, text.c_str(), -1, &rect, DT_LEFT | DT_TOP | DT_WORDBREAK | DT_CALCRECT);
    SelectObject(hdc, oldFont);
    ReleaseDC(nullptr, hdc);
    return rect.bottom;
}

// ============================================================================
// Renderer Implementation
// ============================================================================

Renderer::Renderer() = default;

Renderer::~Renderer() {
    if (memDC && oldBitmap) {
        SelectObject(memDC, oldBitmap);
    }
    if (memBitmap) DeleteObject(memBitmap);
    if (memDC) DeleteDC(memDC);
    
    for (auto font : fontCache) {
        DeleteObject(font);
    }
}

bool Renderer::Initialize(HWND hwnd) {
    this->hwnd = hwnd;
    
    HDC hdc = GetDC(hwnd);
    memDC = CreateCompatibleDC(hdc);
    
    RECT rect;
    GetClientRect(hwnd, &rect);
    width = rect.right - rect.left;
    height = rect.bottom - rect.top;
    
    memBitmap = CreateCompatibleBitmap(hdc, width, height);
    oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);
    
    ReleaseDC(hwnd, hdc);
    
    // Clear to white
    PatBlt(memDC, 0, 0, width, height, WHITENESS);
    
    return true;
}

void Renderer::Resize(int newWidth, int newHeight) {
    if (newWidth == width && newHeight == height) return;
    
    width = newWidth;
    height = newHeight;
    
    if (memDC && oldBitmap) {
        SelectObject(memDC, oldBitmap);
    }
    if (memBitmap) DeleteObject(memBitmap);
    
    HDC hdc = GetDC(hwnd);
    memBitmap = CreateCompatibleBitmap(hdc, width, height);
    oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);
    ReleaseDC(hwnd, hdc);
    
    PatBlt(memDC, 0, 0, width, height, WHITENESS);
}

void Renderer::SetScrollOffset(int x, int y) {
    scrollX = x;
    scrollY = y;
}

HFONT Renderer::GetFont(int size, bool bold) {
    int weight = bold ? FW_BOLD : FW_NORMAL;
    HFONT font = CreateFont(size, 0, 0, 0, weight, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    fontCache.push_back(font);
    return font;
}

void Renderer::Render(std::shared_ptr<DOMNode> root) {
    if (!memDC) return;
    
    // Clear background
    PatBlt(memDC, 0, 0, width, height, WHITENESS);
    
    if (root) {
        RenderNode(memDC, root);
    }
    
    // Copy to screen
    HDC hdc = GetDC(hwnd);
    BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);
    ReleaseDC(hwnd, hdc);
}

void Renderer::RenderToDC(HDC hdc, std::shared_ptr<DOMNode> root) {
    if (root) {
        RenderNode(hdc, root);
    }
}

void Renderer::RenderNode(HDC hdc, std::shared_ptr<DOMNode> node) {
    if (!node->visible) return;
    
    if (node->type == NodeType::ELEMENT) {
        RenderElement(hdc, node);
    } else if (node->type == NodeType::TEXT) {
        RenderText(hdc, node);
    }
}

void Renderer::RenderElement(HDC hdc, std::shared_ptr<DOMNode> node) {
    const Rect& rect = node->layoutRect;
    
    // Draw background
    if (node->backgroundColor.r != 255 || node->backgroundColor.g != 255 || 
        node->backgroundColor.b != 255) {
        HBRUSH brush = CreateSolidBrush(node->backgroundColor.ToCOLORREF());
        RECT fillRect = {rect.x - scrollX, rect.y - scrollY, 
                        rect.x + rect.width - scrollX, rect.y + rect.height - scrollY};
        FillRect(hdc, &fillRect, brush);
        DeleteObject(brush);
    }
    
    // Render children
    for (auto& child : node->children) {
        RenderNode(hdc, child);
    }
}

void Renderer::RenderText(HDC hdc, std::shared_ptr<DOMNode> node) {
    const Rect& rect = node->layoutRect;
    
    HFONT font = GetFont(node->fontSize, false);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    SetTextColor(hdc, node->textColor.ToCOLORREF());
    SetBkMode(hdc, TRANSPARENT);
    
    RECT textRect = {rect.x - scrollX, rect.y - scrollY,
                     rect.x + rect.width - scrollX, rect.y + rect.height - scrollY};
    
    DrawTextA(hdc, node->textContent.c_str(), -1, &textRect, 
              DT_LEFT | DT_TOP | DT_WORDBREAK);
    
    SelectObject(hdc, oldFont);
}

void Renderer::DrawRect(const Rect& rect, Color fill, Color border, int borderWidth) {
    if (!memDC) return;
    
    // Fill
    HBRUSH fillBrush = CreateSolidBrush(fill.ToCOLORREF());
    RECT fillRect = {rect.x, rect.y, rect.x + rect.width, rect.y + rect.height};
    FillRect(memDC, &fillRect, fillBrush);
    DeleteObject(fillBrush);
    
    // Border
    if (borderWidth > 0) {
        HPEN pen = CreatePen(PS_SOLID, borderWidth, border.ToCOLORREF());
        HPEN oldPen = (HPEN)SelectObject(memDC, pen);
        HBRUSH oldBrush = (HBRUSH)SelectObject(memDC, GetStockObject(NULL_BRUSH));
        
        Rectangle(memDC, rect.x, rect.y, rect.x + rect.width, rect.y + rect.height);
        
        SelectObject(memDC, oldPen);
        SelectObject(memDC, oldBrush);
        DeleteObject(pen);
    }
}

void Renderer::DrawText(const std::string& text, const Rect& rect, Color color, 
                        int fontSize, bool bold) {
    if (!memDC) return;
    
    HFONT font = GetFont(fontSize, bold);
    HFONT oldFont = (HFONT)SelectObject(memDC, font);
    SetTextColor(memDC, color.ToCOLORREF());
    SetBkMode(memDC, TRANSPARENT);
    
    RECT textRect = {rect.x, rect.y, rect.x + rect.width, rect.y + rect.height};
    DrawTextA(memDC, text.c_str(), -1, &textRect, DT_LEFT | DT_TOP | DT_WORDBREAK);
    
    SelectObject(memDC, oldFont);
}

void Renderer::DrawImage(const Rect& rect, HBITMAP bitmap) {
    // TODO: Implement image rendering
}

} // namespace RawrXD
