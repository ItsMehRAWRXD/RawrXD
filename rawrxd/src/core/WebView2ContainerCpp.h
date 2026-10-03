#pragma once
#include "WebView2Container.h"
#include <string>

// C++ wrapper around the C WebView2Container API
class WebView2Container {
public:
    bool isReady() const { return m_ready; }

    void setReadyCallback(void (*cb)(void*), void* userData) {
        m_readyCb = cb; m_readyData = userData;
        WebView2Container_SetReadyCallback([](void* ud){ auto* self=static_cast<WebView2Container*>(ud); self->m_ready=true; if(self->m_readyCb) self->m_readyCb(self->m_readyData); }, this);
    }
    void setContentCallback(void (*cb)(const char*,unsigned int,void*), void* userData) {
        m_contentCb = cb; m_contentData = userData;
        WebView2Container_SetContentCallback(cb, userData);
    }
    void setCursorCallback(void (*cb)(int,int,void*), void* userData) {
        m_cursorCb = cb; m_cursorData = userData;
        WebView2Container_SetCursorCallback(cb, userData);
    }
    void setErrorCallback(void (*cb)(const char*,void*), void* userData) {
        m_errorCb = cb; m_errorData = userData;
        WebView2Container_SetErrorCallback(cb, userData);
    }

    WebView2Result initialize(void* hwnd) {
        WebView2Result r = WebView2Container_Initialize(hwnd, nullptr);
        m_hwnd = hwnd;
        return r;
    }
    void destroy() { WebView2Container_Destroy(); m_ready = false; }

    void resize(int x, int y, int w, int h) { WebView2Container_Resize(x,y,w,h); }
    void show() { WebView2Container_Show(); }
    void hide() { WebView2Container_Hide(); }

    WebView2Result setContent(const std::string& content, const std::string& lang) {
        (void)lang;
        return WebView2Container_SetContent(content.c_str(), nullptr);
    }
    void getContent() { WebView2Container_GetContent(); }

    WebView2Result setLanguage(const std::string& language) {
        return WebView2Container_SetLanguage(language.c_str());
    }
    WebView2Result setTheme(const std::string& theme) {
        return WebView2Container_SetTheme(theme.c_str());
    }
    WebView2Result setOptions(const MonacoEditorOptions& opts) {
        return WebView2Container_SetOptions(&opts);
    }
    WebView2Result insertText(const std::string& text) {
        return WebView2Container_InsertText(text.c_str());
    }
    WebView2Result revealLine(int line) {
        return WebView2Container_RevealLine(line);
    }
    WebView2Result setReadOnly(bool ro) {
        return WebView2Container_SetReadOnly(ro);
    }
    WebView2Result focus() {
        return WebView2Container_Focus();
    }
    WebView2Result executeScript(const std::string& js) {
        return WebView2Container_ExecuteScript(js.c_str());
    }

    // Stats stub
    struct Stats { int dummy = 0; };
    Stats getStats() const { return Stats{}; }

private:
    bool m_ready = false;
    void* m_hwnd = nullptr;
    void (*m_readyCb)(void*) = nullptr;
    void* m_readyData = nullptr;
    void (*m_contentCb)(const char*,unsigned int,void*) = nullptr;
    void* m_contentData = nullptr;
    void (*m_cursorCb)(int,int,void*) = nullptr;
    void* m_cursorData = nullptr;
    void (*m_errorCb)(const char*,void*) = nullptr;
    void* m_errorData = nullptr;
};
