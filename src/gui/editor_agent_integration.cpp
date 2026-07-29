<<<<<<< HEAD
// ============================================================================
// editor_agent_integration.cpp — Pure Win32 Native Editor Agent Integration
// ============================================================================
// Ghost text suggestions triggered by TAB key, acceptance via ENTER,
// rendering semi-transparent overlay. Subclasses editor HWND for input.
//
// Pattern: PatchResult-style structured results, no exceptions
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#include "editor_agent_integration.hpp"
#include <commctrl.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "comctl32.lib")

// ============================================================================
// Constants
// ============================================================================

static constexpr COLORREF GHOST_TEXT_CLR  = RGB(102, 102, 102);
static constexpr COLORREF GHOST_BG_CLR   = RGB(40, 40, 40);
static constexpr COLORREF ACCENT_CLR     = RGB(86, 156, 214);
static constexpr COLORREF BADGE_BG       = RGB(50, 50, 55);
static constexpr COLORREF BADGE_TEXT      = RGB(78, 201, 176);

static const wchar_t* OVERLAY_CLASS = L"RawrXD_GhostTextOverlay";
bool EditorAgentIntegration::s_overlayClassRegistered = false;

#define IDT_AUTO_SUGGEST 3001
#define SUBCLASS_ID      42

// ============================================================================
// Constructor / Destructor
// ============================================================================

EditorAgentIntegration::EditorAgentIntegration(HWND editorHwnd)
    : m_editorHwnd(editorHwnd)
{
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(editorHwnd, GWLP_HINSTANCE);
    if (!hInst) hInst = GetModuleHandle(nullptr);

    // Create fonts
    m_ghostFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, TRUE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH, L"Consolas");
    m_normalFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH, L"Consolas");

    // Register overlay class
    if (!s_overlayClassRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = OverlayWndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr;  // Transparent
        wc.lpszClassName = OVERLAY_CLASS;
        RegisterClassExW(&wc);
        s_overlayClassRegistered = true;
    }

    // Create transparent overlay child window
    RECT editorRect;
    GetClientRect(editorHwnd, &editorRect);
    m_overlayHwnd = CreateWindowExW(WS_EX_TRANSPARENT | WS_EX_LAYERED,
        OVERLAY_CLASS, nullptr, WS_CHILD | WS_CLIPSIBLINGS,
        0, 0, editorRect.right, editorRect.bottom,
        editorHwnd, nullptr, hInst, this);
    if (m_overlayHwnd) {
        SetLayeredWindowAttributes(m_overlayHwnd, RGB(0, 0, 0), 180, LWA_ALPHA);
        SetWindowLongPtr(m_overlayHwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    }

    // Subclass editor for key interception
    SetWindowSubclass(editorHwnd, EditorSubclassProc, SUBCLASS_ID, reinterpret_cast<DWORD_PTR>(this));

    OutputDebugStringA("[EditorAgentIntegration] Initialized\n");
=======
/**
 * @file editor_agent_integration.cpp
 * @brief Implementation of editor agentic integration
 *
 * Handles ghost text suggestions and integration with the Direct2D editor.
 */

#include "editor_agent_integration.hpp"
#include <windows.h> // For generic types if needed
#include <nlohmann/json.hpp>
#include <fstream>
using json = nlohmann::json;

// Helper for string conversion
static RawrXD::String toRawrString(const std::string& s) {
    return RawrXD::String::fromUtf8(s.c_str());
}

static std::string toStdString(const RawrXD::String& s) {
    // Convert wide string to UTF-8
    const wchar_t* w = s.constData();
    if (!w) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string str(len - 1, 0); // -1 because len includes null terminator
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &str[0], len, NULL, NULL);
    return str;
}

/**
 * @brief Constructor - attach to editor
 */
EditorAgentIntegration::EditorAgentIntegration(RawrXD::EditorWindow* editor)
    : m_editor(editor)
{
    // Real Configuration Parsing: Load editor integration settings
    // Replaces previous hardcoded/dummy defaults
    std::ifstream configFile("config/editor_agent.json");
    bool configLoaded = false;
    
    if (configFile.is_open()) {
        try {
            json config = json::parse(configFile);
            
            // Parse color (handle hex string or int)
            if (config.contains("ghost_text_color")) {
                if (config["ghost_text_color"].is_string()) {
                    std::string colorStr = config["ghost_text_color"];
                    if (colorStr.substr(0, 2) == "0x") {
                        m_ghostTextColor = std::stoul(colorStr, nullptr, 16);
                    } else {
                        m_ghostTextColor = std::stoul(colorStr);
                    }
                } else {
                    m_ghostTextColor = config.value("ghost_text_color", 0x666666);
                }
            } else {
                m_ghostTextColor = 0x666666;
            }

            m_ghostTextEnabled = config.value("ghost_text_enabled", true);
            m_autoSuggestions = config.value("auto_suggestions", false);
            
            if (config.contains("debounce_ms")) {
                // Store debounce config if we had a member for it, or just use default
            }
            
            configLoaded = true;
        } catch (const std::exception& e) {
            // Invalid config, fallback
        }
    }

    if (!configLoaded) {
        m_ghostTextColor = 0x666666;  // Gray Default
        m_ghostTextEnabled = true;
    }
    
    // Font setup skipped - handled by EditorWindow
}

/**
 * @brief Destructor
 */
EditorAgentIntegration::~EditorAgentIntegration() {
        m_monitoringThreadActive = false;
        if (m_monitorThread.joinable()) {
             m_monitorThread.join();
        }
}

/**
 * @brief Set agent bridge
 */
void EditorAgentIntegration::setAgentBridge(IDEAgentBridge* bridge)
{
    m_agentBridge = bridge;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

EditorAgentIntegration::~EditorAgentIntegration() {
    if (m_autoTimer) KillTimer(m_editorHwnd, m_autoTimer);
    RemoveWindowSubclass(m_editorHwnd, EditorSubclassProc, SUBCLASS_ID);
    if (m_overlayHwnd) DestroyWindow(m_overlayHwnd);
    if (m_ghostFont) DeleteObject(m_ghostFont);
    if (m_normalFont) DeleteObject(m_normalFont);
}

// ============================================================================
// Configuration
// ============================================================================

void EditorAgentIntegration::setAgentCallback(PFN_AGENT_PLAN_WISH planFn,
    PFN_AGENT_COMPLETED completedFn, void* userdata)
{
    m_pfnPlanWish = planFn;
    m_pfnCompleted = completedFn;
    m_agentUserdata = userdata;
    OutputDebugStringA("[EditorAgentIntegration] Agent bridge connected\n");
}

void EditorAgentIntegration::setGhostTextEnabled(bool enabled) {
    m_ghostTextEnabled = enabled;
<<<<<<< HEAD
    if (!enabled) clearGhostText();
    char buf[128];
    sprintf_s(buf, "[EditorAgentIntegration] Ghost text: %s\n", enabled ? "ENABLED" : "DISABLED");
    OutputDebugStringA(buf);
}

void EditorAgentIntegration::setFileType(const wchar_t* fileType) {
    wcscpy_s(m_fileType, fileType);
=======
    if (!enabled) {
        clearGhostText();
    }
}

/**
 * @brief Set file type
 */
void EditorAgentIntegration::setFileType(const std::string& fileType)
{
    m_fileType = fileType;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void EditorAgentIntegration::setAutoSuggestions(bool enabled) {
    m_autoSuggestions = enabled;
<<<<<<< HEAD
    if (enabled) {
        m_autoTimer = SetTimer(m_editorHwnd, IDT_AUTO_SUGGEST, 1000, nullptr);
    } else {
        if (m_autoTimer) { KillTimer(m_editorHwnd, m_autoTimer); m_autoTimer = 0; }
=======
    
    // Explicit Logic: Threaded Debouncer
    // Rather than Windows timers, we use a dedicated background thread loop
    // that sleeps and checks a dirty flag.
    
    if (enabled && !m_monitoringThreadActive) {
        m_monitoringThreadActive = true;
        m_monitorThread = std::thread([this]() {
            while (m_monitoringThreadActive) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Debounce
                
                if (m_contentDirty) {
                    m_contentDirty = false;
                    // Trigger suggestion fetch
                    // Note: Must be careful about thread safety when calling requestSuggestion
                    // For now we just flag it
                }
            }
        });
        m_monitorThread.detach();
    } else if (!enabled) {
        m_monitoringThreadActive = false;
        // Thread will exit on next loop
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
}

// ============================================================================
// Trigger / Accept / Dismiss
// ============================================================================

void EditorAgentIntegration::triggerSuggestion(const GhostTextContext* ctx) {
    if (!m_ghostTextEnabled || !m_pfnPlanWish) return;

    GhostTextContext localCtx;
    if (ctx) {
        localCtx = *ctx;
    } else {
        localCtx = extractContext();
    }
<<<<<<< HEAD
    generateSuggestion(localCtx);
    m_suggestionsGenerated++;
}

bool EditorAgentIntegration::acceptSuggestion() {
    if (!m_hasSuggestion || m_currentSuggestion.text[0] == L'\0') {
        OutputDebugStringA("[EditorAgentIntegration] No suggestion to accept\n");
        return false;
    }

    // Send text to editor via WM_CHAR sequence
    for (const wchar_t* p = m_currentSuggestion.text; *p; ++p) {
        SendMessageW(m_editorHwnd, WM_CHAR, (WPARAM)*p, 0);
    }

    m_suggestionsAccepted++;
    char buf[128];
    sprintf_s(buf, "[EditorAgentIntegration] Suggestion accepted (total: %lu)\n", m_suggestionsAccepted);
    OutputDebugStringA(buf);

    clearGhostText();
=======

    GhostTextContext ctx = context.currentLine.empty() ? extractContext() : context;

    // suggestionGenerating();
    generateSuggestion(ctx);
}

/**
 * @brief Accept suggestion
 */
bool EditorAgentIntegration::acceptSuggestion()
{
    if (m_currentSuggestion.text.empty()) {
        return false;
    }

    if (m_editor) {
        m_editor->acceptGhostText();
    }

    std::string acceptedText = m_currentSuggestion.text;
    clearGhostText();

    // suggestionAccepted(acceptedText);

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

void EditorAgentIntegration::dismissSuggestion() {
    clearGhostText();
<<<<<<< HEAD
    m_suggestionsDismissed++;
=======
    // suggestionDismissed();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void EditorAgentIntegration::clearGhostText() {
    m_currentSuggestion.text[0] = L'\0';
    m_currentSuggestion.explanation[0] = L'\0';
    m_currentSuggestion.confidence = 0;
    m_hasSuggestion = false;
    m_ghostRow = -1;
    m_ghostCol = -1;

<<<<<<< HEAD
    if (m_overlayHwnd) {
        ShowWindow(m_overlayHwnd, SW_HIDE);
        InvalidateRect(m_editorHwnd, nullptr, FALSE);
    }
}

// ============================================================================
// Suggestion arrival
// ============================================================================

void EditorAgentIntegration::onSuggestionGenerated(const GhostTextSuggestion* suggestion, int elapsedMs) {
    if (!suggestion || suggestion->text[0] == L'\0') return;

    m_currentSuggestion = *suggestion;
    m_hasSuggestion = true;

    // Position ghost text at cursor (approximate via caret position)
    POINT caretPos;
    GetCaretPos(&caretPos);
    m_ghostRow = caretPos.y;
    m_ghostCol = caretPos.x;

    // Show overlay at caret position
    if (m_overlayHwnd) {
        // Size overlay to fit text
        HDC hdc = GetDC(m_overlayHwnd);
        SelectObject(hdc, m_ghostFont);
        SIZE textSize;
        GetTextExtentPoint32W(hdc, suggestion->text, (int)wcslen(suggestion->text), &textSize);
        ReleaseDC(m_overlayHwnd, hdc);

        int overlayW = textSize.cx + 20;
        int overlayH = textSize.cy + 24;  // Extra room for confidence badge

        // Clamp to editor bounds
        RECT edRc;
        GetClientRect(m_editorHwnd, &edRc);
        if (caretPos.x + overlayW > edRc.right) overlayW = edRc.right - caretPos.x;
        if (caretPos.y + overlayH > edRc.bottom) overlayH = edRc.bottom - caretPos.y;

        MoveWindow(m_overlayHwnd, caretPos.x, caretPos.y + 18, overlayW, overlayH, TRUE);
        ShowWindow(m_overlayHwnd, SW_SHOWNA);
        InvalidateRect(m_overlayHwnd, nullptr, TRUE);
    }

    char buf[128];
    sprintf_s(buf, "[EditorAgentIntegration] Suggestion in %dms, confidence=%d%%\n",
        elapsedMs, suggestion->confidence);
    OutputDebugStringA(buf);
}

// ============================================================================
// Paint Ghost Overlay
// ============================================================================

void EditorAgentIntegration::paintGhostOverlay(HDC hdc, int editorWidth, int editorHeight) {
    if (!m_hasSuggestion || m_currentSuggestion.text[0] == L'\0') return;

    RECT rc;
    GetClientRect(m_overlayHwnd ? m_overlayHwnd : m_editorHwnd, &rc);
    int w = rc.right - rc.left;
    int h = rc.bottom - rc.top;

    // Semi-transparent background
    HBRUSH bgBr = CreateSolidBrush(GHOST_BG_CLR);
    FillRect(hdc, &rc, bgBr);
    DeleteObject(bgBr);

    // Border
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 65));
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    HBRUSH nullBr = (HBRUSH)GetStockObject(NULL_BRUSH);
    SelectObject(hdc, nullBr);
    Rectangle(hdc, 0, 0, w, h);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);

    SetBkMode(hdc, TRANSPARENT);

    // Ghost text (italic, dim)
    SelectObject(hdc, m_ghostFont);
    SetTextColor(hdc, GHOST_TEXT_CLR);
    RECT textRect = { 6, 2, w - 6, h - 16 };
    DrawTextW(hdc, m_currentSuggestion.text, -1, &textRect, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS);

    // Confidence badge at bottom right
    if (m_currentSuggestion.confidence > 0) {
        wchar_t badge[32];
        swprintf_s(badge, L"Tab to accept (%d%%)", m_currentSuggestion.confidence);

        SIZE badgeSize;
        SelectObject(hdc, m_normalFont);
        GetTextExtentPoint32W(hdc, badge, (int)wcslen(badge), &badgeSize);

        RECT badgeRect = { w - badgeSize.cx - 12, h - 16, w - 4, h - 2 };
        HBRUSH badgeBr = CreateSolidBrush(BADGE_BG);
        FillRect(hdc, &badgeRect, badgeBr);
        DeleteObject(badgeBr);

        SetTextColor(hdc, BADGE_TEXT);
        DrawTextW(hdc, badge, -1, &badgeRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

void EditorAgentIntegration::resize(int x, int y, int w, int h) {
    // Resize overlay to match editor
    if (m_overlayHwnd && !m_hasSuggestion) {
        MoveWindow(m_overlayHwnd, 0, 0, w, h, FALSE);
    }
}

// ============================================================================
// Overlay WndProc
// ============================================================================

LRESULT CALLBACK EditorAgentIntegration::OverlayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto self = reinterpret_cast<EditorAgentIntegration*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));

    switch (msg) {
    case WM_PAINT: {
        if (self && self->m_hasSuggestion) {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            self->paintGhostOverlay(hdc, rc.right, rc.bottom);
            EndPaint(hwnd, &ps);
            return 0;
        }
        break;
    }
    case WM_NCHITTEST:
        return HTTRANSPARENT;  // Pass clicks through
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Editor Subclass (key interception)
// ============================================================================

LRESULT CALLBACK EditorAgentIntegration::EditorSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    auto self = reinterpret_cast<EditorAgentIntegration*>(refData);
    if (!self) return DefSubclassProc(hwnd, msg, wParam, lParam);

    switch (msg) {
    case WM_KEYDOWN: {
        if (!self->m_ghostTextEnabled) break;

        // TAB: trigger suggestion or accept if one is showing
        if (wParam == VK_TAB) {
            if (self->m_hasSuggestion) {
                self->acceptSuggestion();
                return 0;  // Consume
            } else {
                self->triggerSuggestion();
                return 0;
            }
        }

        // ENTER (Ctrl+Enter): accept suggestion
        if (wParam == VK_RETURN && self->m_hasSuggestion) {
            if (GetKeyState(VK_CONTROL) & 0x8000) {
                self->acceptSuggestion();
                return 0;
            }
        }

        // ESC: dismiss
        if (wParam == VK_ESCAPE && self->m_hasSuggestion) {
            self->dismissSuggestion();
            return 0;
        }
        break;
    }

    case WM_CHAR: {
        // If user types regular characters, dismiss ghost text
        if (self->m_hasSuggestion && wParam >= 32) {
            self->clearGhostText();
        }
        break;
    }

    case WM_TIMER: {
        if (wParam == IDT_AUTO_SUGGEST && self->m_autoSuggestions && self->m_ghostTextEnabled) {
            if (!self->m_hasSuggestion) {
                self->triggerSuggestion();
            }
        }
        break;
    }
    }

    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Internal helpers
// ============================================================================

GhostTextContext EditorAgentIntegration::extractContext() const {
    GhostTextContext ctx = {};
    wcscpy_s(ctx.fileType, m_fileType);

    // Get text from editor via EM_GETLINE or WM_GETTEXT
    // For a Rich Edit or Scintilla, use specific messages
    int lineIdx = (int)SendMessageW(m_editorHwnd, EM_LINEFROMCHAR, (WPARAM)-1, 0);

    // Get current line
    wchar_t lineBuf[1024] = {};
    *(WORD*)lineBuf = sizeof(lineBuf) / sizeof(wchar_t);
    int lineLen = (int)SendMessageW(m_editorHwnd, EM_GETLINE, (WPARAM)lineIdx, (LPARAM)lineBuf);
    lineBuf[lineLen] = L'\0';
    wcscpy_s(ctx.currentLine, lineBuf);

    // Get previous lines for context (up to 10)
    ctx.previousLines[0] = L'\0';
    for (int i = lineIdx - 1; i >= 0 && i >= lineIdx - 10; --i) {
        wchar_t prevBuf[1024] = {};
        *(WORD*)prevBuf = sizeof(prevBuf) / sizeof(wchar_t);
        int pLen = (int)SendMessageW(m_editorHwnd, EM_GETLINE, (WPARAM)i, (LPARAM)prevBuf);
        prevBuf[pLen] = L'\0';

        size_t curLen = wcslen(ctx.previousLines);
        if (curLen + pLen + 2 < _countof(ctx.previousLines)) {
            // Prepend
            wchar_t temp[4096];
            swprintf_s(temp, L"%s\n%s", prevBuf, ctx.previousLines);
            wcscpy_s(ctx.previousLines, temp);
        }
    }

    // Cursor column
    int charIdx = (int)SendMessageW(m_editorHwnd, EM_LINEINDEX, (WPARAM)lineIdx, 0);
    DWORD sel = (DWORD)SendMessageW(m_editorHwnd, EM_GETSEL, 0, 0);
    ctx.cursorColumn = LOWORD(sel) - charIdx;

    return ctx;
}

void EditorAgentIntegration::generateSuggestion(const GhostTextContext& ctx) {
    if (!m_pfnPlanWish) return;

    wchar_t wish[4096];
    swprintf_s(wish,
        L"Suggest the next line of code for:\n"
        L"File: %s\n"
        L"Current line: %s\n"
        L"Context: %.200s",
        ctx.fileType, ctx.currentLine, ctx.previousLines);

    m_pfnPlanWish(wish, m_agentUserdata);
=======
    if (m_editor) {
        m_editor->setGhostText(RawrXD::String(L""));
    }
}

/**
 * @brief Set ghost text style
 */
void EditorAgentIntegration::setGhostTextStyle(const std::string& font, const uint32_t& color)
{
    m_ghostTextFont = font;
    m_ghostTextColor = color;
}

// Private Slots removed - key handling delegated to EditorWindow

/**
 * @brief Handle agent suggestion completion
 */
void EditorAgentIntegration::onSuggestionGenerated(const void*& result, int elapsedMs)
{
    // Explicit Logic: Real JSON parsing using nlohmann::json
    // If we receive a raw string (e.g. from AgenticNavigator's WM_COPYDATA or direct IPC buffer)
    // we parse it.
    
    // Safety check for null
    if (!result) return;
    
    // We treat result as a char* to JSON data in this context. 
    // In production, robust type checking/magic number would be used.
    const char* jsonStr = static_cast<const char*>(result);
    // Simple heuristic to verify it looks like JSON
    if (jsonStr && *jsonStr == '{') {
         try {
             auto jsonObj = json::parse(jsonStr);
             std::string suggText = "";
             if (jsonObj.contains("text")) suggText = jsonObj["text"];
             
             if (!suggText.empty()) {
                 GhostTextSuggestion suggestion;
                 suggestion.text = suggText;
                 suggestion.confidence = jsonObj.value("confidence", 0.9f); 
                 
                 // Display in Editor
                 if (m_editor) {
                     m_editor->setGhostText(RawrXD::String(std::wstring(suggText.begin(), suggText.end())));
                 }
                 
                 m_currentSuggestion = suggestion;
             }
         } catch (...) {
             // Invalid JSON or cast - log error
         }
    } 
                 
                 m_currentSuggestion = suggestion;
                 auto [row, col] = getCursorPosition();
                 m_ghostTextRow = row;
                 m_ghostTextColumn = col;
                 renderGhostText(suggText, row, col);
                 success = true;
             }
         } catch (const json::parse_error&) {
             // Invalid JSON - ignore
         }

                 }
             }
         }
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ============================================================================
// C API
// ============================================================================

extern "C" {

EditorAgentIntegration* EditorAgent_Create(HWND editorHwnd) {
    if (!editorHwnd) return nullptr;
    return new EditorAgentIntegration(editorHwnd);
}

<<<<<<< HEAD
void EditorAgent_SetCallback(EditorAgentIntegration* ea, PFN_AGENT_PLAN_WISH planFn,
                              PFN_AGENT_COMPLETED completedFn, void* userdata) {
    if (ea) ea->setAgentCallback(planFn, completedFn, userdata);
}

void EditorAgent_SetGhostTextEnabled(EditorAgentIntegration* ea, int enabled) {
    if (ea) ea->setGhostTextEnabled(enabled != 0);
}

void EditorAgent_SetFileType(EditorAgentIntegration* ea, const wchar_t* fileType) {
    if (ea && fileType) ea->setFileType(fileType);
}

void EditorAgent_SetAutoSuggestions(EditorAgentIntegration* ea, int enabled) {
    if (ea) ea->setAutoSuggestions(enabled != 0);
}

void EditorAgent_TriggerSuggestion(EditorAgentIntegration* ea) {
    if (ea) ea->triggerSuggestion();
}

int EditorAgent_AcceptSuggestion(EditorAgentIntegration* ea) {
    return ea ? (ea->acceptSuggestion() ? 1 : 0) : 0;
}

void EditorAgent_DismissSuggestion(EditorAgentIntegration* ea) {
    if (ea) ea->dismissSuggestion();
}

void EditorAgent_OnSuggestionGenerated(EditorAgentIntegration* ea, const GhostTextSuggestion* s, int ms) {
    if (ea && s) ea->onSuggestionGenerated(s, ms);
}

void EditorAgent_PaintOverlay(EditorAgentIntegration* ea, HDC hdc, int w, int h) {
    if (ea) ea->paintGhostOverlay(hdc, w, h);
}

void EditorAgent_Destroy(EditorAgentIntegration* ea) {
    delete ea;
}

}
=======
/**
 * @brief Text completed
 */
void EditorAgentIntegration::onTextCompleted(const std::string& text)
{
    // Called when text is auto-completed
}

// ─────────────────────────────────────────────────────────────────────────
// Private Methods
// ─────────────────────────────────────────────────────────────────────────

/**
 * @brief Extract context from editor
 */
GhostTextContext EditorAgentIntegration::extractContext() const
{
    GhostTextContext context;
    context.fileType = m_fileType;
    if (!m_editor) return context;

    RawrXD::Point p = m_editor->getCursorPosition();
    context.cursorColumn = p.x;
    
    // Get current line
    RawrXD::String line = m_editor->getLine(p.y);
    context.currentLine = toStdString(line);
    
    // Get prev lines
    int start = (p.y > 10) ? (p.y - 10) : 0;
    for (int i = start; i < p.y; i++) {
        RawrXD::String pl = m_editor->getLine(i);
        context.previousLines += toStdString(pl) + "\n";
    }

    return context;
}

/**
 * @brief Generate suggestion via agent
 */
void EditorAgentIntegration::generateSuggestion(const GhostTextContext& context)
{
    if (!m_agentBridge) {
        // suggestionError("Agent bridge not set");
        return;
    }

    // Explicit Logic: Real code completion (No more simulation)
    std::string suggestedCode = m_agentBridge->generateCodeCompletion(context.previousLines, context.currentLine);

    if (!suggestedCode.empty()) {
        GhostTextSuggestion s;
        s.text = suggestedCode;
        s.confidence = 90;

        m_currentSuggestion = s;
        
        if (m_editor) {
             auto p = m_editor->getCursorPosition();
             m_ghostTextRow = p.y;
             m_ghostTextColumn = p.x;
             renderGhostText(s.text, p.y, p.x);
        }
    }
}

/**
 * @brief Parse LLM response into suggestion
 */
GhostTextSuggestion EditorAgentIntegration::parseSuggestion(const void*& responseObj) const
{
    GhostTextSuggestion suggestion;

    // Explicit Logic: Parse JSON response string pointer
    // We assume responseObj points to a std::string containing valid JSON
    
    if (responseObj == nullptr) return suggestion;
    
    try {
        const std::string* jsonStrPtr = static_cast<const std::string*>(responseObj);
        if (!jsonStrPtr || jsonStrPtr->empty()) return suggestion;
        
        json response = json::parse(*jsonStrPtr);
        
        if (response.contains("actions") && response["actions"].is_array() && !response["actions"].empty()) {
            auto firstAction = response["actions"][0];
            
            if (firstAction.contains("result")) {
                suggestion.text = firstAction["result"].get<std::string>();
            } else if (firstAction.contains("new_code")) {
                suggestion.text = firstAction["new_code"].get<std::string>();
            } else if (firstAction.contains("text")) {
                suggestion.text = firstAction["text"].get<std::string>();
            }
            
            if (firstAction.contains("description")) {
                suggestion.explanation = firstAction["description"].get<std::string>();
            }
            
            suggestion.confidence = response.value("confidence", 85);
        } else if (response.contains("text")) {
             // Fallback for direct completion response
             suggestion.text = response["text"].get<std::string>();
             suggestion.confidence = 90;
        } else {
             // Try assuming raw string if not object
             // suggestion.text = *jsonStrPtr;
        }
        
        // Remove surrounding quotes if they exist inappropriately
        if (suggestion.text.size() >= 2 && suggestion.text.front() == '"' && suggestion.text.back() == '"') {
            suggestion.text = suggestion.text.substr(1, suggestion.text.size() - 2);
        }

    } catch (...) {
        // Fallback or empty
    }
    
    // Limit length
    if (suggestion.text.length() > 200) {
        suggestion.text = suggestion.text.substr(0, 197) + "...";
    }

    return suggestion;
}

/**
 * @brief Render ghost text
 */
void EditorAgentIntegration::renderGhostText(const std::string& text, int row, int column)
{
    m_ghostTextRow = row;
    m_ghostTextColumn = column;

    if (m_editor) {
        m_editor->setGhostText(toRawrString(text));
    }
}

// Event hooks removed - utilizing RawrXD::EditorWindow internal handling

/**
 * @brief Get cursor position
 */
std::pair<int, int> EditorAgentIntegration::getCursorPosition() const
{
    if (!m_editor) return {0,0};
    RawrXD::Point p = m_editor->getCursorPosition();
    return {p.y, p.x};
}

/**
 * @brief Get word under cursor
 */
std::string EditorAgentIntegration::getWordUnderCursor() const
{
    // Simplified implementation
    if (!m_editor) return "";
    RawrXD::Point p = m_editor->getCursorPosition();
    RawrXD::String line = m_editor->getLine(p.y);
    std::string s = toStdString(line);
    
    if (p.x >= s.length()) return "";

    int start = p.x;
    while(start > 0 && isalnum(s[start-1])) start--;
    int end = p.x;
    while(end < s.length() && isalnum(s[end])) end++;
    
    return s.substr(start, end-start);
}


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
