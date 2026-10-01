// Win32IDE_ChatPanel.cpp — streaming AI chat panel
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <algorithm>
#include <cstdio>
#include <sstream>
#include "Win32IDE_ChatPanel.h"

namespace RawrXD::IDE {

HFONT IDECore_MonoFont();
HFONT IDECore_UIFont();
COLORREF IDECore_ColBg();
COLORREF IDECore_ColPanel();
COLORREF IDECore_ColText();
COLORREF IDECore_ColAccent();

struct ChatMessage {
    MsgRole     role;
    std::string text;
    bool        streaming = false;
};

// ── Chat state ────────────────────────────────────────────────────────────────
struct ChatPanelState {
    HWND hwnd       = nullptr;
    HWND hInput     = nullptr;
    HWND hSend      = nullptr;
    HWND hStop      = nullptr;
    HWND hScroll    = nullptr;
    std::vector<ChatMessage> messages;
    std::function<void(const std::string&)> onSend;
    // RAWRXD_IDE_STOP_001: cancellation had no UI affordance at all. The only
    // way to stop a generation was to send a SECOND prompt, which cancelled the
    // first as a side effect of handleChatSend. This callback carries the user's
    // intent straight to the engine's cooperative cancel.
    std::function<void()> onCancel;
    int scrollOffset = 0;
    int lineH        = 18;
    bool streaming   = false;
};

static ChatPanelState g_chat;

// Forward declaration
void ChatPanel_AddMessage(MsgRole role, const std::string& text);

// Panel-side trace of the send path. Written beside the exe so a certification
// run can see what the panel actually received, not just what it rendered.
static void ChatPanel_Trace(const std::string& line)
{
    char mod[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(nullptr, mod, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return;
    std::string path(mod);
    size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return;
    path = path.substr(0, slash) + "\\ide_chat_send_trace.txt";

    HANDLE h = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::string out = line + "\r\n";
    DWORD written = 0;
    WriteFile(h, out.data(), (DWORD)out.size(), &written, nullptr);
    CloseHandle(h);
}

// ── Measure wrapped text height ───────────────────────────────────────────────
static int MeasureWrappedHeight(HDC hdc, const std::string& text, int maxW, int lineH)
{
    if (text.empty()) return lineH;
    RECT rc = {0, 0, maxW, 32000};
    DrawTextA(hdc, text.c_str(), (int)text.size(), &rc, DT_CALCRECT | DT_WORDBREAK | DT_LEFT);
    return std::max(lineH, (int)rc.bottom);
}

// ── Paint ─────────────────────────────────────────────────────────────────────
static void ChatPaint(HWND hwnd)
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, H = rc.bottom;

    HDC mem = CreateCompatibleDC(hdc);
    HBITMAP bmp = CreateCompatibleBitmap(hdc, W, H);
    HBITMAP oldBmp = (HBITMAP)SelectObject(mem, bmp);

    // Background
    HBRUSH bgBrush = CreateSolidBrush(RGB(37, 37, 38));
    FillRect(mem, &rc, bgBrush);
    DeleteObject(bgBrush);

    HFONT font = IDECore_UIFont();
    HFONT oldFont = (HFONT)SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);

    // Message area height (leave room for input)
    const int inputH = 60;
    const int msgAreaH = H - inputH;
    const int padX = 8, padY = 6;
    const int bubbleMaxW = W - padX * 2 - 16;

    // Compute total content height
    int totalH = padY;
    for (auto& msg : g_chat.messages) {
        HDC tmpDC = CreateCompatibleDC(hdc);
        HFONT tmpFont = (HFONT)SelectObject(tmpDC, font);
        int mh = MeasureWrappedHeight(tmpDC, msg.text, bubbleMaxW - 16, g_chat.lineH);
        SelectObject(tmpDC, tmpFont);
        DeleteDC(tmpDC);
        totalH += mh + padY * 2 + 4;
    }

    // Clamp scroll
    int maxScroll = std::max(0, totalH - msgAreaH);
    g_chat.scrollOffset = std::min(g_chat.scrollOffset, maxScroll);

    // Draw messages
    int y = padY - g_chat.scrollOffset;
    for (auto& msg : g_chat.messages) {
        bool isUser = (msg.role == MsgRole::User);
        COLORREF bubbleCol = isUser ? RGB(0, 122, 204) : RGB(50, 50, 55);
        COLORREF textCol   = RGB(212, 212, 212);

        int mh = MeasureWrappedHeight(hdc, msg.text, bubbleMaxW - 16, g_chat.lineH);
        int bh = mh + padY * 2;

        if (y + bh > 0 && y < msgAreaH) {
            // Bubble background
            RECT bubRc;
            if (isUser) {
                bubRc = {W - bubbleMaxW - padX, y, W - padX, y + bh};
            } else {
                bubRc = {padX, y, padX + bubbleMaxW, y + bh};
            }
            HBRUSH bubBrush = CreateSolidBrush(bubbleCol);
            // Rounded feel via filled rect
            FillRect(mem, &bubRc, bubBrush);
            DeleteObject(bubBrush);

            // Role label
            const char* roleLabel = isUser ? "You" :
                (msg.role == MsgRole::Tool ? "Tool" : "RawrXD");
            SetTextColor(mem, isUser ? RGB(180, 220, 255) : RGB(150, 150, 160));
            RECT labelRc = {bubRc.left + 8, bubRc.top + 2, bubRc.right - 4, bubRc.top + g_chat.lineH + 2};
            DrawTextA(mem, roleLabel, -1, &labelRc, DT_LEFT | DT_SINGLELINE);

            // Message text
            SetTextColor(mem, textCol);
            RECT textRc = {bubRc.left + 8, bubRc.top + g_chat.lineH + 4, bubRc.right - 8, bubRc.bottom - padY};
            DrawTextA(mem, msg.text.c_str(), (int)msg.text.size(), &textRc, DT_LEFT | DT_WORDBREAK);

            // Streaming indicator
            if (msg.streaming) {
                SetTextColor(mem, RGB(100, 200, 100));
                RECT dotRc = {bubRc.right - 20, bubRc.bottom - g_chat.lineH - 2, bubRc.right - 4, bubRc.bottom - 2};
                DrawTextA(mem, "...", -1, &dotRc, DT_LEFT | DT_SINGLELINE);
            }
        }
        y += bh + 4;
    }

    // Separator line above input
    HPEN sepPen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
    HPEN oldPen = (HPEN)SelectObject(mem, sepPen);
    MoveToEx(mem, 0, msgAreaH, nullptr);
    LineTo(mem, W, msgAreaH);
    SelectObject(mem, oldPen);
    DeleteObject(sepPen);

    SelectObject(mem, oldFont);
    BitBlt(hdc, 0, 0, W, H, mem, 0, 0, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

// ── Window procedure ──────────────────────────────────────────────────────────
#define IDC_CHAT_SEND  2001
#define IDC_CHAT_INPUT 2002
#define IDC_CHAT_STOP  2003

static LRESULT CALLBACK ChatWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        int W = rc.right, H = rc.bottom;
        const int inputH = 60;
        const int btnW   = 60;

        g_chat.hInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            4, H - inputH + 4, W - btnW * 2 - 16, inputH - 8,
            hwnd, (HMENU)IDC_CHAT_INPUT,
            ((LPCREATESTRUCT)lParam)->hInstance, nullptr);

        g_chat.hSend = CreateWindowExA(0, "BUTTON", "Send",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - btnW * 2 - 12, H - inputH + 4, btnW, inputH - 8,
            hwnd, (HMENU)IDC_CHAT_SEND,
            ((LPCREATESTRUCT)lParam)->hInstance, nullptr);

        // RAWRXD_IDE_STOP_001: explicit cancel. Disabled while idle so it cannot
        // be pressed into a no-op that silently looks like a working control.
        g_chat.hStop = CreateWindowExA(0, "BUTTON", "Stop",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            W - btnW - 4, H - inputH + 4, btnW, inputH - 8,
            hwnd, (HMENU)IDC_CHAT_STOP,
            ((LPCREATESTRUCT)lParam)->hInstance, nullptr);
        EnableWindow(g_chat.hStop, FALSE);

        HFONT font = IDECore_UIFont();
        SendMessage(g_chat.hInput, WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_chat.hSend,  WM_SETFONT, (WPARAM)font, TRUE);
        SendMessage(g_chat.hStop,  WM_SETFONT, (WPARAM)font, TRUE);
        return 0;
    }

    case WM_SIZE: {
        int W = LOWORD(lParam), H = HIWORD(lParam);
        const int inputH = 60, btnW = 60;
        if (g_chat.hInput)
            SetWindowPos(g_chat.hInput, nullptr, 4, H - inputH + 4, W - btnW * 2 - 16, inputH - 8, SWP_NOZORDER);
        if (g_chat.hSend)
            SetWindowPos(g_chat.hSend, nullptr, W - btnW * 2 - 12, H - inputH + 4, btnW, inputH - 8, SWP_NOZORDER);
        if (g_chat.hStop)
            SetWindowPos(g_chat.hStop, nullptr, W - btnW - 4, H - inputH + 4, btnW, inputH - 8, SWP_NOZORDER);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CHAT_STOP) {
            // RAWRXD_IDE_STOP_001: cooperative cancel. The engine checks this
            // each decode step, so the stream unwinds and the existing
            // WM_CHAT_DONE path still runs and still writes the receipt with
            // CANCELLED=1 / COMPLETED=0 rather than being abandoned.
            if (g_chat.onCancel) {
                g_chat.onCancel();
                ChatPanel_AddMessage(MsgRole::System, "[Generation cancelled by user.]");
            }
            return 0;
        }
        if (LOWORD(wParam) == IDC_CHAT_SEND || (LOWORD(wParam) == IDC_CHAT_INPUT && HIWORD(wParam) == EN_UPDATE)) {
            if (LOWORD(wParam) == IDC_CHAT_SEND) {
                char buf[4096] = {};
                GetWindowTextA(g_chat.hInput, buf, sizeof(buf));
                std::string text(buf);

                ChatPanel_Trace("WM_COMMAND send inputHwnd=" + std::to_string((uintptr_t)g_chat.hInput)
                              + " textLen=" + std::to_string(text.size())
                              + " onSend=" + (g_chat.onSend ? "1" : "0"));

                if (!text.empty()) {
                    SetWindowTextA(g_chat.hInput, "");
                    ChatPanel_AddMessage(MsgRole::User, text);
                    if (g_chat.onSend) g_chat.onSend(text);
                }
            }
        }
        return 0;

    case WM_PAINT:
        ChatPaint(hwnd);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wParam);
        g_chat.scrollOffset -= delta / WHEEL_DELTA * 40;
        g_chat.scrollOffset = std::max(0, g_chat.scrollOffset);
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ── Public API ────────────────────────────────────────────────────────────────
void ChatPanel_Register(HINSTANCE hInst)
{
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = ChatWndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = "RawrXDChat";
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = nullptr;
    RegisterClassExA(&wc);
}

HWND ChatPanel_Create(HWND parent, int x, int y, int w, int h, HINSTANCE hInst)
{
    g_chat.hwnd = CreateWindowExA(0, "RawrXDChat", nullptr,
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInst, nullptr);
    return g_chat.hwnd;
}

void ChatPanel_AddMessage(MsgRole role, const std::string& text)
{
    ChatMessage m;
    m.role = role;
    m.text = text;
    g_chat.messages.push_back(m);
    // Auto-scroll to bottom
    g_chat.scrollOffset = 999999;
    if (g_chat.hwnd) InvalidateRect(g_chat.hwnd, nullptr, FALSE);
}

void ChatPanel_BeginStreaming()
{
    ChatMessage m;
    m.role      = MsgRole::Assistant;
    m.text      = "";
    m.streaming = true;
    g_chat.messages.push_back(m);
    g_chat.streaming = true;
    // RAWRXD_IDE_STOP_001: the Stop control is only meaningful while a
    // generation is in flight, so it tracks the streaming state exactly.
    if (g_chat.hStop) EnableWindow(g_chat.hStop, TRUE);
}

void ChatPanel_AppendStreamToken(const std::string& token)
{
    if (g_chat.messages.empty()) return;
    auto& last = g_chat.messages.back();
    if (last.streaming) {
        last.text += token;
        g_chat.scrollOffset = 999999;
        if (g_chat.hwnd) InvalidateRect(g_chat.hwnd, nullptr, FALSE);
    }
}

void ChatPanel_EndStreaming()
{
    if (!g_chat.messages.empty() && g_chat.messages.back().streaming)
        g_chat.messages.back().streaming = false;
    g_chat.streaming = false;
    if (g_chat.hStop) EnableWindow(g_chat.hStop, FALSE);
    if (g_chat.hwnd) InvalidateRect(g_chat.hwnd, nullptr, FALSE);
}

void ChatPanel_SetSendCallback(std::function<void(const std::string&)> cb)
{
    g_chat.onSend = std::move(cb);
}

void ChatPanel_SetCancelCallback(std::function<void()> cb)
{
    g_chat.onCancel = std::move(cb);
}

void ChatPanel_Clear()
{
    g_chat.messages.clear();
    g_chat.scrollOffset = 0;
    if (g_chat.hwnd) InvalidateRect(g_chat.hwnd, nullptr, FALSE);
}

// ── Gate evidence ─────────────────────────────────────────────────────────────
// These read the same store ChatPaint draws from, so a certification run can
// assert on precisely what the user sees. UI-thread only.
size_t ChatPanel_MessageCount()
{
    return g_chat.messages.size();
}

std::string ChatPanel_GetMessage(size_t index)
{
    if (index >= g_chat.messages.size()) return std::string();
    return g_chat.messages[index].text;
}

bool ChatPanel_IsLastStreaming()
{
    if (g_chat.messages.empty()) return false;
    return g_chat.messages.back().streaming;
}

size_t ChatPanel_StreamingTokenCount()
{
    if (g_chat.messages.empty()) return 0;
    if (!g_chat.messages.back().streaming) return 0;
    // Approximate the streamed token count from the rendered text; the engine
    // callback is the authoritative count and is recorded in the E2E receipt.
    return g_chat.messages.back().text.size();
}

} // namespace RawrXD::IDE
