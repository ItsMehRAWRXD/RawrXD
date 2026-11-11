#include "Win32IDE_GhostText.h"

#include <richedit.h>
#include <algorithm>
#include <memory>
#include <utility>

namespace {
constexpr UINT_PTR kGhostTimer = 0x5247;
constexpr UINT kGhostResult = WM_APP + 73;
struct Result { NativeGhostTextController* owner; uint64_t generation; std::string text; };
}

NativeGhostTextController::~NativeGhostTextController() { detach(); }

bool NativeGhostTextController::attach(HWND host, HWND editor, Request request) {
    if (!host || !editor || !request) return false;
    detach();
    m_host = host;
    m_editor = editor;
    m_request = std::move(request);
    SetPropA(m_editor, "RawrXD.GhostText", this);
    m_originalProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrA(
        m_editor, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&editorProc)));
    m_hint = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "",
        WS_CHILD | SS_LEFTNOWORDWRAP, 0, 0, 0, 20, m_host, nullptr,
        GetModuleHandleA(nullptr), nullptr);
    if (!m_originalProc || !m_hint) { detach(); return false; }
    SendMessageA(m_hint, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
    ShowWindow(m_hint, SW_HIDE);
    return true;
}

void NativeGhostTextController::detach() {
    if (m_editor && m_timer) KillTimer(m_editor, m_timer);
    if (m_editor && m_originalProc) {
        SetWindowLongPtrA(m_editor, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(m_originalProc));
        RemovePropA(m_editor, "RawrXD.GhostText");
    }
    if (m_hint) DestroyWindow(m_hint);
    m_hint = nullptr; m_editor = nullptr; m_host = nullptr; m_originalProc = nullptr;
    m_timer = 0; m_completion.clear(); m_snapshot.clear(); ++m_generation;
}

std::string NativeGhostTextController::editorText() const {
    if (!m_editor) return {};
    const int length = GetWindowTextLengthA(m_editor);
    std::string text(static_cast<size_t>(std::max(0, length)) + 1, '\0');
    if (length) GetWindowTextA(m_editor, text.data(), length + 1);
    text.resize(static_cast<size_t>(length));
    return text;
}

void NativeGhostTextController::onEditorChanged() {
    ++m_generation;
    m_snapshot = editorText();
    dismiss();
    if (!m_editor || m_snapshot.empty()) return;
    if (!m_timer) m_timer = SetTimer(m_editor, kGhostTimer, 250, nullptr);
}

void NativeGhostTextController::requestCompletion() {
    if (!m_request || m_snapshot.empty()) return;
    const uint64_t generation = m_generation;
    const std::string prompt = "Complete the following code. Return only the completion text, no markdown:\n" + m_snapshot;
    auto accumulated = std::make_shared<std::string>();
    m_request(prompt, [this, generation, accumulated](const std::string& response, bool done) {
        if (!response.empty()) *accumulated += response;
        if (!done || accumulated->empty() || !m_host) return;
        auto* result = new Result{this, generation, *accumulated};
        if (!PostMessageA(m_host, kGhostResult, 0, reinterpret_cast<LPARAM>(result))) delete result;
    });
}

void NativeGhostTextController::showCompletion(const std::string& completion, uint64_t generation) {
    if (generation != m_generation || editorText() != m_snapshot || completion.empty()) return;
    m_completion = completion;
    if (m_hint) {
        SetWindowTextA(m_hint, ("  " + completion).c_str());
        positionHint();
        ShowWindow(m_hint, SW_SHOWNA);
    }
}

void NativeGhostTextController::positionHint() {
    if (!m_editor || !m_hint) return;
    RECT r{}; GetWindowRect(m_editor, &r);
    POINT p{r.left, r.bottom - 24}; ScreenToClient(m_host, &p);
    MoveWindow(m_hint, p.x + 8, p.y, std::max(120L, r.right - r.left - 16), 20, TRUE);
}

void NativeGhostTextController::dismiss() {
    m_completion.clear();
    if (m_hint) ShowWindow(m_hint, SW_HIDE);
}

bool NativeGhostTextController::accept() {
    if (m_completion.empty() || !m_editor) return false;
    SendMessageA(m_editor, EM_SETSEL, -1, -1);
    SendMessageA(m_editor, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(m_completion.c_str()));
    dismiss();
    return true;
}

bool NativeGhostTextController::handleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == kGhostResult) {
        std::unique_ptr<Result> result(reinterpret_cast<Result*>(lParam));
        if (result && result->owner == this) showCompletion(result->text, result->generation);
        return true;
    }
    return false;
}

LRESULT CALLBACK NativeGhostTextController::editorProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = static_cast<NativeGhostTextController*>(GetPropA(hwnd, "RawrXD.GhostText"));
    if (self) {
        if (message == WM_TIMER && wParam == kGhostTimer) {
            KillTimer(hwnd, kGhostTimer); self->m_timer = 0; self->requestCompletion(); return 0;
        }
        if (message == WM_KEYDOWN) {
            if (wParam == VK_TAB && self->accept()) return 0;
            if (wParam == VK_ESCAPE && self->active()) { self->dismiss(); return 0; }
        }
        if (message == WM_SIZE) self->positionHint();
        if (message == WM_NCDESTROY) self->detach();
        if (self->m_originalProc) return CallWindowProcA(self->m_originalProc, hwnd, message, wParam, lParam);
    }
    return DefWindowProcA(hwnd, message, wParam, lParam);
}
