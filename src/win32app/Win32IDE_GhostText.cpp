#include "Win32IDE_GhostText.h"

#include <richedit.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <thread>
#include <utility>

namespace {
constexpr UINT_PTR kGhostTimer = 0x5247;
constexpr UINT kGhostResult = WM_APP + 73;
struct Result {
    NativeGhostTextController* owner;
    std::shared_ptr<void> requestIdentity;
    uint64_t requestId;
    uint64_t generation;
    std::string text;
    bool success;
};
std::atomic<uint64_t> g_nextGhostRequestId{1};

// Candidate-only deterministic scheduling control.  It is disabled unless
// explicitly enabled by both delay variables.  Production runs therefore
// retain the provider's normal callback timing and behavior.
void applyGhostTextTestDelay(uint64_t requestId) {
    const char* first = std::getenv("RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS");
    const char* second = std::getenv("RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS");
    if (!first || !second) return;
    const char* selected = requestId == 1 ? first : (requestId == 2 ? second : nullptr);
    if (!selected || !*selected) return;
    char* end = nullptr;
    const long delayMs = std::strtol(selected, &end, 10);
    if (end == selected || *end != '\0' || delayMs <= 0 || delayMs > 30000) return;
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
}
}

NativeGhostTextController::~NativeGhostTextController() { detach(); }

bool NativeGhostTextController::attach(HWND host, HWND editor, Request request,
                                       std::string promptPrefix, Trace trace) {
    if (!host || !editor || !request) return false;
    detach();
    m_host = host;
    m_editor = editor;
    m_request = std::move(request);
    m_promptPrefix = std::move(promptPrefix);
    m_trace = std::move(trace);
    m_requestIdentity = std::make_shared<int>(0);
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
    m_timer = 0; m_completion.clear(); m_snapshot.clear(); m_promptPrefix.clear();
    m_requestIdentity.reset();
    m_trace = {};
    m_requestPending = false;
    ++m_generation;
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
    m_snapshot = editorText();
    dismiss();
    if (m_editor && !m_snapshot.empty()) {
        m_timer = SetTimer(m_editor, kGhostTimer, 250, nullptr);
    }
}

void NativeGhostTextController::triggerCompletion() {
    m_snapshot = editorText();
    dismiss();
    if (!m_editor || m_snapshot.empty()) return;
    requestCompletion();
}

void NativeGhostTextController::requestCompletion() {
    if (!m_request || m_snapshot.empty()) return;
    const uint64_t requestId = g_nextGhostRequestId.fetch_add(1);
    const uint64_t generation = m_generation;
    const std::weak_ptr<void> requestIdentity = m_requestIdentity;
    const HWND host = m_host;
    NativeGhostTextController* owner = this;
    const std::string prompt = (m_promptPrefix.empty()
        ? "Complete the following code. Return only the completion text, no markdown:\n"
        : m_promptPrefix + "\n") + m_snapshot;
    auto accumulated = std::make_shared<std::string>();
    m_requestPending = true;
    m_requestId = requestId;
    if (m_trace) {
        m_trace("GHOSTTEXT_TRIGGER request_id=" + std::to_string(requestId) +
                " generation=" + std::to_string(generation) +
                " editor_bytes=" + std::to_string(m_snapshot.size()));
        m_trace("GHOSTTEXT_REQUEST_SENT request_id=" + std::to_string(requestId));
    }
    m_request(prompt, [owner, host, requestIdentity, requestId, generation, accumulated](
        const std::string& response, bool done, bool success) {
        if (success && !response.empty()) *accumulated += response;
        if (!done || !host) return;
        applyGhostTextTestDelay(requestId);
        // Do not touch the controller here: the provider may finish after a
        // model switch, editor detach, or IDE teardown.  Locking the identity
        // proves the attachment still exists; handleMessage performs the
        // second identity check on the UI thread before rendering.
        auto identity = requestIdentity.lock();
        if (!identity) return;
        auto* result = new Result{owner, std::move(identity), requestId,
                                  generation, *accumulated, success};
        if (!PostMessageA(host, kGhostResult, 0, reinterpret_cast<LPARAM>(result))) delete result;
    });
}

void NativeGhostTextController::showCompletion(const std::string& completion, uint64_t generation) {
    if (generation != m_generation || editorText() != m_snapshot || completion.empty()) return;
    m_completion = completion;
    if (m_trace) {
        m_trace("GHOSTTEXT_RENDERED request_id=" + std::to_string(m_requestId) +
                " response_bytes=" + std::to_string(completion.size()));
    }
    if (m_hint) {
        SetWindowTextA(m_hint, ("  " + completion).c_str());
        positionHint();
        ShowWindow(m_hint, SW_SHOWNA);
    }
}

void NativeGhostTextController::positionHint() {
    if (!m_editor || !m_hint) return;
    RECT editorRect{};
    GetWindowRect(m_editor, &editorRect);
    POINT p{editorRect.left + 8, editorRect.top + 4};

    // RichEdit exposes the caret position in client coordinates.  Anchor the
    // hint to that position instead of painting a misleading footer overlay.
    // If a non-RichEdit surface does not support EM_POSFROMCHAR, retain a
    // safe top-left fallback inside the editor bounds.
    CHARRANGE selection{};
    if (SendMessageA(m_editor, EM_EXGETSEL, 0,
                     reinterpret_cast<LPARAM>(&selection)) != 0) {
        const LRESULT packed = SendMessageA(
            m_editor, EM_POSFROMCHAR, static_cast<WPARAM>(selection.cpMax), 0);
        if (packed != -1) {
            POINT clientPoint{static_cast<SHORT>(LOWORD(packed)),
                              static_cast<SHORT>(HIWORD(packed))};
            ClientToScreen(m_editor, &clientPoint);
            p = clientPoint;
        }
    }
    ScreenToClient(m_host, &p);
    const LONG width = std::max<LONG>(120, editorRect.right - editorRect.left -
        (p.x - (editorRect.left - (editorRect.left - p.x))));
    MoveWindow(m_hint, p.x + 8, p.y, width, 20, TRUE);
}

void NativeGhostTextController::dismiss() {
    const bool hadCompletion = !m_completion.empty();
    const bool hadPending = m_requestPending;
    const uint64_t generationBefore = m_generation;
    if (m_trace && (hadCompletion || hadPending)) {
        m_trace(std::string(hadPending ? "GHOSTTEXT_CANCELLED" :
                            "GHOSTTEXT_DISMISSED") +
                " request_id=" + std::to_string(m_requestId) +
                " generation_before=" + std::to_string(generationBefore) +
                " pending_before=" + (hadPending ? "1" : "0"));
    }
    ++m_generation;
    m_requestPending = false;
    if (m_editor && m_timer) {
        KillTimer(m_editor, m_timer);
        m_timer = 0;
    }
    m_completion.clear();
    if (m_hint) ShowWindow(m_hint, SW_HIDE);
    if (m_trace && (hadCompletion || hadPending)) {
        m_trace("GHOSTTEXT_INVALIDATED request_id=" + std::to_string(m_requestId) +
                " generation_after=" + std::to_string(m_generation) +
                " pending_after=0");
    }
}

bool NativeGhostTextController::accept() {
    if (m_completion.empty() || !m_editor) return false;
    if (m_trace) {
        m_trace("GHOSTTEXT_ACCEPTED request_id=" + std::to_string(m_requestId) +
                " suggestion_bytes=" + std::to_string(m_completion.size()));
    }
    // Replace the current selection at the caret.  Appending at EOF made
    // accepted suggestions modify the wrong location in multi-line editors.
    SendMessageA(m_editor, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(m_completion.c_str()));
    dismiss();
    return true;
}

bool NativeGhostTextController::handleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    if (message != kGhostResult || !lParam ||
        reinterpret_cast<Result*>(lParam)->owner != this) return false;
    std::unique_ptr<Result> result(reinterpret_cast<Result*>(lParam));
    m_requestPending = false;
    const bool identityCurrent = result->requestIdentity &&
        result->requestIdentity == m_requestIdentity;
    const bool generationCurrent = result->generation == m_generation;
    const bool snapshotCurrent = editorText() == m_snapshot;
    if (m_trace) {
        m_trace(std::string("GHOSTTEXT_RESPONSE_RECEIVED request_id=") +
                std::to_string(result->requestId) +
                " success=" + (result->success ? "1" : "0") +
                " response_bytes=" + std::to_string(result->text.size()) +
                " generated_tokens=N/A" +
                " generation_current=" + (generationCurrent ? "1" : "0") +
                " identity_current=" + (identityCurrent ? "1" : "0") +
                " snapshot_current=" + (snapshotCurrent ? "1" : "0"));
    }
    if (m_trace) {
        m_trace("GHOSTTEXT_RENDER_DECISION request_id=" +
                std::to_string(result->requestId) +
                " eligible=" +
                ((result->success && identityCurrent && generationCurrent &&
                  snapshotCurrent && !result->text.empty()) ? "1" : "0"));
    }
    if (result->success && identityCurrent && generationCurrent && snapshotCurrent) {
        showCompletion(result->text, result->generation);
    }
    return true;
}

bool NativeGhostTextController::ownsMessage(UINT message, LPARAM lParam) const {
    return message == kGhostResult && lParam &&
        reinterpret_cast<Result*>(lParam)->owner == this;
}

void NativeGhostTextController::discardMessage(UINT message, LPARAM lParam) {
    if (message == kGhostResult) delete reinterpret_cast<Result*>(lParam);
}

LRESULT CALLBACK NativeGhostTextController::editorProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = static_cast<NativeGhostTextController*>(GetPropA(hwnd, "RawrXD.GhostText"));
    if (self) {
        if (message == WM_TIMER && wParam == kGhostTimer) {
            KillTimer(hwnd, kGhostTimer); self->m_timer = 0; self->requestCompletion(); return 0;
        }
        if (message == WM_KEYDOWN) {
            if (wParam == VK_TAB && self->accept()) return 0;
            if (wParam == VK_ESCAPE) {
                const bool cancellable = self->active() || self->m_timer ||
                    self->m_requestPending;
                if (self->m_trace) {
                    self->m_trace("GHOSTTEXT_ESCAPE_ENTRY request_id=" +
                        std::to_string(self->m_requestId) +
                        " generation=" + std::to_string(self->m_generation) +
                        " pending=" + (self->m_requestPending ? "1" : "0") +
                        " timer=" + (self->m_timer ? "1" : "0") +
                        " active=" + (self->active() ? "1" : "0") +
                        " cancellable=" + (cancellable ? "1" : "0"));
                }
                if (cancellable) self->dismiss();
                return 0;
            }
            if (wParam == VK_SPACE && (GetKeyState(VK_CONTROL) & 0x8000)) {
                self->triggerCompletion();
                return 0;
            }
        }
        if (message == WM_SIZE) self->positionHint();
        if (message == WM_NCDESTROY) self->detach();
        if (self->m_originalProc) return CallWindowProcA(self->m_originalProc, hwnd, message, wParam, lParam);
    }
    return DefWindowProcA(hwnd, message, wParam, lParam);
}

