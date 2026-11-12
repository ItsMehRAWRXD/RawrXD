#include "Win32IDE_GhostText.h"

#include <richedit.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <utility>

namespace {
constexpr UINT_PTR kGhostTimer = 0x5247;
constexpr UINT kGhostResult = WM_APP + 73;
// Typing debounce only — never reuse this as the Ollama HTTP deadline.
constexpr UINT kGhostDebounceMs = 250;

bool utf8ToWide(const std::string& input, std::wstring& output) {
    output.clear();
    if (input.empty()) return true;
    if (input.size() > static_cast<size_t>(INT_MAX)) return false;
    const int sourceLength = static_cast<int>(input.size());
    const int length = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), sourceLength,
        nullptr, 0);
    if (length <= 0) return false;
    output.resize(static_cast<size_t>(length));
    return MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), sourceLength,
        output.data(), length) == length;
}

bool wideToUtf8(const std::wstring& input, std::string& output) {
    output.clear();
    if (input.empty()) return true;
    if (input.size() > static_cast<size_t>(INT_MAX)) return false;
    const int sourceLength = static_cast<int>(input.size());
    const int length = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), sourceLength,
        nullptr, 0, nullptr, nullptr);
    if (length <= 0) return false;
    output.resize(static_cast<size_t>(length));
    return WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), sourceLength,
        output.data(), length, nullptr, nullptr) == length;
}

bool readEditorTextUtf8(HWND editor, std::string& output) {
    output.clear();
    if (!editor) return false;
    const int length = GetWindowTextLengthW(editor);
    if (length < 0) return false;
    std::wstring wide(static_cast<size_t>(length) + 1, L'\0');
    if (length > 0 && GetWindowTextW(editor, wide.data(), length + 1) <= 0) {
        return false;
    }
    wide.resize(static_cast<size_t>(length));
    return wideToUtf8(wide, output);
}

void traceUtf8ConversionFailure(const NativeGhostTextController::Trace& trace,
                                const char* operation) {
    if (trace) trace(std::string("GHOSTTEXT_UTF8_ERROR operation=") + operation);
}

struct Result {
    NativeGhostTextController* owner;
    std::shared_ptr<void> requestIdentity;
    uint64_t requestId;
    uint64_t generation;
    NativeGhostTextController::Response response;
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
    SetPropW(m_editor, L"RawrXD.GhostText", this);
    // Must use SetWindowLongPtrW: SetWindowLongPtrA flips IsWindowUnicode to
    // FALSE and CJK/emoji WM_SETTEXT becomes '?' (MULTILINE_UNICODE gate).
    m_originalProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrW(
        m_editor, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&editorProc)));
    m_hint = CreateWindowExW(WS_EX_TRANSPARENT, L"STATIC", L"",
        WS_CHILD | SS_LEFTNOWORDWRAP, 0, 0, 0, 20, m_host, nullptr,
        GetModuleHandleW(nullptr), nullptr);
    if (!m_originalProc || !m_hint) { detach(); return false; }
    SendMessageW(m_hint, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
    ShowWindow(m_hint, SW_HIDE);
    return true;
}

void NativeGhostTextController::detach() {
    // Cancel any in-flight transport request before the attachment (and its
    // identity) goes away.  Idempotent and non-blocking, same as dismiss().
    if (m_cancelActive) {
        RequestCancel cancel = std::move(m_cancelActive);
        m_cancelActive = nullptr;
        cancel();
    }
    if (m_editor && m_timer) KillTimer(m_editor, m_timer);
    if (m_editor && m_originalProc) {
        SetWindowLongPtrW(m_editor, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(m_originalProc));
        RemovePropW(m_editor, L"RawrXD.GhostText");
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
    std::string text;
    if (!readEditorTextUtf8(m_editor, text)) {
        traceUtf8ConversionFailure(m_trace, "editor_read");
        return {};
    }
    return text;
}

void NativeGhostTextController::onEditorChanged() {
    std::string text;
    if (!readEditorTextUtf8(m_editor, text)) {
        // A transient read failure is not a document change. Treating it as
        // one would wipe a valid snapshot and cancel in-flight work.
        if (m_trace) m_trace("GHOSTTEXT_EDITOR_READ_FAILED");
        return;
    }
    if (text == m_snapshot) {
        // Redundant EN_CHANGE (caret/selection, font, buffer-limit, or a
        // programmatic set of identical text) must not invalidate a valid
        // in-flight request or a visible hint. Only re-arm the debounce when
        // nothing is pending and no hint is showing.
        if (m_trace) {
            m_trace("GHOSTTEXT_CHANGE_REDUNDANT bytes=" +
                    std::to_string(text.size()));
        }
        if (!m_requestPending && m_completion.empty() && !m_timer &&
            m_editor && !text.empty()) {
            m_timer = SetTimer(m_editor, kGhostTimer, kGhostDebounceMs, nullptr);
        }
        return;
    }
    m_snapshot = std::move(text);
    dismiss();
    if (m_editor && !m_snapshot.empty()) {
        m_timer = SetTimer(m_editor, kGhostTimer, kGhostDebounceMs, nullptr);
    }
}

long NativeGhostTextController::resolveCaretCp() const {
    if (!m_editor || !IsWindow(m_editor)) return -1;
    CHARRANGE selection{};
    // EM_EXGETSEL returns SEL_* flags; SEL_EMPTY==0 at a caret is success.
    SendMessageW(m_editor, EM_EXGETSEL, 0,
                 reinterpret_cast<LPARAM>(&selection));
    long caret = selection.cpMin;
    const int length = GetWindowTextLengthW(m_editor);
    if (length < 0) return -1;
    if (caret < 0 || caret > length) caret = length;
    return caret;
}

void NativeGhostTextController::triggerCompletion() {
    std::string text = editorText();
    if (!text.empty()) m_snapshot = std::move(text);
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
        ? "Complete the following code. Return only the text to append at the current caret. Do not repeat the existing document prefix and do not use markdown:\n"
        : m_promptPrefix + " Return only the text to append at the current caret; do not repeat the existing document prefix and do not use markdown:\n") + m_snapshot;
    auto accumulated = std::make_shared<std::string>();

    m_caretCp = resolveCaretCp();
    if (m_caretCp < 0) {
        if (m_trace) {
            m_trace("GHOSTTEXT_CURSOR_UNRESOLVED request_id=" +
                    std::to_string(requestId) + " sentinel=-1");
        }
        return;
    }

    m_requestPending = true;
    m_requestId = requestId;
    if (m_trace) {
        m_trace("GHOSTTEXT_TRIGGER request_id=" + std::to_string(requestId) +
                " generation=" + std::to_string(generation) +
                " editor_hwnd=" +
                std::to_string(reinterpret_cast<uintptr_t>(m_editor)) +
                " cursor=" + std::to_string(m_caretCp) +
                " editor_bytes=" + std::to_string(m_snapshot.size()));
        m_trace("GHOSTTEXT_REQUEST_SENT request_id=" + std::to_string(requestId) +
                " generation=" + std::to_string(generation) +
                " cursor=" + std::to_string(m_caretCp) +
                " editor_bytes=" + std::to_string(m_snapshot.size()));
    }

    // The backend returns a cancellation handle synchronously (it hands the
    // actual work to a worker).  Storing it lets dismiss()/detach() release the
    // exact in-flight transport request without blocking the UI thread.
    m_cancelActive = m_request(
        prompt,
        [owner, host, requestIdentity, requestId, generation, accumulated](
            const NativeGhostTextController::Response& response) {
            if (response.success && !response.text.empty()) {
                *accumulated += response.text;
            }
            if (!response.done || !host) return;
            applyGhostTextTestDelay(requestId);
            // Do not touch the controller here: the provider may finish after
            // a model switch, editor detach, or IDE teardown.  Locking the
            // identity proves the attachment still exists; handleMessage
            // performs the second identity check on the UI thread before
            // rendering.
            auto identity = requestIdentity.lock();
            if (!identity) return;
            NativeGhostTextController::Response finalResponse = response;
            finalResponse.text = *accumulated;
            auto* result = new Result{owner, std::move(identity), requestId,
                                      generation, std::move(finalResponse)};
            if (!PostMessageA(host, kGhostResult, 0,
                              reinterpret_cast<LPARAM>(result))) {
                delete result;
            }
        });
    // A backend that rejects synchronously (disabled route, no model, revoked
    // consent) may have already posted its result before returning here. That
    // message is handled after this method returns, so the cancel handle stored
    // above is still correct: it is cleared in handleMessage when the result
    // for this request is consumed.
}

void NativeGhostTextController::showCompletion(const std::string& completion, uint64_t generation) {
    if (generation != m_generation || editorText() != m_snapshot || completion.empty()) return;
    // Some local models echo the complete prompt/document before emitting
    // their continuation.  GhostText must own only the suffix: accepting an
    // echoed document would duplicate the user's existing buffer.  Normalize
    // an exact UTF-8 snapshot prefix before rendering or accepting.
    m_completion = completion;
    if (!m_snapshot.empty() &&
        m_completion.rfind(m_snapshot, 0) == 0) {
        const size_t echoedBytes = m_snapshot.size();
        m_completion.erase(0, echoedBytes);
        if (m_trace) {
            m_trace("GHOSTTEXT_NORMALIZED echoed_prefix_bytes=" +
                    std::to_string(echoedBytes) +
                    " suggestion_bytes=" +
                    std::to_string(m_completion.size()));
        }
    }
    if (m_completion.empty()) return;
    if (m_trace) {
        m_trace("GHOSTTEXT_RENDERED request_id=" + std::to_string(m_requestId) +
                " response_bytes=" + std::to_string(completion.size()));
    }
    if (m_hint) {
        std::wstring wideCompletion;
        if (!utf8ToWide("  " + m_completion, wideCompletion)) {
            traceUtf8ConversionFailure(m_trace, "hint_write");
            m_completion.clear();
            return;
        }
        SetWindowTextW(m_hint, wideCompletion.c_str());
        positionHint();
        ShowWindow(m_hint, SW_SHOWNA);
    }
}

void NativeGhostTextController::positionHint() {
    if (!m_editor || !m_hint) return;
    RECT editorRect{};
    GetWindowRect(m_editor, &editorRect);
    POINT p{editorRect.left + 8, editorRect.top + 4};

    // Anchor to resolved caret; SEL_EMPTY (0) from EM_EXGETSEL is success.
    const long caret = (m_caretCp >= 0) ? m_caretCp : resolveCaretCp();
    if (caret >= 0) {
        const LRESULT packed = SendMessageW(
            m_editor, EM_POSFROMCHAR, static_cast<WPARAM>(caret), 0);
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
    // Release the exact in-flight transport request.  The handle is moved out
    // and cleared first, so repeated dismiss()/detach() calls are idempotent and
    // cannot double-cancel.  The handle is non-blocking: it closes the WinHTTP
    // handle that unblocks the worker, it never joins it.
    if (m_cancelActive) {
        RequestCancel cancel = std::move(m_cancelActive);
        m_cancelActive = nullptr;
        cancel();
    }
    if (m_editor && m_timer) {
        KillTimer(m_editor, m_timer);
        m_timer = 0;
    }
    m_completion.clear();
    m_caretCp = -1;
    if (m_hint) ShowWindow(m_hint, SW_HIDE);
    if (m_trace && (hadCompletion || hadPending)) {
        m_trace("GHOSTTEXT_INVALIDATED request_id=" + std::to_string(m_requestId) +
                " generation_after=" + std::to_string(m_generation) +
                " pending_after=0");
    }
}

bool NativeGhostTextController::accept() {
    if (m_completion.empty() || !m_editor) return false;
    // A completion is valid only for the exact editor snapshot that caused
    // it. This also protects against programmatic edits that do not emit the
    // normal change notification before Tab is pressed.
    if (editorText() != m_snapshot) {
        dismiss();
        return false;
    }
    long caret = m_caretCp;
    if (caret < 0) caret = resolveCaretCp();
    if (caret < 0) {
        if (m_trace) {
            m_trace("GHOSTTEXT_CURSOR_UNRESOLVED request_id=" +
                    std::to_string(m_requestId) + " phase=accept");
        }
        dismiss();
        return false;
    }
    std::wstring wideCompletion;
    if (!utf8ToWide(m_completion, wideCompletion)) {
        traceUtf8ConversionFailure(m_trace, "accept");
        dismiss();
        return false;
    }
    if (m_trace) {
        m_trace("GHOSTTEXT_ACCEPTED request_id=" + std::to_string(m_requestId) +
                " cursor=" + std::to_string(caret) +
                " suggestion_bytes=" + std::to_string(m_completion.size()));
    }
    // Place the real caret before insert — never leave sentinel -1 into
    // EM_REPLACESEL (which would append at an undefined selection).
    CHARRANGE range{caret, caret};
    SendMessageW(m_editor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&range));
    const size_t acceptedBytes = m_completion.size();
    const std::string before = editorText();
    SendMessageW(m_editor, EM_REPLACESEL, TRUE,
                 reinterpret_cast<LPARAM>(wideCompletion.c_str()));
    const std::string after = editorText();
    // RichEdit may normalize newlines; require growth + suggestion substring.
    const bool documentVerified =
        after.size() > before.size() &&
        after.find(m_completion) != std::string::npos;
    if (m_trace) {
        m_trace(std::string("GHOSTTEXT_DOCUMENT_CONTENT_VERIFIED request_id=") +
                std::to_string(m_requestId) +
                " verified=" + (documentVerified ? "1" : "0") +
                " cursor=" + std::to_string(caret) +
                " accepted_bytes=" + std::to_string(acceptedBytes) +
                " document_bytes=" + std::to_string(after.size()));
    }
    dismiss();
    return documentVerified;
}

bool NativeGhostTextController::handleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    if (message != kGhostResult || !lParam ||
        reinterpret_cast<Result*>(lParam)->owner != this) return false;
    std::unique_ptr<Result> result(reinterpret_cast<Result*>(lParam));
    const bool requestCurrent = result->requestId == m_requestId;
    const bool pendingCurrent = requestCurrent && m_requestPending;
    // A late completion from request A must not clear the pending state of a
    // newer request B. Otherwise Escape can no longer invalidate B and the
    // controller falsely appears idle while B is still in flight.
    if (requestCurrent) {
        m_requestPending = false;
        // The transport for this request has finished (or was cancelled). Drop
        // the cancel handle so a later dismiss() cannot touch a dead request.
        m_cancelActive = nullptr;
    }
    const bool identityCurrent = result->requestIdentity &&
        result->requestIdentity == m_requestIdentity;
    const bool generationCurrent = result->generation == m_generation;
    const bool snapshotCurrent = editorText() == m_snapshot;

    // Classify the outcome explicitly. A cancelled request, a transport
    // timeout/refusal, and an empty model answer are different results and must
    // never collapse into a bare success=false.
    const char* disposition = "ELIGIBLE";
    if (!identityCurrent) disposition = "SUPERSEDED";
    else if (!requestCurrent) disposition = "SUPERSEDED";
    else if (!pendingCurrent) disposition = "CANCELLED";
    else if (!result->response.success) disposition = "TRANSPORT_FAILED";
    else if (result->response.text.empty()) disposition = "EMPTY";
    else if (!generationCurrent || !snapshotCurrent) disposition = "STALE";
    const bool eligible = std::strcmp(disposition, "ELIGIBLE") == 0;

    if (m_trace) {
        m_trace(std::string("GHOSTTEXT_RESPONSE_RECEIVED request_id=") +
                std::to_string(result->requestId) +
                " disposition=" + disposition +
                " success=" + (result->response.success ? "1" : "0") +
                " response_bytes=" + std::to_string(result->response.text.size()) +
                " failure_reason=" +
                    (result->response.failureReason.empty()
                         ? "NONE" : result->response.failureReason) +
                " http_status=" + std::to_string(result->response.httpStatus) +
                " elapsed_ms=" + std::to_string(result->response.elapsedMs) +
                " request_current=" + (requestCurrent ? "1" : "0") +
                " pending_current=" + (pendingCurrent ? "1" : "0") +
                " generation_current=" + (generationCurrent ? "1" : "0") +
                " identity_current=" + (identityCurrent ? "1" : "0") +
                " snapshot_current=" + (snapshotCurrent ? "1" : "0"));
    }
    if (eligible) {
        if (m_trace) {
            m_trace("GHOSTTEXT_SUGGESTION_VALIDATED request_id=" +
                    std::to_string(result->requestId) +
                    " response_bytes=" +
                    std::to_string(result->response.text.size()));
        }
        showCompletion(result->response.text, result->generation);
    } else if (m_trace) {
        m_trace("GHOSTTEXT_RENDER_DECISION request_id=" +
                std::to_string(result->requestId) +
                " eligible=0 reason=" + disposition);
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
    auto* self = static_cast<NativeGhostTextController*>(GetPropW(hwnd, L"RawrXD.GhostText"));
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

