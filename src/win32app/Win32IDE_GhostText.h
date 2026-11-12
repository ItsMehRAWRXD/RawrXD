#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

class NativeGhostTextController {
public:
    // Result of one asynchronous completion attempt.  `success` is only true
    // when the transport produced a non-empty body for the *current* request;
    // cancellation, transport failure, and an empty model answer are reported
    // separately through `failureReason` so they are never collapsed into a
    // single boolean.
    struct Response {
        std::string text;
        bool success = false;
        bool done = false;
        std::string failureReason;   // empty when success; otherwise CANCELLED,
                                     // HTTP_TIMEOUT, HTTP_CANNOT_CONNECT,
                                     // EMPTY_RESPONSE, EMPTY_OUTPUT, ...
        unsigned int httpStatus = 0; // 0 when no status line was received
        uint64_t elapsedMs = 0;      // transport wall time measured by the backend
    };
    // Cancellation is idempotent and non-blocking: the returned handle asks the
    // transport owner to release the specific in-flight request.  The controller
    // never sees the backend/client type.
    using RequestCancel = std::function<void()>;
    using RequestCallback = std::function<void(const Response&)>;
    using Request = std::function<RequestCancel(
        const std::string&, RequestCallback)>;
    using Trace = std::function<void(const std::string&)>;

    NativeGhostTextController() = default;
    ~NativeGhostTextController();

    bool attach(HWND host, HWND editor, Request request,
                std::string promptPrefix = {}, Trace trace = {});
    void detach();
    void onEditorChanged();
    // Start a completion explicitly from the editor (Ctrl+Space).  Normal
    // typing refreshes the snapshot, dismisses an old hint, and arms the
    // debounce timer for an asynchronous inline request.
    void triggerCompletion();
    bool handleMessage(UINT message, WPARAM wParam, LPARAM lParam);
    bool ownsMessage(UINT message, LPARAM lParam) const;
    static void discardMessage(UINT message, LPARAM lParam);
    bool accept();
    void dismiss();
    bool active() const { return !m_completion.empty(); }
    bool attachedTo(HWND target) const { return target && m_editor == target; }

private:
    static LRESULT CALLBACK editorProc(HWND, UINT, WPARAM, LPARAM);
    void requestCompletion();
    void showCompletion(const std::string& completion, uint64_t generation);
    void positionHint();
    std::string editorText() const;
    // Resolve caret to a real cp in [0, length]. Returns -1 only when the
    // editor handle is gone; never leaves the -1 sentinel into insert.
    long resolveCaretCp() const;

    HWND m_host = nullptr;
    HWND m_editor = nullptr;
    HWND m_hint = nullptr;
    WNDPROC m_originalProc = nullptr;
    Request m_request;
    Trace m_trace;
    std::string m_promptPrefix;
    std::string m_completion;
    std::string m_snapshot;
    long m_caretCp = -1;  // caret captured at request; -1 = unresolved
    uint64_t m_generation = 0;
    UINT_PTR m_timer = 0;
    bool m_requestPending = false;
    uint64_t m_requestId = 0;
    // Cancel handle for the request currently in flight.  Empty when idle.
    // Cleared on completion, on supersede/dismiss, and on detach.  Invoking it
    // is safe to repeat and must not block the UI thread.
    RequestCancel m_cancelActive;
    // A per-attachment identity fences callbacks that outlive a controller
    // detach/rebind. Stale completions are discarded without dereferencing
    // the old object.
    std::shared_ptr<void> m_requestIdentity;
};

