#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <mutex>
#include <stdio.h>
#include <string.h>


#pragma comment(lib, "Ws2_32.lib")

namespace SovereignNetwork {

enum class LoaderApiState : int {
    Idle = 0,
    Loading = 1,
    Ready = 2,
    Fault = 3,
};

enum class SuggestedAction : int {
    None = 0,
    RetrySame = 1,
    RetryFallback = 2,
    Abort = 3,
    Exit = 4,
};

struct RecoveryEvent {
    char timestamp_utc[32] = {0};
    char from_model[MAX_PATH] = {0};
    char to_model[MAX_PATH] = {0};
    char reason[96] = {0};
};

struct InferenceRequest {
    bool pending = false;
    unsigned long long request_id = 0;
    char prompt[2048] = {0};
    char capability_requirement[64] = {0};
};

struct SharedLoaderState {
    std::mutex mtx;
    LoaderApiState load_state = LoaderApiState::Idle;
    SuggestedAction suggested_action = SuggestedAction::None;
    bool model_loaded = false;
    bool can_retry = false;
    bool terminal_fault = false;
    bool unload_requested = false;
    int last_win32_error = 0;
    int retry_count = 0;
    int retry_budget_rem = 0;
    unsigned long long next_request_id = 1;
    unsigned long long last_completed_request_id = 0;
    unsigned long long startup_epoch_ms = 0;
    unsigned long long last_update_epoch_ms = 0;
    unsigned long long status_seq = 0;
    char session_id[64] = {0};
    char fault_class[32] = "NONE";
    char active_model[MAX_PATH] = {0};
    char last_error_tag[96] = "none";
    InferenceRequest inference;
    static constexpr int kMaxRecoveryEvents = 8;
    RecoveryEvent recovery_history[kMaxRecoveryEvents] = {};
    int recovery_count = 0;
};

struct Runtime {
    std::atomic<bool> running{false};
    std::atomic<bool> wsa_started{false};
    SOCKET listen_socket = INVALID_SOCKET;
    HANDLE thread = nullptr;
    HWND control_window = nullptr;
};

inline SharedLoaderState& State() {
    static SharedLoaderState state;
    return state;
}

inline Runtime& Rt() {
    static Runtime rt;
    return rt;
}

inline void SetControlWindow(HWND hwnd) {
    Rt().control_window = hwnd;
}

inline const char* LoaderStateToString(LoaderApiState state) {
    switch (state) {
        case LoaderApiState::Idle:
            return "idle";
        case LoaderApiState::Loading:
            return "loading";
        case LoaderApiState::Ready:
            return "ready";
        case LoaderApiState::Fault:
            return "fault";
        default:
            return "unknown";
    }
}

inline const char* SuggestedActionToString(SuggestedAction action) {
    switch (action) {
        case SuggestedAction::None:
            return "NONE";
        case SuggestedAction::RetrySame:
            return "RETRY_SAME";
        case SuggestedAction::RetryFallback:
            return "RETRY_FALLBACK";
        case SuggestedAction::Abort:
            return "ABORT";
        case SuggestedAction::Exit:
            return "EXIT";
        default:
            return "NONE";
    }
}

inline unsigned long long EpochMsNowUtc() {
    FILETIME ft = {};
    GetSystemTimeAsFileTime(&ft);

    ULARGE_INTEGER uli = {};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    static constexpr unsigned long long kWindowsToUnixEpoch100ns = 116444736000000000ULL;
    if (uli.QuadPart <= kWindowsToUnixEpoch100ns) {
        return 0;
    }
    return (uli.QuadPart - kWindowsToUnixEpoch100ns) / 10000ULL;
}

inline void TouchStatusLocked(SharedLoaderState& state) {
    state.last_update_epoch_ms = EpochMsNowUtc();
    state.status_seq++;
}

inline void JsonEscape(const char* src, char* dst, size_t dst_size);

inline void FaultSidecarPath(char* out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    out[0] = '\0';

    char exe_path[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        strncpy_s(out, out_size, "headless_fault_policy.json", _TRUNCATE);
        return;
    }

    char* slash = strrchr(exe_path, '\\');
    if (!slash) {
        strncpy_s(out, out_size, "headless_fault_policy.json", _TRUNCATE);
        return;
    }
    *slash = '\0';
    _snprintf_s(out, out_size, _TRUNCATE, "%s\\headless_fault_policy.json", exe_path);
}

inline void RemoveFaultSidecarBestEffort() {
    char path[MAX_PATH] = {};
    FaultSidecarPath(path, sizeof(path));
    if (!path[0]) {
        return;
    }
    DeleteFileA(path);
}

inline void WriteFaultSidecarLocked(const SharedLoaderState& state) {
    if (state.load_state != LoaderApiState::Fault) {
        return;
    }

    char path[MAX_PATH] = {};
    FaultSidecarPath(path, sizeof(path));
    if (!path[0]) {
        return;
    }

    FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0 || !f) {
        return;
    }

    char esc_session[128] = {};
    char esc_tag[192] = {};
    char esc_action[48] = {};
    char esc_fault_class[64] = {};
    char esc_model[MAX_PATH * 2] = {};
    JsonEscape(state.session_id[0] ? state.session_id : "none", esc_session, sizeof(esc_session));
    JsonEscape(state.last_error_tag[0] ? state.last_error_tag : "none", esc_tag, sizeof(esc_tag));
    JsonEscape(SuggestedActionToString(state.suggested_action), esc_action, sizeof(esc_action));
    JsonEscape(state.fault_class[0] ? state.fault_class : "NONE", esc_fault_class, sizeof(esc_fault_class));
    JsonEscape(state.active_model[0] ? state.active_model : "none", esc_model, sizeof(esc_model));

    char body[2048] = {};
    _snprintf_s(
        body,
        sizeof(body),
        _TRUNCATE,
        "{\"source\":\"last_gasp\",\"process_id\":%lu,\"session_id\":\"%s\",\"startup_epoch_ms\":%llu,\"status_seq\":%llu,\"last_update_epoch_ms\":%llu,\"active_model\":\"%s\",\"loader_context\":{\"state\":\"fault\",\"last_error_tag\":\"%s\",\"win32_error_code\":%d,\"retry_count\":%d,\"retry_budget_rem\":%d,\"can_retry\":%s,\"terminal_fault\":%s,\"fault_class\":\"%s\",\"suggested_action\":\"%s\"}}",
        static_cast<unsigned long>(GetCurrentProcessId()),
        esc_session,
        state.startup_epoch_ms,
        state.status_seq,
        state.last_update_epoch_ms,
        esc_model,
        esc_tag,
        state.last_win32_error,
        state.retry_count,
        state.retry_budget_rem,
        state.can_retry ? "true" : "false",
        state.terminal_fault ? "true" : "false",
        esc_fault_class,
        esc_action);

    const size_t len = strlen(body);
    if (len > 0) {
        fwrite(body, 1, len, f);
    }
    fclose(f);
}

inline void ClassifyFaultLocked(SharedLoaderState& state) {
    if (state.load_state != LoaderApiState::Fault) {
        strncpy_s(state.fault_class, "NONE", _TRUNCATE);
        return;
    }

    const bool perm_denied = (state.last_win32_error == 5);
    const bool corrupt_data = (strstr(state.last_error_tag, "corrupt_data") != nullptr);
    const bool file_not_found = (strstr(state.last_error_tag, "file_not_found") != nullptr);
    const bool mapping_fault = (strstr(state.last_error_tag, "map_view_failed") != nullptr) ||
                               (strstr(state.last_error_tag, "file_mapping_failed") != nullptr) ||
                               (state.last_win32_error == 1455) ||
                               (state.last_win32_error == 8);

    if (perm_denied) {
        strncpy_s(state.fault_class, "PERM_DENIED", _TRUNCATE);
    } else if (corrupt_data) {
        strncpy_s(state.fault_class, "DATA_CORRUPTION", _TRUNCATE);
    } else if (file_not_found) {
        strncpy_s(state.fault_class, "CONFIG", _TRUNCATE);
    } else if (mapping_fault) {
        strncpy_s(state.fault_class, "TRANSIENT", _TRUNCATE);
    } else {
        strncpy_s(state.fault_class, "UNKNOWN", _TRUNCATE);
    }
}

inline int CountFaultsForActiveModelLocked(const SharedLoaderState& state) {
    if (!state.active_model[0]) {
        return 0;
    }

    const int history_items = (state.recovery_count < SharedLoaderState::kMaxRecoveryEvents)
                                  ? state.recovery_count
                                  : SharedLoaderState::kMaxRecoveryEvents;
    const int start_idx = (state.recovery_count > SharedLoaderState::kMaxRecoveryEvents)
                              ? (state.recovery_count % SharedLoaderState::kMaxRecoveryEvents)
                              : 0;

    int same_model_faults = 0;
    for (int i = 0; i < history_items; ++i) {
        const int idx = (start_idx + i) % SharedLoaderState::kMaxRecoveryEvents;
        const RecoveryEvent& evt = state.recovery_history[idx];
        if (_stricmp(evt.to_model, state.active_model) != 0) {
            continue;
        }
        if (_stricmp(evt.reason, "model_switch") == 0) {
            continue;
        }
        same_model_faults++;
    }
    return same_model_faults;
}

inline void RecomputePolicyLocked(SharedLoaderState& state) {
    state.suggested_action = SuggestedAction::None;
    state.can_retry = false;
    state.retry_budget_rem = 0;
    state.terminal_fault = false;

    if (state.load_state != LoaderApiState::Fault) {
        strncpy_s(state.fault_class, "NONE", _TRUNCATE);
        return;
    }

    ClassifyFaultLocked(state);

    const int same_model_faults = CountFaultsForActiveModelLocked(state);
    static constexpr int kRetryBudgetMax = 2;
    const int rem = kRetryBudgetMax - same_model_faults;
    state.retry_budget_rem = (rem > 0) ? rem : 0;

    const bool retriable_class =
        (_stricmp(state.fault_class, "TRANSIENT") == 0) ||
        (_stricmp(state.fault_class, "DATA_CORRUPTION") == 0);
    state.can_retry = retriable_class && (state.retry_budget_rem > 0);

    if (state.can_retry) {
        if (_stricmp(state.fault_class, "TRANSIENT") == 0) {
            state.suggested_action = SuggestedAction::RetryFallback;
        } else {
            state.suggested_action = SuggestedAction::RetrySame;
        }
    } else {
        if ((_stricmp(state.fault_class, "PERM_DENIED") == 0) || (_stricmp(state.fault_class, "CONFIG") == 0)) {
            state.suggested_action = SuggestedAction::Abort;
        } else {
            state.suggested_action = SuggestedAction::Exit;
        }
    }

    state.terminal_fault = !state.can_retry;

    if (state.load_state == LoaderApiState::Fault) {
        WriteFaultSidecarLocked(state);
    }
}

inline void InitializeSessionLocked(SharedLoaderState& state) {
    LARGE_INTEGER qpc = {};
    QueryPerformanceCounter(&qpc);

    const DWORD pid = GetCurrentProcessId();
    state.startup_epoch_ms = EpochMsNowUtc();
    _snprintf_s(state.session_id,
                sizeof(state.session_id),
                _TRUNCATE,
                "pid-%lu-%llu-%lld",
                static_cast<unsigned long>(pid),
                state.startup_epoch_ms,
                static_cast<long long>(qpc.QuadPart));
    state.status_seq = 0;
    TouchStatusLocked(state);
    RemoveFaultSidecarBestEffort();
}

inline void UtcTimestampNow(char* out, size_t out_size) {
    if (!out || out_size == 0) {
        return;
    }
    SYSTEMTIME st = {};
    GetSystemTime(&st);
    _snprintf_s(out, out_size, _TRUNCATE, "%04u-%02u-%02uT%02u:%02u:%02uZ",
                static_cast<unsigned>(st.wYear),
                static_cast<unsigned>(st.wMonth),
                static_cast<unsigned>(st.wDay),
                static_cast<unsigned>(st.wHour),
                static_cast<unsigned>(st.wMinute),
                static_cast<unsigned>(st.wSecond));
}

inline void JsonEscape(const char* src, char* dst, size_t dst_size) {
    if (!dst || dst_size == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src) {
        return;
    }

    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 2 < dst_size; ++i) {
        const char c = src[i];
        if (c == '\\' || c == '"') {
            dst[j++] = '\\';
            dst[j++] = c;
            continue;
        }
        if (static_cast<unsigned char>(c) < 0x20) {
            continue;
        }
        dst[j++] = c;
    }
    dst[j] = '\0';
}

inline void AppendRecoveryEventLocked(SharedLoaderState& state, const char* from_model, const char* to_model, const char* reason) {
    const int idx = state.recovery_count % SharedLoaderState::kMaxRecoveryEvents;
    RecoveryEvent& evt = state.recovery_history[idx];
    UtcTimestampNow(evt.timestamp_utc, sizeof(evt.timestamp_utc));
    strncpy_s(evt.from_model, (from_model && from_model[0]) ? from_model : "none", _TRUNCATE);
    strncpy_s(evt.to_model, (to_model && to_model[0]) ? to_model : "none", _TRUNCATE);
    strncpy_s(evt.reason, (reason && reason[0]) ? reason : "unspecified", _TRUNCATE);
    state.recovery_count++;
}

inline void SetActiveModel(const char* model) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    const char* src = (model && model[0]) ? model : "none";
    if (_stricmp(state.active_model, src) != 0) {
        char prev[MAX_PATH] = {};
        strncpy_s(prev, state.active_model[0] ? state.active_model : "none", _TRUNCATE);
        strncpy_s(state.active_model, src, _TRUNCATE);
        AppendRecoveryEventLocked(state, prev, state.active_model, "model_switch");
        RecomputePolicyLocked(state);
        TouchStatusLocked(state);
        return;
    }
    strncpy_s(state.active_model, src, _TRUNCATE);
    RecomputePolicyLocked(state);
    TouchStatusLocked(state);
}

inline void SetLoadState(LoaderApiState new_state, const char* tag, int win32_error) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    const LoaderApiState prev_state = state.load_state;
    state.load_state = new_state;
    state.model_loaded = (new_state == LoaderApiState::Ready);

    if (prev_state == LoaderApiState::Fault && new_state == LoaderApiState::Loading) {
        state.retry_count++;
    }

    const char* src = (tag && tag[0]) ? tag : "none";
    strncpy_s(state.last_error_tag, src, _TRUNCATE);
    state.last_win32_error = win32_error;

    if (new_state == LoaderApiState::Fault) {
        AppendRecoveryEventLocked(state, state.active_model[0] ? state.active_model : "none", state.active_model[0] ? state.active_model : "none", src);
    }

    RecomputePolicyLocked(state);
    TouchStatusLocked(state);
}

inline void SetRetryCount(int retry_count) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    state.retry_count = retry_count;
    RecomputePolicyLocked(state);
    TouchStatusLocked(state);
}

inline bool ConsumeUnloadRequested() {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    if (!state.unload_requested) {
        return false;
    }
    state.unload_requested = false;
    TouchStatusLocked(state);
    return true;
}

inline bool EnqueueInference(const char* prompt, const char* requirement, unsigned long long* request_id_out) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    if (state.inference.pending) {
        return false;
    }

    state.inference.pending = true;
    state.inference.request_id = state.next_request_id++;
    strncpy_s(state.inference.prompt, (prompt && prompt[0]) ? prompt : "", _TRUNCATE);
    strncpy_s(state.inference.capability_requirement, (requirement && requirement[0]) ? requirement : "", _TRUNCATE);

    if (request_id_out) {
        *request_id_out = state.inference.request_id;
    }
    TouchStatusLocked(state);
    return true;
}

inline bool ConsumeInferenceRequest(unsigned long long* request_id_out, char* prompt_out, size_t prompt_out_size, char* req_out, size_t req_out_size) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    if (!state.inference.pending) {
        return false;
    }

    if (request_id_out) {
        *request_id_out = state.inference.request_id;
    }
    if (prompt_out && prompt_out_size > 0) {
        strncpy_s(prompt_out, prompt_out_size, state.inference.prompt, _TRUNCATE);
    }
    if (req_out && req_out_size > 0) {
        strncpy_s(req_out, req_out_size, state.inference.capability_requirement, _TRUNCATE);
    }

    state.inference.pending = false;
    state.inference.prompt[0] = '\0';
    state.inference.capability_requirement[0] = '\0';
    TouchStatusLocked(state);
    return true;
}

inline void CompleteInference(unsigned long long request_id) {
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mtx);
    state.last_completed_request_id = request_id;
    TouchStatusLocked(state);
}

inline bool ExtractJsonStringField(const char* request, const char* field_name, char* out, size_t out_size) {
    if (!request || !field_name || !out || out_size == 0) {
        return false;
    }
    out[0] = '\0';

    char needle[96] = {};
    _snprintf_s(needle, sizeof(needle), _TRUNCATE, "\"%s\":\"", field_name);
    const char* begin = strstr(request, needle);
    if (!begin) {
        return false;
    }
    begin += strlen(needle);

    const char* end = begin;
    while (*end) {
        if (*end == '"' && *(end - 1) != '\\') {
            break;
        }
        ++end;
    }
    if (*end != '"') {
        return false;
    }

    const size_t len = static_cast<size_t>(end - begin);
    if (len == 0) {
        return true;
    }

    const size_t copy_len = (len < (out_size - 1)) ? len : (out_size - 1);
    memcpy(out, begin, copy_len);
    out[copy_len] = '\0';
    return true;
}

inline bool SendAll(SOCKET sock, const char* data, int len) {
    int sent_total = 0;
    while (sent_total < len) {
        const int sent = send(sock, data + sent_total, len - sent_total, 0);
        if (sent <= 0) {
            return false;
        }
        sent_total += sent;
    }
    return true;
}

inline void SendJsonResponse(SOCKET sock, int status_code, const char* status_text, const char* json_body, const char* extra_headers = nullptr) {
    char header[512] = {};
    const int body_len = static_cast<int>(strlen(json_body));
    const int header_len = _snprintf_s(
        header,
        sizeof(header),
        _TRUNCATE,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "%s"
        "Connection: close\r\n\r\n",
        status_code,
        status_text,
        body_len,
        extra_headers ? extra_headers : "");

    if (header_len > 0) {
        SendAll(sock, header, header_len);
    }
    SendAll(sock, json_body, body_len);
}

inline void BuildStatusJson(char* out, size_t out_size) {
    SharedLoaderState snapshot;
    {
        auto& state = State();
        std::lock_guard<std::mutex> lock(state.mtx);
        snapshot.model_loaded = state.model_loaded;
        snapshot.unload_requested = state.unload_requested;
        snapshot.last_win32_error = state.last_win32_error;
        snapshot.retry_count = state.retry_count;
        snapshot.retry_budget_rem = state.retry_budget_rem;
        snapshot.can_retry = state.can_retry;
        snapshot.terminal_fault = state.terminal_fault;
        snapshot.suggested_action = state.suggested_action;
        snapshot.load_state = state.load_state;
        snapshot.next_request_id = state.next_request_id;
        snapshot.last_completed_request_id = state.last_completed_request_id;
        snapshot.startup_epoch_ms = state.startup_epoch_ms;
        snapshot.last_update_epoch_ms = state.last_update_epoch_ms;
        snapshot.status_seq = state.status_seq;
        strncpy_s(snapshot.session_id, state.session_id, _TRUNCATE);
        strncpy_s(snapshot.fault_class, state.fault_class, _TRUNCATE);
        strncpy_s(snapshot.active_model, state.active_model, _TRUNCATE);
        strncpy_s(snapshot.last_error_tag, state.last_error_tag, _TRUNCATE);
        snapshot.inference.pending = state.inference.pending;
        snapshot.recovery_count = state.recovery_count;
        for (int i = 0; i < SharedLoaderState::kMaxRecoveryEvents; ++i) {
            snapshot.recovery_history[i] = state.recovery_history[i];
        }
    }

    char esc_model[MAX_PATH * 2] = {};
    char esc_tag[192] = {};
    char esc_session[128] = {};
    char esc_fault_class[64] = {};
    char esc_action[48] = {};
    JsonEscape(snapshot.active_model[0] ? snapshot.active_model : "none", esc_model, sizeof(esc_model));
    JsonEscape(snapshot.last_error_tag[0] ? snapshot.last_error_tag : "none", esc_tag, sizeof(esc_tag));
    JsonEscape(snapshot.session_id[0] ? snapshot.session_id : "none", esc_session, sizeof(esc_session));
    JsonEscape(snapshot.fault_class[0] ? snapshot.fault_class : "NONE", esc_fault_class, sizeof(esc_fault_class));
    JsonEscape(SuggestedActionToString(snapshot.suggested_action), esc_action, sizeof(esc_action));

    char history[2048] = "[";
    const int history_items = (snapshot.recovery_count < SharedLoaderState::kMaxRecoveryEvents)
                                  ? snapshot.recovery_count
                                  : SharedLoaderState::kMaxRecoveryEvents;
    const int start_idx = (snapshot.recovery_count > SharedLoaderState::kMaxRecoveryEvents)
                              ? (snapshot.recovery_count % SharedLoaderState::kMaxRecoveryEvents)
                              : 0;

    for (int i = 0; i < history_items; ++i) {
        const int idx = (start_idx + i) % SharedLoaderState::kMaxRecoveryEvents;
        const RecoveryEvent& evt = snapshot.recovery_history[idx];

        char esc_from[MAX_PATH * 2] = {};
        char esc_to[MAX_PATH * 2] = {};
        char esc_reason[192] = {};
        JsonEscape(evt.from_model, esc_from, sizeof(esc_from));
        JsonEscape(evt.to_model, esc_to, sizeof(esc_to));
        JsonEscape(evt.reason, esc_reason, sizeof(esc_reason));

        char item[512] = {};
        _snprintf_s(item, sizeof(item), _TRUNCATE,
                    "%s{\"timestamp\":\"%s\",\"from\":\"%s\",\"to\":\"%s\",\"reason\":\"%s\"}",
                    (i == 0 ? "" : ","),
                    evt.timestamp_utc[0] ? evt.timestamp_utc : "",
                    esc_from,
                    esc_to,
                    esc_reason);
        strncat_s(history, item, _TRUNCATE);
    }
    strncat_s(history, "]", _TRUNCATE);

    _snprintf_s(
        out,
        out_size,
        _TRUNCATE,
        "{\"status\":\"ok\",\"session_id\":\"%s\",\"startup_epoch_ms\":%llu,\"status_seq\":%llu,\"last_update_epoch_ms\":%llu,\"model_loaded\":%s,\"active_model\":\"%s\",\"loader_context\":{\"state\":\"%s\",\"last_error_tag\":\"%s\",\"win32_error_code\":%d,\"retry_count\":%d,\"retry_budget_rem\":%d,\"can_retry\":%s,\"terminal_fault\":%s,\"fault_class\":\"%s\",\"suggested_action\":\"%s\",\"pending_inference\":%s,\"last_completed_request_id\":%llu,\"unload_requested\":%s,\"recovery_history\":%s}}",
        esc_session,
        snapshot.startup_epoch_ms,
        snapshot.status_seq,
        snapshot.last_update_epoch_ms,
        snapshot.model_loaded ? "true" : "false",
        esc_model,
        LoaderStateToString(snapshot.load_state),
        esc_tag,
        snapshot.last_win32_error,
        snapshot.retry_count,
        snapshot.retry_budget_rem,
        snapshot.can_retry ? "true" : "false",
        snapshot.terminal_fault ? "true" : "false",
        esc_fault_class,
        esc_action,
        snapshot.inference.pending ? "true" : "false",
        snapshot.last_completed_request_id,
        snapshot.unload_requested ? "true" : "false",
        history);
}

inline void HandleRequest(SOCKET client, const char* request) {
    char method[8] = {};
    char path[128] = {};
    if (sscanf_s(request, "%7s %127s", method, static_cast<unsigned>(_countof(method)), path, static_cast<unsigned>(_countof(path))) != 2) {
        SendJsonResponse(client, 400, "Bad Request", "{\"error\":\"invalid_request_line\"}");
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        SendJsonResponse(client, 200, "OK", "{\"status\":\"ok\"}");
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) {
        char body[4096] = {};
        BuildStatusJson(body, sizeof(body));
        SendJsonResponse(client, 200, "OK", body);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/unload_model") == 0) {
        {
            auto& state = State();
            std::lock_guard<std::mutex> lock(state.mtx);
            state.unload_requested = true;
            state.model_loaded = false;
            state.load_state = LoaderApiState::Idle;
            RecomputePolicyLocked(state);
            TouchStatusLocked(state);
        }

        HWND hwnd = Rt().control_window;
        if (hwnd != nullptr) {
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
        }

        SendJsonResponse(client, 200, "OK", "{\"status\":\"unloaded\"}");
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/infer") == 0) {
        bool model_loaded = false;
        LoaderApiState load_state = LoaderApiState::Idle;
        char active_model[MAX_PATH] = {};
        char last_error_tag[96] = {};
        int last_win32_error = 0;
        {
            auto& state = State();
            std::lock_guard<std::mutex> lock(state.mtx);
            model_loaded = state.model_loaded;
            load_state = state.load_state;
            strncpy_s(active_model, state.active_model, _TRUNCATE);
            strncpy_s(last_error_tag, state.last_error_tag, _TRUNCATE);
            last_win32_error = state.last_win32_error;
        }

        if (load_state == LoaderApiState::Loading) {
            char body[512] = {};
            _snprintf_s(
                body,
                sizeof(body),
                _TRUNCATE,
                "{\"error\":\"model_loading\",\"state\":\"loading\",\"last_error_tag\":\"%s\"}",
                last_error_tag[0] ? last_error_tag : "none");
            SendJsonResponse(client, 425, "Too Early", body, "Retry-After: 1\r\n");
            return;
        }

        if (!model_loaded) {
            char body[512] = {};
            _snprintf_s(
                body,
                sizeof(body),
                _TRUNCATE,
                "{\"error\":\"model_not_ready\",\"state\":\"%s\",\"last_error_tag\":\"%s\",\"win32_error_code\":%d}",
                LoaderStateToString(load_state),
                last_error_tag[0] ? last_error_tag : "none",
                last_win32_error);
            SendJsonResponse(client, 409, "Conflict", body);
            return;
        }

        char prompt[2048] = {};
        char requirement[64] = {};
        ExtractJsonStringField(request, "prompt", prompt, sizeof(prompt));
        ExtractJsonStringField(request, "model_capability_requirement", requirement, sizeof(requirement));

        const bool needs_high_accuracy = (_stricmp(requirement, "high_accuracy") == 0);
        const bool is_small_fallback = (strstr(active_model, "TinyLlama") != nullptr) || (strstr(active_model, "1.1B") != nullptr);
        if (needs_high_accuracy && is_small_fallback) {
            char body[640] = {};
            _snprintf_s(
                body,
                sizeof(body),
                _TRUNCATE,
                "{\"error\":\"capability_mismatch\",\"active_model\":\"%s\",\"required\":\"high_accuracy\",\"last_error_tag\":\"%s\"}",
                active_model[0] ? active_model : "none",
                last_error_tag[0] ? last_error_tag : "none");
            SendJsonResponse(client, 409, "Conflict", body);
            return;
        }

        unsigned long long request_id = 0;
        if (!EnqueueInference(prompt, requirement, &request_id)) {
            SendJsonResponse(client, 429, "Too Many Requests", "{\"error\":\"inference_queue_busy\"}");
            return;
        }

        char body[256] = {};
        _snprintf_s(body, sizeof(body), _TRUNCATE,
                    "{\"status\":\"accepted\",\"request_id\":%llu}",
                    request_id);
        SendJsonResponse(client, 202, "Accepted", body);
        return;
    }

    SendJsonResponse(client, 404, "Not Found", "{\"error\":\"route_not_found\"}");
}

inline DWORD WINAPI ListenerThreadProc(LPVOID) {
    auto& rt = Rt();

    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        rt.running.store(false);
        return 1;
    }
    rt.wsa_started.store(true);

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        WSACleanup();
        rt.wsa_started.store(false);
        rt.running.store(false);
        return 1;
    }
    rt.listen_socket = listen_sock;

    const BOOL reuse = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(11435);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listen_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listen_sock);
        rt.listen_socket = INVALID_SOCKET;
        WSACleanup();
        rt.wsa_started.store(false);
        rt.running.store(false);
        return 1;
    }

    if (listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_sock);
        rt.listen_socket = INVALID_SOCKET;
        WSACleanup();
        rt.wsa_started.store(false);
        rt.running.store(false);
        return 1;
    }

    while (rt.running.load()) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(listen_sock, &read_set);

        timeval tv = {};
        tv.tv_sec = 0;
        tv.tv_usec = 200000;

        const int ready = select(0, &read_set, nullptr, nullptr, &tv);
        if (!rt.running.load()) {
            break;
        }
        if (ready <= 0) {
            continue;
        }

        SOCKET client = accept(listen_sock, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }

        char request[8192] = {};
        const int received = recv(client, request, static_cast<int>(sizeof(request) - 1), 0);
        if (received > 0) {
            request[received] = '\0';
            HandleRequest(client, request);
        } else {
            SendJsonResponse(client, 400, "Bad Request", "{\"error\":\"empty_request\"}");
        }
        closesocket(client);
    }

    if (rt.listen_socket != INVALID_SOCKET) {
        closesocket(rt.listen_socket);
        rt.listen_socket = INVALID_SOCKET;
    }

    if (rt.wsa_started.load()) {
        WSACleanup();
        rt.wsa_started.store(false);
    }

    rt.running.store(false);
    return 0;
}

inline bool StartNetworkThread() {
    auto& rt = Rt();
    if (rt.running.load()) {
        return true;
    }

    {
        auto& state = State();
        std::lock_guard<std::mutex> lock(state.mtx);
        InitializeSessionLocked(state);
        RecomputePolicyLocked(state);
    }

    rt.running.store(true);
    rt.thread = CreateThread(nullptr, 0, ListenerThreadProc, nullptr, 0, nullptr);
    if (!rt.thread) {
        rt.running.store(false);
        return false;
    }
    return true;
}

inline void StopNetworkThread() {
    auto& rt = Rt();
    if (!rt.running.load()) {
        if (rt.thread) {
            CloseHandle(rt.thread);
            rt.thread = nullptr;
        }
        return;
    }

    rt.running.store(false);

    if (rt.listen_socket != INVALID_SOCKET) {
        shutdown(rt.listen_socket, SD_BOTH);
        closesocket(rt.listen_socket);
        rt.listen_socket = INVALID_SOCKET;
    }

    if (rt.thread) {
        WaitForSingleObject(rt.thread, 2000);
        CloseHandle(rt.thread);
        rt.thread = nullptr;
    }
}

}  // namespace SovereignNetwork
