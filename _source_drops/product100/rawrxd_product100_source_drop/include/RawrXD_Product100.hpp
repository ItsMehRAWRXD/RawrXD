#pragma once

// RawrXD Product Finish 100 source overlay.
// No third-party dependencies: Win32 + toolchain C++ + x64 MASM object only.
// This module is intentionally fail-closed.  Smoke/evidence APIs never mark PASS
// unless the host IDE supplies real callbacks and those callbacks return success.

#include <stddef.h>
#include <stdint.h>

#ifndef P100_API
#  define P100_API extern "C"
#endif

#ifndef P100_CALL
#  ifdef _WIN32
#    define P100_CALL __stdcall
#  else
#    define P100_CALL
#  endif
#endif

#define P100_PATH_CCH      520u
#define P100_TEXT_CCH      4096u
#define P100_PREVIEW_CCH   768u
#define P100_NAME_CCH      96u
#define P100_PLAN_MAX      128u

enum P100_Status : int32_t {
    P100_OK = 0,
    P100_E_INVALID_ARG = -1,
    P100_E_NOT_INITIALIZED = -2,
    P100_E_ACCESS_DENIED = -3,
    P100_E_PROCESS_FAILED = -4,
    P100_E_IO = -5,
    P100_E_NOT_FOUND = -6,
    P100_E_BUFFER_TOO_SMALL = -7,
    P100_E_MISSING_CALLBACK = -8,
    P100_E_SMOKE_FAILED = -9,
    P100_E_MASM_NOT_LINKED = -10
};

enum P100_Capability : uint64_t {
    P100_CAP_READ          = 1ull << 0,
    P100_CAP_SEARCH        = 1ull << 1,
    P100_CAP_EDIT          = 1ull << 2,
    P100_CAP_DESTRUCTIVE   = 1ull << 3,
    P100_CAP_COMMAND       = 1ull << 4,
    P100_CAP_GIT_READ      = 1ull << 5,
    P100_CAP_GIT_WRITE     = 1ull << 6,
    P100_CAP_SETTINGS      = 1ull << 7,
    P100_CAP_PERSISTENCE   = 1ull << 8,
    P100_CAP_TERMINAL      = 1ull << 9
};

enum P100_ApprovalState : uint32_t {
    P100_APPROVAL_PENDING = 0,
    P100_APPROVAL_APPROVED = 1,
    P100_APPROVAL_DENIED = 2,
    P100_APPROVAL_APPLIED = 3,
    P100_APPROVAL_REJECTED = 4
};

enum P100_PlanStepState : uint32_t {
    P100_PLAN_PENDING = 0,
    P100_PLAN_RUNNING = 1,
    P100_PLAN_PASS = 2,
    P100_PLAN_FAIL = 3,
    P100_PLAN_SKIPPED = 4
};

typedef void (P100_CALL *P100_TextSink)(
    const wchar_t* channel,
    const wchar_t* text,
    void* user);

typedef int32_t (P100_CALL *P100_SearchHitSink)(
    const struct P100_SearchHit* hit,
    void* user);

typedef int32_t (P100_CALL *P100_SmokeStepFn)(
    const wchar_t* step_name,
    void* user);

struct P100_Context {
    uint32_t size;
    wchar_t workspace[P100_PATH_CCH];
    wchar_t evidence_dir[P100_PATH_CCH];
    uint64_t capabilities;
    P100_TextSink sink;
    void* sink_user;
};

struct P100_RunResult {
    int32_t exit_code;
    uint32_t timed_out;
    uint64_t stdout_bytes;
    uint64_t stderr_bytes;
    uint64_t seal64;
};

struct P100_SearchHit {
    wchar_t path[P100_PATH_CCH];
    uint32_t line;
    uint32_t column;
    wchar_t preview[P100_PREVIEW_CCH];
    uint64_t seal64;
};

struct P100_SettingsV1 {
    uint32_t size;
    wchar_t model_path[P100_PATH_CCH];
    uint32_t context_tokens;
    float temperature;
    wchar_t gpu_split[P100_NAME_CCH];
    uint32_t reasoning_control;
    uint32_t output_control;
};

struct P100_SessionV1 {
    uint32_t size;
    wchar_t workspace[P100_PATH_CCH];
    wchar_t model_path[P100_PATH_CCH];
    wchar_t mode[P100_NAME_CCH];
    wchar_t history_path[P100_PATH_CCH];
    wchar_t plan_path[P100_PATH_CCH];
    uint32_t plan_step_count;
    uint32_t active_plan_step;
    uint32_t plan_states[P100_PLAN_MAX];
};

struct P100_ApprovalV1 {
    uint32_t size;
    uint64_t id;
    uint64_t required_capabilities;
    uint32_t state;
    wchar_t verb[P100_NAME_CCH];
    wchar_t target[P100_PATH_CCH];
    wchar_t detail[P100_TEXT_CCH];
    uint64_t seal64;
};

struct P100_SmokeHostV1 {
    uint32_t size;
    P100_SmokeStepFn load_gguf;
    P100_SmokeStepFn ask_send;
    P100_SmokeStepFn plan_checklist;
    P100_SmokeStepFn approve_plan;
    P100_SmokeStepFn agent_read_search;
    P100_SmokeStepFn build_edit_diff;
    P100_SmokeStepFn apply_edit;
    P100_SmokeStepFn terminal_run;
    P100_SmokeStepFn agent_observe_repair;
    P100_SmokeStepFn git_diff_commit;
    P100_SmokeStepFn stop_cancel;
    P100_SmokeStepFn restart_restore;
    void* user;
};

struct P100_FreezeInputV1 {
    uint32_t size;
    wchar_t exe_sha256[80];
    wchar_t e2e_log_path[P100_PATH_CCH];
    wchar_t e2e_finalize[16];
    wchar_t model_path[P100_PATH_CCH];
    wchar_t wave1_verdict[P100_PATH_CCH];
    wchar_t wave2_verdict[P100_PATH_CCH];
    wchar_t wave3_verdict[P100_PATH_CCH];
    wchar_t wave4_verdict[P100_PATH_CCH];
    wchar_t known_gaps[P100_TEXT_CCH];
};

P100_API int32_t P100_CALL P100_Init(const P100_Context* ctx);
P100_API int32_t P100_CALL P100_Shutdown(void);
P100_API uint64_t P100_CALL P100_SourceSeal64(const void* data, uint64_t bytes);
P100_API int32_t P100_CALL P100_DescribeError(int32_t status, const wchar_t* detail, wchar_t* out_text, uint32_t out_cch);

P100_API int32_t P100_CALL P100_GitStatus(wchar_t* out_text, uint32_t out_cch, P100_RunResult* result);
P100_API int32_t P100_CALL P100_GitDiff(wchar_t* out_text, uint32_t out_cch, P100_RunResult* result);
P100_API int32_t P100_CALL P100_GitStage(const wchar_t* repo_relative_path, P100_RunResult* result);
P100_API int32_t P100_CALL P100_GitUnstage(const wchar_t* repo_relative_path, P100_RunResult* result);
P100_API int32_t P100_CALL P100_GitCommit(const wchar_t* message, wchar_t* out_text, uint32_t out_cch, P100_RunResult* result);

P100_API int32_t P100_CALL P100_SearchWorkspaceLiteral(const wchar_t* literal, uint32_t case_insensitive, uint32_t max_hits, P100_SearchHitSink sink, void* user);
P100_API int32_t P100_CALL P100_SearchWorkspaceSymbol(const wchar_t* symbol, uint32_t max_hits, P100_SearchHitSink sink, void* user);

P100_API int32_t P100_CALL P100_SaveSettings(const P100_SettingsV1* settings);
P100_API int32_t P100_CALL P100_LoadSettings(P100_SettingsV1* settings);
P100_API int32_t P100_CALL P100_SaveSession(const P100_SessionV1* session);
P100_API int32_t P100_CALL P100_LoadSession(P100_SessionV1* session);

P100_API int32_t P100_CALL P100_AddApproval(const P100_ApprovalV1* request, uint64_t* out_id);
P100_API int32_t P100_CALL P100_ListApprovals(P100_ApprovalV1* out_items, uint32_t capacity, uint32_t* out_count);
P100_API int32_t P100_CALL P100_DecideApproval(uint64_t id, uint32_t approved);

P100_API int32_t P100_CALL P100_RunSmokeMatrix(const P100_SmokeHostV1* host, const wchar_t* evidence_dir);
P100_API int32_t P100_CALL P100_WriteFreezeManifest(const P100_FreezeInputV1* input, const wchar_t* evidence_dir);

