#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

static constexpr std::uint32_t RAWRXD_SCREENPILOT_ABI_V2 = 2;

// Permission bits are SERVER-DERIVED from mode. The browser never supplies them.
enum RawrXD_SP_PermissionV2 : std::uint64_t {
    RAWRXD_SP_PERM_READ              = 1ull << 0,
    RAWRXD_SP_PERM_SEARCH            = 1ull << 1,
    RAWRXD_SP_PERM_WORKSPACE_WRITE   = 1ull << 2,
    RAWRXD_SP_PERM_BUILD             = 1ull << 3,
    RAWRXD_SP_PERM_TEST              = 1ull << 4,
    RAWRXD_SP_PERM_PROCESS_GENERAL   = 1ull << 5,
    RAWRXD_SP_PERM_GIT_READ          = 1ull << 6,
    RAWRXD_SP_PERM_GIT_WRITE         = 1ull << 7,
    RAWRXD_SP_PERM_GIT_REMOTE        = 1ull << 8,
    RAWRXD_SP_PERM_NETWORK           = 1ull << 9,
    RAWRXD_SP_PERM_MODEL_CONTROL     = 1ull << 10,
    RAWRXD_SP_PERM_HOST_DESTRUCTIVE  = 1ull << 11,
};

struct RawrXD_SP_StringV2 {
    const char* data;
    std::size_t size;
};

struct RawrXD_SP_AgentRequestV2 {
    RawrXD_SP_StringV2 request_id;
    RawrXD_SP_StringV2 mode;       // ask | plan | build | agent
    RawrXD_SP_StringV2 model;
    RawrXD_SP_StringV2 workspace;  // canonical absolute path
    RawrXD_SP_StringV2 prompt;

    // SERVER-derived security contract.
    std::uint64_t permission_mask;
    std::uint64_t approval_required_mask;
    int workspace_only;            // always 1 in shipping configuration
};

using RawrXD_SP_EmitFnV2 =
    int (*)(void* emit_user,
            const char* event_type,
            const char* data,
            std::size_t data_size);

using RawrXD_SP_IsCancelledFnV2 =
    int (*)(void* cancel_user);

// The canonical Tool Authority calls this before an operation whose permission
// bit is included in request.approval_required_mask.
//
// Returns:
//   1 = approved once
//   0 = denied / timeout / cancelled
using RawrXD_SP_RequestApprovalFnV2 =
    int (*)(void* approval_user,
            const char* tool_name,
            const char* summary,
            const char* risk,
            std::uint64_t permission_bit);

struct RawrXD_SP_AuthorityV2 {
    std::uint32_t abi_version;
    void* user;

    // REQUIRED.
    // Must enter the SAME canonical Agent Coordinator / Tool Authority used by
    // native IDE + CLI. It must enforce permission_mask and workspace_only on
    // EVERY tool call, not only at request admission.
    int (*run_agent)(
        void* user,
        const RawrXD_SP_AgentRequestV2* request,
        RawrXD_SP_EmitFnV2 emit,
        void* emit_user,
        RawrXD_SP_IsCancelledFnV2 is_cancelled,
        void* cancel_user,
        RawrXD_SP_RequestApprovalFnV2 request_approval,
        void* approval_user
    );
};

struct RawrXD_SP_HttpRequestV2 {
    RawrXD_SP_StringV2 method;
    RawrXD_SP_StringV2 path;
    RawrXD_SP_StringV2 host;
    RawrXD_SP_StringV2 origin;
    RawrXD_SP_StringV2 session_token;
    RawrXD_SP_StringV2 content_type;
    RawrXD_SP_StringV2 body;
};

struct RawrXD_SP_HttpSinkV2 {
    void* user;
    int (*begin)(void* user, int status_code, const char* content_type, int chunked);
    int (*header)(void* user, const char* name, const char* value);
    int (*write)(void* user, const char* data, std::size_t size);
    int (*end)(void* user);
};

struct RawrXD_SP_ConfigV2 {
    std::uint32_t abi_version;
    std::uint16_t port;
    RawrXD_SP_StringV2 workspace_root;

    // Shipping: 0. Enable only during an explicitly insecure file:// dev test.
    int allow_null_origin;

    // Hard request bounds enforced by the adapter.
    std::size_t max_body_bytes;    // recommended 8 MiB
    std::size_t max_prompt_bytes;  // recommended 4 MiB

    // Approval wait timeout. Recommended 120000 ms.
    std::uint32_t approval_timeout_ms;
};

int RawrXD_ScreenPilot_InitializeV2(
    const RawrXD_SP_ConfigV2* config,
    const RawrXD_SP_AuthorityV2* authority);

void RawrXD_ScreenPilot_ShutdownV2();

// Returns 1 if handled, 0 if this is not a ScreenPilot route.
int RawrXD_ScreenPilot_HandleHttpV2(
    const RawrXD_SP_HttpRequestV2* request,
    const RawrXD_SP_HttpSinkV2* sink);

// Use this from existing LocalServer middleware to require the SAME browser
// session on legacy privileged /api/* routes (read/write/cli/git/tool/etc).
int RawrXD_ScreenPilot_ValidateBrowserSessionV2(
    RawrXD_SP_StringV2 host,
    RawrXD_SP_StringV2 origin,
    RawrXD_SP_StringV2 session_token);

// Server-side canonical mode policy.
std::uint64_t RawrXD_ScreenPilot_ModePermissionsV2(RawrXD_SP_StringV2 mode);
std::uint64_t RawrXD_ScreenPilot_ModeApprovalMaskV2(RawrXD_SP_StringV2 mode);

} // extern "C"
