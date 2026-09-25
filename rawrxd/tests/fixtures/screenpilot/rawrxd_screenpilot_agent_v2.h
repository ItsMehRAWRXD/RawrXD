#pragma once
#include <cstddef>
#include <cstdint>
extern "C" {
enum RawrXD_SP_PermissionV2 : std::uint64_t {
    RAWRXD_SP_PERM_READ = 1ull << 0,
    RAWRXD_SP_PERM_SEARCH = 1ull << 1,
    RAWRXD_SP_PERM_WORKSPACE_WRITE = 1ull << 2,
    RAWRXD_SP_PERM_BUILD = 1ull << 3,
    RAWRXD_SP_PERM_TEST = 1ull << 4,
    RAWRXD_SP_PERM_PROCESS_GENERAL = 1ull << 5,
    RAWRXD_SP_PERM_GIT_READ = 1ull << 6,
    RAWRXD_SP_PERM_GIT_WRITE = 1ull << 7,
    RAWRXD_SP_PERM_GIT_REMOTE = 1ull << 8,
    RAWRXD_SP_PERM_NETWORK = 1ull << 9,
    RAWRXD_SP_PERM_MODEL_CONTROL = 1ull << 10,
    RAWRXD_SP_PERM_HOST_DESTRUCTIVE = 1ull << 11,
};
struct RawrXD_SP_StringV2 { const char* data; std::size_t size; };
struct RawrXD_SP_AgentRequestV2 {
    RawrXD_SP_StringV2 request_id, mode, model, workspace, prompt;
    std::uint64_t permission_mask;
    std::uint64_t approval_required_mask;
    int workspace_only;
};
using RawrXD_SP_IsCancelledFnV2 = int (*)(void*);
using RawrXD_SP_RequestApprovalFnV2 = int (*)(void*, const char*, const char*, const char*, std::uint64_t);
}
