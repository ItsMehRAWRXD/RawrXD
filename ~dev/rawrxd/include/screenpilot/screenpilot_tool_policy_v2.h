#pragma once
#include "rawrxd_screenpilot_agent_v2.h"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace rawrxd::screenpilot {

// This is a policy helper ONLY. It never executes a tool.
// Call it inside the canonical Tool Authority before every tool invocation.

enum class ToolClass {
    Unknown,
    Read,
    Search,
    WorkspaceWrite,
    Build,
    Test,
    ProcessGeneral,
    GitRead,
    GitWrite,
    GitRemote,
    Network,
    ModelControl,
    HostDestructive
};

inline ToolClass ClassifyTool(std::string_view name) {
    // Keep this table intentionally fail-closed.
    if (name == "read_file" || name == "list_directory" ||
        name == "file_stat" || name == "read_range") {
        return ToolClass::Read;
    }

    if (name == "search_files" || name == "grep" ||
        name == "find_symbol" || name == "index_query") {
        return ToolClass::Search;
    }

    if (name == "write_file" || name == "patch_file" ||
        name == "delete_file" || name == "move_file" ||
        name == "mkdir" || name == "apply_patch") {
        return ToolClass::WorkspaceWrite;
    }

    if (name == "build" || name == "cmake_build" ||
        name == "compile" || name == "assemble") {
        return ToolClass::Build;
    }

    if (name == "test" || name == "run_tests" ||
        name == "ctest" || name == "smoke_gate") {
        return ToolClass::Test;
    }

    if (name == "run_command" || name == "terminal_exec" ||
        name == "process_exec") {
        return ToolClass::ProcessGeneral;
    }

    if (name == "git_status" || name == "git_diff" ||
        name == "git_log" || name == "git_show") {
        return ToolClass::GitRead;
    }

    if (name == "git_add" || name == "git_commit" ||
        name == "git_checkout_local" || name == "git_restore") {
        return ToolClass::GitWrite;
    }

    if (name == "git_push" || name == "git_pull" ||
        name == "git_fetch" || name == "git_remote") {
        return ToolClass::GitRemote;
    }

    if (name == "http_get" || name == "http_post" ||
        name == "browser_fetch" || name == "download") {
        return ToolClass::Network;
    }

    if (name == "model_load" || name == "model_unload" ||
        name == "model_switch" || name == "engine_swap") {
        return ToolClass::ModelControl;
    }

    if (name == "shutdown" || name == "reboot" ||
        name == "service_install" || name == "driver_change" ||
        name == "delete_outside_workspace") {
        return ToolClass::HostDestructive;
    }

    return ToolClass::Unknown;
}

inline std::uint64_t PermissionBit(ToolClass c) {
    switch (c) {
        case ToolClass::Read:             return RAWRXD_SP_PERM_READ;
        case ToolClass::Search:           return RAWRXD_SP_PERM_SEARCH;
        case ToolClass::WorkspaceWrite:   return RAWRXD_SP_PERM_WORKSPACE_WRITE;
        case ToolClass::Build:            return RAWRXD_SP_PERM_BUILD;
        case ToolClass::Test:             return RAWRXD_SP_PERM_TEST;
        case ToolClass::ProcessGeneral:   return RAWRXD_SP_PERM_PROCESS_GENERAL;
        case ToolClass::GitRead:          return RAWRXD_SP_PERM_GIT_READ;
        case ToolClass::GitWrite:         return RAWRXD_SP_PERM_GIT_WRITE;
        case ToolClass::GitRemote:        return RAWRXD_SP_PERM_GIT_REMOTE;
        case ToolClass::Network:          return RAWRXD_SP_PERM_NETWORK;
        case ToolClass::ModelControl:     return RAWRXD_SP_PERM_MODEL_CONTROL;
        case ToolClass::HostDestructive:  return RAWRXD_SP_PERM_HOST_DESTRUCTIVE;
        case ToolClass::Unknown:          return 0;
    }
    return 0;
}

inline bool IsAllowed(
    const RawrXD_SP_AgentRequestV2& request,
    std::string_view tool_name)
{
    const auto c = ClassifyTool(tool_name);
    const auto bit = PermissionBit(c);
    return bit != 0 && (request.permission_mask & bit) != 0;
}

inline bool NeedsApproval(
    const RawrXD_SP_AgentRequestV2& request,
    std::string_view tool_name)
{
    const auto bit = PermissionBit(ClassifyTool(tool_name));
    return bit != 0 && (request.approval_required_mask & bit) != 0;
}

// Windows path confinement must be applied to EACH path-bearing tool argument.
// Do not treat request.workspace admission as sufficient.
inline bool PathUnderWorkspace(
    const std::filesystem::path& canonical_workspace,
    const std::filesystem::path& candidate)
{
    try {
        const auto root = std::filesystem::weakly_canonical(canonical_workspace);
        const auto child = std::filesystem::weakly_canonical(candidate);

        auto r = root.begin();
        auto c = child.begin();

        for (; r != root.end(); ++r, ++c) {
            if (c == child.end()) return false;

            std::wstring rs = r->wstring();
            std::wstring cs = c->wstring();
            std::transform(rs.begin(), rs.end(), rs.begin(), ::towlower);
            std::transform(cs.begin(), cs.end(), cs.begin(), ::towlower);

            if (rs != cs) return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace rawrxd::screenpilot
