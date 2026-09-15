#include "LegacyRawrXDToolProviders.hpp"
#include "RawrXD_ToolRegistry.h"

#include <stdexcept>
#include <utility>

namespace RawrXD::Agentic {
namespace {

int legacyExitCode(RawrXD::Agent::ToolResult r) noexcept {
    using Legacy = RawrXD::Agent::ToolResult;
    switch (r) {
        case Legacy::Success:          return 0;
        case Legacy::ValidationFailed: return 64;
        case Legacy::SandboxBlocked:   return 77;
        case Legacy::ExecutionError:   return 1;
        case Legacy::Timeout:          return 124;
        case Legacy::Cancelled:        return 130;
        default:                       return 1;
    }
}

AgentToolRegistry::Handler adaptLegacy(std::string legacy_name) {
    return [legacy_name = std::move(legacy_name)](
               const ToolRequest& request,
               ToolContext&) -> ToolResult {

        auto& legacy = RawrXD::Agent::ToolRegistry::Instance();

        if (!request.working_directory.empty()) {
            legacy.SetProjectRoot(request.working_directory.wstring());
        }

        std::string output;
        const std::string json_args =
            request.stdin_text.empty() ? "{}" : request.stdin_text;

        const auto legacy_result =
            legacy.Execute(legacy_name, json_args, output);

        ToolResult result;
        result.exit_code = legacyExitCode(legacy_result);
        if (result.exit_code == 0) {
            result.stdout_text = std::move(output);
        } else {
            result.stderr_text = std::move(output);
        }
        return result;
    };
}

void registerIfMissing(
    AgentToolRegistry& authority,
    ToolDescriptor descriptor,
    AgentToolRegistry::Handler handler) {

    if (authority.contains(descriptor.id)) return;
    try {
        authority.registerTool(std::move(descriptor), std::move(handler));
    } catch (const std::invalid_argument&) {
        if (!authority.contains(descriptor.id)) throw;
    }
}

} // namespace

void RegisterLegacyRawrXDToolProviders(AgentToolRegistry& authority) {
    registerIfMissing(
        authority,
        {"code-edit", {"CodeEdit", "code_edit"}, "Existing RawrXD CodeEdit provider."},
        adaptLegacy("CodeEdit"));

    registerIfMissing(
        authority,
        {"build-project", {"BuildProject", "build_project"}, "Existing RawrXD BuildProject provider."},
        adaptLegacy("BuildProject"));

    registerIfMissing(
        authority,
        {"static-analysis", {"StaticAnalysis", "static_analysis"}, "Existing RawrXD StaticAnalysis provider."},
        adaptLegacy("StaticAnalysis"));

    registerIfMissing(
        authority,
        {"git-operation", {"GitOperation", "git_operation"}, "Existing RawrXD GitOperation provider."},
        adaptLegacy("GitOperation"));
}

} // namespace RawrXD::Agentic
