#pragma once
// Concrete, instrumented operations. Authorization belongs to the caller's tool policy.
#include "RawrSwarmEvents.hpp"
#include <filesystem>
#include <string>

namespace rawr::live {
struct ToolResult {
    bool ok=false;
    int exitCode=-1;
    std::string value;     // actual file contents for read, actual error for failures
};

// All file paths MUST remain within the canonical workspace root.
// readText uses a size limit; callers may request a smaller cap.
ToolResult readText(Sink& sink, const std::filesystem::path& workspace,
                    const std::filesystem::path& relativePath,
                    const std::string& worker, size_t maxBytes=2*1024*1024);

// Replace exactly one occurrence; fail closed on missing/ambiguous text.
// Persists actual diff preview from old/new bytes. Caller must authorize file modification.
ToolResult editExact(Sink& sink, const std::filesystem::path& workspace,
                     const std::filesystem::path& relativePath,
                     std::string_view expected, std::string_view replacement,
                     const std::string& worker);

#ifdef _WIN32
// Real CreateProcessW + piped stdout/stderr. No shell implicit; exe/args explicit.
// Caller MUST enforce the mode's execute permission and command allowlist.
ToolResult runProcess(Sink& sink,const std::wstring& exe,const std::wstring& args,
                      const std::wstring& workingDirectory,const std::string& worker,
                      uint32_t timeoutMs=300000);
#endif
}
