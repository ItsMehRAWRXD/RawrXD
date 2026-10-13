// =============================================================================
// WorkspaceToolHost.h — Workspace Tools with Certificates and Path Policy
// =============================================================================
// Addresses the three confirmed RAWRXD_SELF_AUDIT_001 defects at the tool layer:
//
//   1. PATH RESOLUTION: the model passed "What RawrXD Is" and "TODO" as
//      filesystem paths, so valid searches were rejected. Fixes applied here:
//        - The canonical workspace root is supplied to every tool at session
//          init and tools default to it when `path` is omitted.
//        - `search_text` treats `path` as a directory root and `query` as the
//          needle. A phrase never becomes a path implicitly.
//        - `list_repo` returns STRUCTURED entries (name/type/size), not prose.
//        - A rejected path returns permitted alternatives in the error text so
//          the model can correct itself instead of probing the disk.
//        - A path outside the workspace is NEVER widened to the filesystem root.
//
//   2. BUILD CERTIFICATE: `run_build ok=1` is replaced by a BuildEvidence
//      record built from the real process exit code, parsed compiler
//      diagnostics, artifact existence on disk, and a persisted log file.
//      `ok` is derived, never self-reported.
//
//   3. The ledger's tool records carry args, results, approval state and
//      denial reasons so failures are auditable after the fact.
// =============================================================================
#pragma once

#include "tool_core.hpp"
#include "AgentSession.h"
#include "AgentMode.h"

#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Agent {

// ---------------------------------------------------------------------------
// Structured directory entry (list_repo returns these, not raw text)
// ---------------------------------------------------------------------------
struct DirEntry {
    std::string name;
    std::string type;      // "directory" | "file"
    uint64_t    size = 0;
};

// ---------------------------------------------------------------------------
// Search hit
// ---------------------------------------------------------------------------
struct SearchHit {
    std::string path;
    int         line = 0;
    std::string text;
};

// ---------------------------------------------------------------------------
// WorkspaceToolHost
// ---------------------------------------------------------------------------
class WorkspaceToolHost {
public:
    using ApprovalFn = std::function<bool(const std::string& tool_name, const json& args)>;

    explicit WorkspaceToolHost(std::string workspace_root);

    // ---- Registration ----
    void RegisterWorkspaceTools(rawrxd::tools::Registry& registry) const;

    // ---- Structured operations (used by the CLI and tests directly) ----
    std::vector<DirEntry> ListRepo(const std::string& path, std::string& error) const;
    std::vector<SearchHit> SearchText(const std::string& query,
                                      const std::string& path,
                                      std::string& error) const;
    std::vector<DirEntry> FindFiles(const std::string& pattern,
                                    const std::string& path,
                                    std::string& error) const;

    // ---- Certified build ----
    // Runs the build, parses diagnostics, verifies artifacts, writes the log.
    BuildEvidence RunBuild(const std::string& target,
                           const std::string& config,
                           const std::string& evidence_dir,
                           int timeout_minutes = 10) const;

    // ---- Certified test run ----
    TestEvidence RunTests(const std::string& filter,
                          const std::string& evidence_dir,
                          int timeout_minutes = 5) const;

    // ---- Path policy ----
    // Returns the resolved absolute path if it is inside the workspace,
    // otherwise empty and `error` lists permitted alternatives.
    std::filesystem::path ResolveInWorkspace(const std::string& path,
                                             std::string& error) const;
    const std::string& WorkspaceRoot() const { return m_root; }

    // ---- Approval ----
    void SetApproval(ApprovalFn fn) { m_approval = std::move(fn); }
    bool IsApproved(const std::string& tool_name, const json& args) const;

private:
    std::string m_root;
    ApprovalFn  m_approval;

    bool IsRegularTextFile(const std::filesystem::path& p, std::error_code& ec) const;
    std::string SuggestAlternatives(const std::string& bad_path) const;
    int CountCompilerErrors(const std::string& log) const;
    int CountCompilerWarnings(const std::string& log) const;
    bool VerifyArtifact(const std::filesystem::path& build_dir,
                        const std::string& target,
                        std::vector<std::string>& found) const;
    std::string RunProcess(const std::string& cmd, int& exit_code, int timeout_minutes) const;
};

} // namespace Agent
} // namespace RawrXD
