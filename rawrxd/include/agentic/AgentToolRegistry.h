// ============================================================================
// AgentToolRegistry.h — RAWRXD_AGENTIC_TOOL_REGISTRY_001
// Registry for agent tools plus the built-in Win32 tool set.
//
// Threading contract: the registry mutex is released before any executor runs.
// An executor may therefore call back into Execute (for example search_code
// delegating to read_file) without deadlocking.
// ============================================================================
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd {
namespace agentic {

struct ToolParam {
    std::string name;
    std::string type;
    std::string description;
    bool required = false;
};

struct ToolDef {
    std::string name;
    std::string description;
    std::vector<ToolParam> params;
};

struct ToolResult {
    bool success = false;
    std::string output;
    std::string error;
    std::uint64_t elapsedMicros = 0;
    std::uint32_t outputBytesTruncated = 0;  // non-zero when output hit the cap
};

using ToolExecutor = std::function<ToolResult(const std::unordered_map<std::string, std::string>&)>;

// Path access policy. An empty allowRoot means "no filesystem tool is enabled",
// which is the safe default: tools must be opted into explicitly.
struct ToolPolicy {
    std::vector<std::string> allowedRoots;  // canonical absolute prefixes
    std::size_t maxOutputBytes = 1u << 20;  // 1 MiB per tool result
    std::size_t maxFileReadBytes = 4u << 20;
    std::size_t maxSearchFileBytes = 16u << 20;
    std::uint32_t maxSearchMatches = 500;
    bool allowWrite = false;
    bool allowExecute = false;
    std::uint32_t executeTimeoutMs = 60000;
    // RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
    //
    // allowWrite alone authorises an unjournaled autonomous edit. The file is
    // published atomically, so a crash cannot truncate it, but nothing records
    // what the file was before, so nothing can put it back: the agent's edit is
    // permanent whether or not the turn that produced it succeeded.
    //
    // With this flag set, write_file is refused unless a checkpoint transaction
    // (ckpt::Transaction) is open AND the target resolves inside that
    // transaction's workspace root AND is not inside the .rawrxd\ckpt tree
    // itself. Every accepted write is then journalled with its before-state and
    // is undoable by rollback or by the startup recovery pass.
    //
    // This is a refusal, not a warning. A write that cannot be rolled back is
    // not an autonomous edit; it is an unrecoverable mutation.
    bool writeRequiresTransaction = false;

    // RAWRXD_GIT_TRANSACTION_AUTHORITY_001
    //
    // The same promise extends to every OTHER tool that mutates state. Measured
    // on 2026-10-01: with capability and scope granted, `git_stage` moved the
    // repository index with no transaction open and wrote zero journal records,
    // so write_file was transactional while the git mutation path was not.
    //
    // Each name listed here is refused unless a transaction is open, exactly as
    // write_file is. The list is explicit because a registry cannot infer which
    // tool mutates -- git_status and git_stage have identical signatures.
    //
    // UncoveredMutatingTools() exists so the list cannot be quietly wrong: a
    // registered tool whose NAME implies mutation but which is absent from this
    // list is reported, because a typo in a security list is a silent hole.
    std::vector<std::string> transactionRequiredTools;

    static ToolPolicy DefaultDenyAll();
};

// Returns true when `candidate` resolves inside one of the allowed roots.
// Rejects traversal, UNC, device and ADS paths by requiring the canonical form
// to start with a canonical root plus a separator.
//
// `outError`, when given, receives the SPECIFIC reason for a refusal ("resolved
// path escapes the allowed root", "path crosses a reparse point (junction or
// link) inside the root", "UNC paths are not permitted", ...). Without it a
// caller can only say "rejected", which is indistinguishable from a policy that
// does not exist and from a path that simply does not exist.
bool IsPathAllowed(const ToolPolicy& policy, const std::string& candidate,
                   std::string& outCanonical, std::string* outError = nullptr);

// Canonicalises a configured root: resolves it to an absolute, separator-
// normalised form using the same rules the tools use, and rejects UNC, device
// and stream paths. An embedder must call this before putting a root into a
// policy. A root left as a relative string still works for IsPathAllowed (the
// join resolves it against the process CWD) but it can never be compared
// against a canonical absolute path, which is what the transactional write
// profile has to do.
bool CanonicalizeRoot(const std::string& path, std::string& outCanonical, std::string& outError);

// True when `absPath` is canonical and already resolves inside one of the
// allowed roots. Use this for a caller that already holds an absolute path
// (a transaction workspace root, for example) -- IsPathAllowed takes a
// root-relative candidate and cannot be given one.
bool IsCanonicalPathAllowed(const ToolPolicy& policy, const std::string& absPath);

// RAWRXD_GIT_TRANSACTION_AUTHORITY_001
// True when `toolName` is in policy.transactionRequiredTools.
bool IsTransactionRequired(const std::string& toolName, const ToolPolicy& policy);

// True when `toolName` contains a verb that implies mutation. A heuristic, and
// deliberately so: it exists to make a mistake in transactionRequiredTools
// VISIBLE, not to stand in for the list.
bool ToolNameLooksMutating(const std::string& toolName);

// Every registered tool whose name implies mutation but which is absent from
// policy.transactionRequiredTools. An empty result is the only state in which
// the transactional write profile can honestly claim to cover every mutating
// tool.
std::vector<std::string> UncoveredMutatingTools(const class ToolRegistry& registry,
                                                const ToolPolicy& policy);

class ToolRegistry {
public:
    static ToolRegistry& Instance();

    void Register(const ToolDef& def, ToolExecutor exec);
    bool Unregister(const std::string& name);

    ToolResult Execute(const std::string& name,
                       const std::unordered_map<std::string, std::string>& params);

    // Deterministic: tools are emitted in name order, never hash order, so the
    // system prompt is byte-stable across runs and across processes.
    std::string BuildSystemPrompt() const;

    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
    //
    // The live tool set as data, in name order. The tool protocol authority
    // needs the parameter names to decide whether a call is valid, and it must
    // decide it against what is actually installed rather than against a copy
    // that can drift. A name the authority does not see is a name it refuses.
    std::vector<ToolDef> GetDefs() const;

    std::vector<std::string> GetToolNames() const;
    bool HasTool(const std::string& name) const;
    std::size_t Size() const;

    void SetPolicy(const ToolPolicy& policy);
    ToolPolicy GetPolicy() const;

    // Installs read_file, write_file, list_directory, search_code,
    // execute_command. Writes and process execution are refused unless the
    // policy enables them.
    void InstallBuiltinTools();

    // Truncates to the policy cap, recording how many bytes were dropped.
    static void CapOutput(ToolResult& result, const ToolPolicy& policy);

private:
    ToolRegistry() = default;

    mutable std::mutex mtx_;
    std::unordered_map<std::string, ToolDef> defs_;
    std::unordered_map<std::string, ToolExecutor> executors_;
    ToolPolicy policy_ = ToolPolicy::DefaultDenyAll();
};

} // namespace agentic
} // namespace rawrxd
