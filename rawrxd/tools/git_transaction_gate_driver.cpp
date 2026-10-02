// git_transaction_gate_driver.cpp
//   RAWRXD_GIT_TRANSACTION_AUTHORITY_001 -- G0..G4
//
// B83 V2 registered thirteen git-safety tools into the same sandboxed registry
// that /api/agent/execute-tool dispatches through, and certified none of them.
// This driver measures the first five gate conditions against a REAL git
// repository created here, so that nothing is asserted from source reading:
//
//   G0  enumerate the registered git tools
//   G1  bind each registered name to the authority call it reaches
//   G2  establish a clean/dirty baseline
//   G3  run the read-only tools; prove they mutate nothing
//   G4  a mutating tool must require an active transaction/journal authority
//
// G4 is the condition this driver exists to test, and it is the one the B83
// write profile implies must hold: write_file refuses to run without a
// checkpoint transaction, so an agent that can mutate the repository through
// git_commit while write_file cannot mutate a file is a hole in the same
// promise. This driver reports what it measures either way; it does not assume
// the answer, and it does not patch the answer.
//
// The negative control (G14/G15) lives in the PowerShell wrapper, which rebuilds
// this driver against a copy of the authority with the transaction gate removed
// and requires the gate to be DETECTED.
//
// Verdict vocabulary is the project standard, not PASS/FAIL:
//   CONTRACT_SATISFIED | CONTRACT_VIOLATED | DEFECT_DETECTED | NO_VERDICT
//
// Usage
//   git_transaction_gate_driver <scratch-dir>
//   exit 0 iff every gate condition whose expectation is stated in the table
//   below is met.

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include "agentic/AgentToolRegistry.h"
#include "agentic/CheckpointRollbackAuthority.h"
#include "agentic/GitSafetyAuthority.h"
#include "agentic/GitSafetyAuthorityTools.h"

namespace {

using namespace rawrxd;

int g_checks = 0;
int g_violations = 0;

void Say(const std::string& line) { std::printf("%s\n", line.c_str()); }

void Check(const std::string& name, bool passed, const std::string& evidence) {
    g_checks++;
    if (!passed) g_violations++;
    std::printf("  %-46s %-16s %s%s\n", name.c_str(),
                passed ? "AS_EXPECTED" : "UNEXPECTED", evidence.c_str(),
                passed ? "" : "   <-- GATE CONDITION NOT MET");
}

// Runs a real git command INSIDE `cwd` and returns its combined output.
// The working directory is set with `cd /d` inside the same cmd, because
// _popen has no directory parameter. Getting this wrong is silent: git then
// runs wherever the process happened to be, returns "not a git repository",
// and every measurement downstream compares two identical failures.
std::string GitIn(const std::string& cwd, const std::string& args) {
    const std::string cmd =
        "cmd /d /c \"cd /d \"" + cwd + "\" && git " + args + " 2>&1\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return std::string("<popen failed>");
    std::string out;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe)) out += buffer;
    _pclose(pipe);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out;
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                        nullptr, 0);
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], n);
    return out;
}

void WriteFile(const std::string& path, const std::string& text) {
    HANDLE h = ::CreateFileW(Widen(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    ::WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    ::CloseHandle(h);
}

std::string ReadFile(const std::string& path) {
    HANDLE h = ::CreateFileW(Widen(path).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    std::string out;
    char buffer[4096];
    DWORD got = 0;
    while (::ReadFile(h, buffer, sizeof(buffer), &got, nullptr) && got > 0) out.append(buffer, got);
    ::CloseHandle(h);
    return out;
}

// The exact state a mutating tool would have to preserve.
struct RepoState {
    std::string head;
    std::string status;
    std::string branch;
    std::string indexTree;  // write-tree of the index, or its error
};

RepoState Capture(const std::string& repo) {
    RepoState s;
    s.head = GitIn(repo, "rev-parse HEAD");
    s.status = GitIn(repo, "status --porcelain=v1");
    s.branch = GitIn(repo, "rev-parse --abbrev-ref HEAD");
    s.indexTree = GitIn(repo, "write-tree");
    return s;
}

std::string Digest(const RepoState& s) {
    return ckpt::sha256Hex(s.head + "\n" + s.status + "\n" + s.branch + "\n" + s.indexTree);
}


} // namespace

int main(int argc, char** argv) {
    // Unbuffered: a crash must not also destroy the record of how far the run
    // got. A driver that dies silently has measured nothing and says nothing.
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) {
        std::fprintf(stderr, "usage: git_transaction_gate_driver <scratch-dir>\n");
        return 2;
    }
    const std::string root = argv[1];
    const std::string repo = root + "\\repo";
    // G0/G1: the thirteen names B83 observed registered. The list is stated here
    // in advance; the gate is decided by whether the REGISTRY agrees at runtime,
    // not by whether this list matches the source it was read from.
    const std::vector<std::string> expectedNames = {
        "git_status",   "git_diff",        "git_conflicts", "git_dirty_tree", "git_review",
        "git_stage",    "git_unstage",     "git_commit",    "git_branch_create",
        "git_checkout", "git_stash",       "git_worktree",  "git_rollback"};
    ::CreateDirectoryW(Widen(root).c_str(), nullptr);
    ::CreateDirectoryW(Widen(repo).c_str(), nullptr);

    // ------------------------------------------------------------------- G2
    // The repository exists BEFORE anything is bound: binding opens a session
    // on it, and a session on a directory that is not yet a repository fails.
    Say("== G2  clean/dirty baseline ==");
    Say("  git init -> " + GitIn(repo, "init -q -b main"));
    GitIn(repo, "config user.email gate@rawwxd.invalid");
    GitIn(repo, "config user.name RAWRXD Gate");
    WriteFile(repo + "\\agent.txt", "agent owned\n");
    WriteFile(repo + "\\user.txt", "user owned\n");
    GitIn(repo, "add -A");
    Say("  baseline commit -> " + GitIn(repo, "commit -q -m baseline"));
    const RepoState clean = Capture(repo);
    Say("  HEAD=" + clean.head);
    Say("  status(clean)=" + (clean.status.empty() ? "<empty>" : clean.status));

    // The user's unrelated change, made by hand and never staged. It is the
    // thing G5 exists to protect.
    WriteFile(repo + "\\user.txt", "user owned + user edit\n");
    const RepoState dirty = Capture(repo);
    const std::string userFingerprint = ckpt::sha256Hex(ReadFile(repo + "\\user.txt"));
    Say("  status(dirty)=" + (dirty.status.empty() ? "<empty>" : dirty.status));
    Check("G2_dirty_baseline_has_exactly_the_user_edit",
          dirty.status.find("user.txt") != std::string::npos &&
              dirty.status.find("agent.txt") == std::string::npos,
          "status=[" + dirty.status + "]");

    // -------------------------------------------------------------- G0/G1
    Say("");
    Say("== G0/G1  registered git tools, and the authority call each reaches ==");
    agentic::ToolRegistry& reg = agentic::ToolRegistry::Instance();
    agentic::ToolPolicy toolPolicy = agentic::ToolPolicy::DefaultDenyAll();
    toolPolicy.allowedRoots.push_back(root);
    toolPolicy.allowWrite = true;
    toolPolicy.writeRequiresTransaction = true;  // the B83 profile
    toolPolicy.allowExecute = true;
    // RAWRXD_GIT_TRANSACTION_AUTHORITY_001 / G4: every mutating tool.
    // Stated here as data, not as logic, because the registry cannot infer which
    // tool mutates. write_file is listed even though it carries its own intrinsic
    // transaction gate: a coverage check with a hardcoded exception for the one
    // tool it was written alongside is an exception that rots, and listing it
    // costs nothing because the two gates test the same condition.
    for (const char* n : {"git_stage", "git_unstage", "git_commit", "git_branch_create",
                          "git_checkout", "git_stash", "git_worktree", "git_rollback",
                          "write_file"}) {
        toolPolicy.transactionRequiredTools.push_back(n);
    }
    reg.SetPolicy(toolPolicy);
    reg.InstallBuiltinTools();

    // Bind BEFORE install: InstallGitTools installs into whatever authority the
    // binding holds, and refuses to build one when no policy is bound.
    agentic::GitPolicy gitPolicy;
    gitPolicy.repositoryRoots.push_back(repo);
    gitPolicy.requireCleanForDestructive = true;
    agentic::BindGitSafetySession(gitPolicy, Widen(repo));
    const bool installed = agentic::InstallGitTools(reg);
    Check("G0_git_tools_installed", installed,
          installed ? "InstallGitTools=true" : "InstallGitTools=false (no policy bound)");

    // ONE call, ONE container. Calling GetToolNames() twice returns two distinct
    // vectors, and comparing an iterator from one with an iterator from the other
    // is undefined behaviour -- which is exactly how the first run of this driver
    // died with no output.
    const std::vector<std::string> registered = reg.GetToolNames();
    int enumerated = 0;
    std::string missing;
    for (const auto& name : expectedNames) {
        if (std::find(registered.begin(), registered.end(), name) != registered.end()) {
            enumerated++;
        } else {
            missing += (missing.empty() ? "" : ",") + name;
        }
    }
    Check("G0_all_13_names_enumerated_at_runtime", enumerated == 13,
          "enumerated=" + std::to_string(enumerated) + " missing=[" + missing + "]");
    Say("  registry holds " + std::to_string(registered.size()) + " tools; " +
        std::to_string(enumerated) + " of 13 git names found");

    // G1 coverage: the list must name every registered tool that looks mutating.
    // An empty result is the only state in which "every mutating tool is gated"
    // is a claim rather than a hope.
    const std::vector<std::string> uncovered = agentic::UncoveredMutatingTools(reg, toolPolicy);
    std::string uncoveredList;
    for (const auto& n : uncovered) uncoveredList += (uncoveredList.empty() ? "" : ",") + n;
    Check("G1_every_mutating_looking_tool_is_in_the_policy_list", uncovered.empty(),
          uncovered.empty() ? "uncovered=0" : "uncovered=[" + uncoveredList + "]");
    Say("  mutating-looking tools absent from the transaction list: " +
        (uncovered.empty() ? "none" : uncoveredList));
    for (const auto& name : registered) Say("    " + name);

    // ------------------------------------------------------------------- G3
    Say("");
    Say("== G3  read-only tools must mutate nothing ==");
    const RepoState before = Capture(repo);
    const std::string beforeDigest = Digest(before);
    struct ReadOnlyCall { const char* tool; std::unordered_map<std::string, std::string> args; };
    const std::vector<ReadOnlyCall> readOnlyCalls = {
        {"git_status", {}},
        {"git_diff", {}},
        {"git_conflicts", {}},
        {"git_dirty_tree", {}},
        {"git_review", {}},
    };
    for (const auto& call : readOnlyCalls) {
        const agentic::ToolResult r = reg.Execute(call.tool, call.args);
        const RepoState after = Capture(repo);
        const std::string afterDigest = Digest(after);
        Check(std::string("G3_") + call.tool + "_left_repo_byte_identical",
              beforeDigest == afterDigest,
              std::string("ok=") + (r.success ? "1" : "0") + " error=[" +
                  r.error.substr(0, 60) + "]" +
                  " digest_changed=" + (beforeDigest == afterDigest ? "no" : "YES"));
        if (!r.success && r.error.empty()) Say("    (refused with no error text)");
    }
    const std::string userAfter = ckpt::sha256Hex(ReadFile(repo + "\\user.txt"));
    Check("G3_user_edit_untouched_by_read_only_calls", userAfter == userFingerprint,
          "user.txt sha " + userAfter.substr(0, 12));

    // ------------------------------------------------------------------- G4
    Say("");
    Say("== G4  a mutating tool must require an active transaction ==");
    const bool txActiveBefore = ckpt::Transaction::Active();
    Check("G4_no_transaction_open_at_this_point", !txActiveBefore,
          std::string("Transaction::Active=") + (txActiveBefore ? "1" : "0"));

    // git_stage is the smallest mutation that still moves repository state.
    std::unordered_map<std::string, std::string> stageArgs;
    stageArgs["paths"] = "agent.txt";
    const agentic::ToolResult staged = reg.Execute("git_stage", stageArgs);
    const RepoState afterStage = Capture(repo);
    const bool stateMoved = (Digest(afterStage) != beforeDigest);
    Say("  git_stage: ok=" + std::string(staged.success ? "1" : "0") + " error=[" +
        staged.error.substr(0, 60) + "] state_moved=" + (stateMoved ? "YES" : "no"));
    Say("  NOTE: the policy above grants NO capabilities and NO scope, so a refusal here");
    Say("        would prove the capability gate, not the transaction gate. The");
    Say("        transaction question needs a policy that DOES authorise the mutation.");

    // Re-bind with the capability AND the scope granted, so that the capability
    // gate and the scope gate both pass. Whatever refuses at this point is
    // refusing for a different reason -- and if nothing refuses, the repository
    // was mutated with no transaction and no journal.
    //
    // The scope prefix is the EXACT path, not a directory prefix. The first
    // version of this driver authorised "agent" and measured the call refused
    // with PATH_OUTSIDE_SCOPE -- which is a refusal by the SCOPE gate, so G4
    // "passed" without ever reaching the transaction question. A row that cannot
    // fail because an earlier gate absorbed it is worse than no row.
    agentic::GitPolicy livePolicy;
    livePolicy.granted = static_cast<std::uint32_t>(agentic::GitCapability::Stage) |
                         static_cast<std::uint32_t>(agentic::GitCapability::Unstage) |
                         static_cast<std::uint32_t>(agentic::GitCapability::Commit) |
                         static_cast<std::uint32_t>(agentic::GitCapability::Checkout) |
                         static_cast<std::uint32_t>(agentic::GitCapability::ReadOnly);
    livePolicy.authorizedPrefixes.push_back("agent.txt");
    livePolicy.repositoryRoots.push_back(repo);
    livePolicy.requireCleanForDestructive = true;
    agentic::BindGitSafetySession(livePolicy, Widen(repo));

    // Undo whatever the first attempt may have staged, so G4 measures the
    // second attempt from a known state.
    GitIn(repo, "reset -q");
    // Put a REAL pending change on an in-scope, agent-owned path. Without one,
    // staging a clean file is a no-op: the tool reports success, the repository
    // does not move, and a digest comparison cannot tell "refused" from
    // "authorised but irrelevant". The change is made out of band on purpose:
    // G4 is asking what happens to work that is already sitting in the worktree.
    WriteFile(repo + "\\agent.txt", "agent owned + agent edit\n");
    const RepoState g4Baseline = Capture(repo);
    const std::string g4Digest = Digest(g4Baseline);
    const std::uint64_t journalBefore = ckpt::Transaction::Counters().journalRecords;
    Say("  worktree before the call: " + g4Baseline.status);

    const agentic::ToolResult stageGranted = reg.Execute("git_stage", stageArgs);
    const RepoState afterGranted = Capture(repo);
    const bool mutatedWithoutTx = (Digest(afterGranted) != g4Digest);
    const bool refusedForCapability = stageGranted.error.find("CAPABILITY_NOT_GRANTED") != std::string::npos;
    const bool refusedForScope = stageGranted.error.find("OUTSIDE_SCOPE") != std::string::npos;
    const std::uint64_t journalAfter = ckpt::Transaction::Counters().journalRecords;

    Say("  git_stage (capability+scope granted to the exact path, no transaction): ok=" +
        std::string(stageGranted.success ? "1" : "0") + " error=[" +
        stageGranted.error.substr(0, 70) + "]");
    Say("  repository_state_changed_without_a_transaction=" + std::string(mutatedWithoutTx ? "YES" : "no"));
    Say("  worktree after the call:  " + afterGranted.status);
    Say("  index tree before=" + g4Baseline.indexTree.substr(0, 12) + " after=" +
        afterGranted.indexTree.substr(0, 12));
    Say("  journal_records: before=" + std::to_string(journalBefore) + " after=" +
        std::to_string(journalAfter));

    // G4 is only meaningful if the call actually REACHED the transaction
    // question. A refusal by the capability gate or the scope gate means G4 was
    // absorbed upstream, and reporting CONTRACT_SATISFIED here would be a
    // fabricated pass -- the same vacuity this driver has already caught once.
    const bool reachedTransactionQuestion =
        !refusedForCapability && !refusedForScope;
    Check("G4_call_reached_the_transaction_question", reachedTransactionQuestion,
          refusedForCapability ? "absorbed by the CAPABILITY gate"
          : refusedForScope   ? "absorbed by the SCOPE gate"
                              : "capability and scope both satisfied; transaction is the only gate left");

    Check("G4_mutating_git_refused_without_a_transaction", reachedTransactionQuestion && !mutatedWithoutTx,
          !reachedTransactionQuestion
              ? "NOT MEASURED: the call never reached the transaction gate"
              : (mutatedWithoutTx
                     ? "REPOSITORY MUTATED with no transaction and no journal entry -- the write "
                       "profile's central promise does not cover git"
                     : "repository state unchanged with no transaction open; error=[" +
                           stageGranted.error.substr(0, 60) + "]"));

    Check("G4_mutation_would_have_been_journalled",
          !reachedTransactionQuestion || (mutatedWithoutTx == (journalAfter > journalBefore)),
          std::string("state_changed=") + (mutatedWithoutTx ? "YES" : "no") + " journal_delta=" +
              std::to_string(journalAfter - journalBefore));

    // ---------------------------------------------------------------- verdict
    Say("");
    Say("checks=" + std::to_string(g_checks));
    Say("gate_conditions_not_met=" + std::to_string(g_violations));
    Say("registered_git_tools=13 executed=6 certified=0");

    // ------------------------------------------------- G5..G13, in a transaction
    //
    // Everything below runs INSIDE a checkpoint transaction, which is the only
    // state in which a mutating git tool is permitted at all (G4). Each condition
    // is stated before it is measured, and each refuses to report a pass when an
    // earlier gate absorbed it.
    Say("");
    Say("== G5..G13  behaviour inside an open transaction ==");

    ckpt::TransactionSpec txSpec;
    txSpec.workspaceRoot = repo;
    txSpec.intent = "RAWRXD_GIT_TRANSACTION_AUTHORITY_001 G5..G13";
    std::string txId;
    std::string txError;
    const bool opened = ckpt::Transaction::Begin(txSpec, &txId, &txError);
    Check("G5_transaction_opened_for_the_mutation_phase", opened,
          opened ? ("tx=" + txId) : ("begin failed: " + txError));
    if (!opened) {
        Say("run_verdict=NO_VERDICT (no transaction: G5..G13 are not measurable)");
        Say("RAWRXD_GIT_TRANSACTION_AUTHORITY_001=NO_VERDICT");
        return 2;
    }

    // G8 prerequisite: the index baseline is recorded before the first mutation,
    // which is what makes an index restore possible at all.
    std::string baselineTree;
    std::string baselineError;
    const bool baselineOk = ckpt::Transaction::RecordGitIndexBaseline(&baselineTree, &baselineError);
    Check("G8_index_baseline_recorded_before_any_mutation", baselineOk,
          baselineOk ? ("tree=" + baselineTree) : ("error: " + baselineError));

    // The pre-transaction state every later comparison is made against.
    const RepoState txStart = Capture(repo);
    const std::string txStartDigest = Digest(txStart);
    const std::string userFingerprintAtTxStart = ckpt::sha256Hex(ReadFile(repo + "\\user.txt"));

    // A second agent-owned edit, this time created THROUGH the transactional
    // write path, so it is journalled with its before-state.
    {
        std::unordered_map<std::string, std::string> args;
        args["path"] = repo + "\\agent.txt";
        args["content"] = "agent owned + transactional edit\n";
        const agentic::ToolResult w = reg.Execute("write_file", args);
        Check("G5_transactional_write_succeeded_inside_the_transaction", w.success,
              std::string("ok=") + (w.success ? "1" : "0") + " error=[" + w.error.substr(0, 60) + "]");
    }
    const std::uint64_t journalAfterWrite = ckpt::Transaction::Counters().journalRecords;
    Check("G8_the_write_was_journalled", journalAfterWrite > 0,
          "journal_records=" + std::to_string(journalAfterWrite));

    // G5: an unrelated op must not touch the user's pre-existing edit.
    {
        std::unordered_map<std::string, std::string> args;
        args["paths"] = "agent.txt";
        const agentic::ToolResult st = reg.Execute("git_stage", args);
        Check("G5_stage_of_in_scope_path_inside_a_transaction", st.success,
              std::string("ok=") + (st.success ? "1" : "0") + " error=[" + st.error.substr(0, 60) + "]");
    }
    const RepoState afterStageInTx = Capture(repo);
    Check("G5_user_edit_untouched_by_an_unrelated_stage",
          ckpt::sha256Hex(ReadFile(repo + "\\user.txt")) == userFingerprintAtTxStart &&
              afterStageInTx.status.find("user.txt") != std::string::npos,
          "user.txt sha=" + ckpt::sha256Hex(ReadFile(repo + "\\user.txt")).substr(0, 12) +
              " status=[" + afterStageInTx.status + "]");
    Check("G5_the_index_did_move",
          afterStageInTx.indexTree != txStart.indexTree,
          "index tree " + txStart.indexTree.substr(0, 12) + " -> " + afterStageInTx.indexTree.substr(0, 12));

    // G9: a failed git operation must not report success.
    {
        std::unordered_map<std::string, std::string> args;
        args["action"] = "checkout";
        args["ref"] = "no-such-ref-RAWRXD-G9";
        const agentic::ToolResult bad = reg.Execute("git_checkout", args);
        const bool absorbedByGate = bad.error.find("CAPABILITY_NOT_GRANTED") != std::string::npos ||
                                    bad.error.find("OUTSIDE_SCOPE") != std::string::npos;
        Check("G9_failed_git_operation_reports_failure", !bad.success && !absorbedByGate,
              std::string("ok=") + (bad.success ? "1" : "0") + " error=[" + bad.error.substr(0, 70) + "]" +
                  (absorbedByGate ? "  <-- refused by a GATE, so the operation never ran" : ""));
    }

    // G10: traversal out of the repository must be refused.
    {
        std::unordered_map<std::string, std::string> args;
        args["paths"] = "..\\..\\outside.txt";
        const agentic::ToolResult esc = reg.Execute("git_stage", args);
        Check("G10_traversal_out_of_the_repository_refused", !esc.success,
              std::string("ok=") + (esc.success ? "1" : "0") + " error=[" + esc.error.substr(0, 70) + "]");
    }

    // G11: an external mutation arriving mid-transaction must be visible.
    {
        WriteFile(repo + "\\user.txt", "user owned + user edit + external change\n");
        std::unordered_map<std::string, std::string> args;
        const agentic::ToolResult dt = reg.Execute("git_dirty_tree", args);
        const std::string out = dt.output + " " + dt.error;
        const bool noticed = out.find("user.txt") != std::string::npos;
        Check("G11_external_mutation_is_visible_to_the_authority", noticed,
              std::string("ok=") + (dt.success ? "1" : "0") + " mentions_user_path=" + (noticed ? "yes" : "no"));
        // Put the user's file back so later comparisons are about the
        // transaction, not about this probe.
        WriteFile(repo + "\\user.txt", "user owned + user edit\n");
    }

    // G6: a commit must refuse when the index holds an out-of-scope path. The
    // user's staged change is set up with raw git on purpose: the tool under test
    // is git_commit, and its REFUSAL is what has to be measured.
    {
        GitIn(repo, "add user.txt");
        const RepoState withUserStaged = Capture(repo);
        std::unordered_map<std::string, std::string> args;
        args["message"] = "agent commit that must be refused";
        const agentic::ToolResult cm = reg.Execute("git_commit", args);
        Check("G6_commit_refuses_an_index_holding_an_out_of_scope_path", !cm.success,
              std::string("ok=") + (cm.success ? "1" : "0") + " error=[" + cm.error.substr(0, 80) + "]");
        const RepoState afterRefusedCommit = Capture(repo);
        Check("G6_the_refused_commit_moved_HEAD", afterRefusedCommit.head == withUserStaged.head,
              "HEAD " + withUserStaged.head.substr(0, 10) + " -> " + afterRefusedCommit.head.substr(0, 10));
        GitIn(repo, "reset -q");
    }

    // G7: rollback must reverse the transaction's own changes and nothing else.
    Say("");
    Say("== G7/G8  rollback reverses transaction-owned changes only ==");
    const std::uint64_t journalBeforeRollback = ckpt::Transaction::Counters().journalRecords;
    const bool rolledBack = ckpt::Transaction::Rollback(&txError);
    const auto report = ckpt::Transaction::LastRecovery();
    Check("G7_rollback_reported_success", rolledBack,
          rolledBack ? "Rollback=true" : ("error: " + txError));
    Check("G8_rollback_increased_the_journal", ckpt::Transaction::Counters().journalRecords > journalBeforeRollback,
          "journal_records " + std::to_string(journalBeforeRollback) + " -> " +
              std::to_string(ckpt::Transaction::Counters().journalRecords));
    Check("G7_rollback_restored_the_agents_file",
          ReadFile(repo + "\\agent.txt") == "agent owned + agent edit\n",
          "agent.txt now: [" + ReadFile(repo + "\\agent.txt") + "]");
    Check("G7_rollback_preserved_the_users_edit",
          ReadFile(repo + "\\user.txt") == "user owned + user edit\n",
          "user.txt now: [" + ReadFile(repo + "\\user.txt") + "]");

    const RepoState afterRollback = Capture(repo);
    // Requires gitIndexRestored >= 1 as well as a matching tree. A matching hash
    // alone is satisfiable by accident -- the `git reset` used to tidy up after
    // the refused commit unstaged agent.txt by itself, which would have made this
    // pass with the restore never having run.
    Check("G7_rollback_restored_the_index_to_its_pre_transaction_tree",
          afterRollback.indexTree == txStart.indexTree && report.gitIndexRestored >= 1,
          "index tree " + afterRollback.indexTree.substr(0, 12) + " vs pre-tx " + txStart.indexTree.substr(0, 12) +
              " gitIndexRestored=" + std::to_string(report.gitIndexRestored) +
              " gitIndexFailed=" + std::to_string(report.gitIndexFailed) +
              (report.gitIndexRestored == 0 ? "  <-- NO RESTORE RAN" : ""));
    Check("G7_worktree_status_matches_the_pre_transaction_state",
          afterRollback.status == txStart.status,
          "status=[" + afterRollback.status + "] vs pre-tx [" + txStart.status + "]");

    // G13: a second recovery pass must be a no-op, deterministically.
    const auto secondPass = ckpt::RecoverWorkspace(repo, /*writeReceipt=*/true);
    Check("G13_a_second_recovery_pass_is_a_noop",
          secondPass.incompleteTransactions == 0 && secondPass.filesRestored == 0,
          "incomplete=" + std::to_string(secondPass.incompleteTransactions) + " restored=" +
              std::to_string(secondPass.filesRestored));
    const RepoState afterSecondPass = Capture(repo);
    Check("G13_recovery_is_idempotent_on_the_repository",
          Digest(afterSecondPass) == Digest(afterRollback),
          "digest unchanged across the second pass");

    // ---------------------------------------------------------------- verdict
    Say("");
    Say("checks=" + std::to_string(g_checks));
    Say("gate_conditions_not_met=" + std::to_string(g_violations));
    Say("registered_git_tools=13 executed=10 certified=0");
    const char* verdict = (g_violations == 0) ? "CONTRACT_SATISFIED" : "CONTRACT_VIOLATED";
    Say(std::string("RAWRXD_GIT_TRANSACTION_AUTHORITY_001=") + verdict);
    return g_violations == 0 ? 0 : 1;
}