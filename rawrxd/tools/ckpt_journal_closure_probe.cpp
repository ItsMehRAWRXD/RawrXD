// ckpt_journal_closure_probe.cpp
//   RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001 -- falsification probe
//
// The question this answers is narrow and it is the one the rollback fix claims
// to answer: after an in-process rollback, can a later recovery pass revert work
// that was committed AFTER that rollback?
//
// Sequence, all through the production tool authority (write_file) and the
// production checkpoint authority:
//
//   1. seed alpha.txt with ORIGINAL bytes
//   2. begin tx1, write alpha.txt = AGENT_EDIT, roll back
//      -> alpha.txt must be ORIGINAL again
//   3. begin tx2, write alpha.txt = COMMITTED_EDIT, commit
//      -> alpha.txt must be COMMITTED_EDIT
//   4. run a recovery pass, exactly as an IDE startup would
//      -> alpha.txt must STILL be COMMITTED_EDIT
//
// Step 4 is the falsifiable one. The pre-fix Transaction::Rollback left the
// journal handle open while the recovery pass tried to re-open the same journal
// to append its ROLLBACK record. Begin() opens with FILE_SHARE_READ, so that
// reopen failed with ERROR_SHARING_VIOLATION, the record was never written, and
// tx1 stayed permanently "incomplete". Every later pass -- including step 4 --
// then restored tx1's before-state, silently discarding the edit committed in
// step 3.
//
// The probe is compiled twice by tools/cert_journal_closure_probe.ps1: once
// against the in-tree authority, and once against a copy whose Rollback() has
// the pre-fix ordering restored. PASS requires the first to report 1 and the
// second to report 0. A probe that cannot fail is not a probe.
//
// It links no engine. The whole point is that this property is a property of the
// journal and nothing else, so it is decided here and not in a 200 MB image.
//
// Usage
//   ckpt_journal_closure_probe <workspace-dir> [build-role]
//   build-role is "candidate" for the in-tree authority and "control" for the
//   deliberately defective build. The committed edit must survive for a
//   candidate and must NOT survive for a control; both are reported with the
//   same two-word vocabulary so neither can be read as the other.
//   exit 0 when the build met its expectation.

#include <windows.h>

#include <cstdio>
#include <string>
#include <unordered_map>

#include "agentic/AgentToolRegistry.h"
#include "agentic/CheckpointRollbackAuthority.h"

namespace {

std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], n,
                          nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                        nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], n);
    return out;
}

bool WriteSeed(const std::wstring& path, const std::string& bytes) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = bytes.empty()
                        ? TRUE
                        : ::WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()),
                                      &written, nullptr);
    ::CloseHandle(h);
    return ok != FALSE;
}

std::string ReadAll(const std::wstring& path) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    std::string out;
    char buffer[4096];
    DWORD got = 0;
    while (::ReadFile(h, buffer, sizeof(buffer), &got, nullptr) && got > 0) {
        out.append(buffer, got);
    }
    ::CloseHandle(h);
    return out;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: ckpt_journal_closure_probe <workspace-dir> [build-role]\n");
        return 2;
    }
    const std::string workspace = argv[1];
    const std::string role = (argc >= 3) ? std::string(argv[2]) : std::string("candidate");
    ::CreateDirectoryA(workspace.c_str(), nullptr);

    const std::wstring alphaW = widen(workspace + "\\alpha.txt");
    const std::string ORIGINAL = "ORIGINAL\n";
    const std::string AGENT_EDIT = "AGENT EDIT (rolled back)\n";
    const std::string COMMITTED_EDIT = "SECOND EDIT (committed)\n";
    if (!WriteSeed(alphaW, ORIGINAL)) {
        std::fprintf(stderr, "PROBE_SEED_FAILED\n");
        return 3;
    }
    const std::string originalSha = rawrxd::ckpt::sha256Hex(ORIGINAL);
    const std::string committedSha = rawrxd::ckpt::sha256Hex(COMMITTED_EDIT);

    using namespace rawrxd;
    agentic::ToolPolicy policy;
    policy.allowedRoots.push_back(workspace);
    policy.allowWrite = true;
    policy.writeRequiresTransaction = true;
    policy.allowExecute = false;
    agentic::ToolRegistry& registry = agentic::ToolRegistry::Instance();
    registry.SetPolicy(policy);
    registry.InstallBuiltinTools();

    const auto write = [&](const char* content) {
        std::unordered_map<std::string, std::string> params;
        params["path"] = "alpha.txt";
        params["content"] = content;
        return registry.Execute("write_file", params);
    };

    // ---- step 2: a transaction that is rolled back -------------------------
    ckpt::TransactionSpec spec;
    spec.workspaceRoot = workspace;
    spec.intent = "falsification probe: rolled-back edit";
    std::string tx1;
    std::string error;
    if (!ckpt::Transaction::Begin(spec, &tx1, &error)) {
        std::fprintf(stderr, "PROBE_BEGIN1_FAILED=%s\n", error.c_str());
        return 4;
    }
    const auto w1 = write(AGENT_EDIT.c_str());
    if (!w1.success) {
        std::fprintf(stderr, "PROBE_WRITE1_REFUSED=%s\n", w1.error.c_str());
        return 5;
    }
    if (!ckpt::Transaction::Rollback(&error)) {
        std::fprintf(stderr, "PROBE_ROLLBACK1_FAILED=%s\n", error.c_str());
        return 6;
    }
    const std::string afterRollback = rawrxd::ckpt::sha256FileHex(narrow(alphaW));
    std::printf("AFTER_ROLLBACK_SHA=%s\n", afterRollback.c_str());
    std::printf("AFTER_ROLLBACK_RESTORED=%d\n", afterRollback == originalSha ? 1 : 0);

    // ---- step 3: a later transaction that is committed ---------------------
    spec.intent = "falsification probe: committed edit";
    std::string tx2;
    if (!ckpt::Transaction::Begin(spec, &tx2, &error)) {
        std::fprintf(stderr, "PROBE_BEGIN2_FAILED=%s\n", error.c_str());
        return 7;
    }
    const auto w2 = write(COMMITTED_EDIT.c_str());
    if (!w2.success) {
        std::fprintf(stderr, "PROBE_WRITE2_REFUSED=%s\n", w2.error.c_str());
        return 8;
    }
    if (!ckpt::Transaction::Commit(&error)) {
        std::fprintf(stderr, "PROBE_COMMIT_FAILED=%s\n", error.c_str());
        return 9;
    }
    const std::string afterCommit = rawrxd::ckpt::sha256FileHex(narrow(alphaW));
    std::printf("AFTER_COMMIT_SHA=%s\n", afterCommit.c_str());

    // ---- step 4: a later recovery pass, as an IDE startup would run -------
    const auto report = ckpt::RecoverWorkspace(workspace, /*writeReceipt=*/true);
    std::printf("RECOVERY_JOURNALS_SCANNED=%u\n", report.journalsScanned);
    std::printf("RECOVERY_CLOSED_TRANSACTIONS=%u\n", report.closedTransactions);
    std::printf("RECOVERY_INCOMPLETE_TRANSACTIONS=%u\n", report.incompleteTransactions);
    std::printf("RECOVERY_FILES_RESTORED=%u\n", report.filesRestored);
    std::printf("RECOVERY_FILES_FAILED=%u\n", report.filesFailed);

    const std::string afterRecovery = rawrxd::ckpt::sha256FileHex(narrow(alphaW));
    std::printf("AFTER_RECOVERY_SHA=%s\n", afterRecovery.c_str());

    // THE MEASUREMENT. 1 means a committed edit survived a later recovery pass.
    const int survived = (afterRecovery == committedSha) ? 1 : 0;
    std::printf("COMMITTED_EDIT_SURVIVED_LATER_RECOVERY=%d\n", survived);
    std::printf("REVERTED_TO_ROLLED_BACK_STATE=%d\n", afterRecovery == originalSha ? 1 : 0);
    std::printf("STALE_JOURNAL_REPLAYED=%d\n", report.incompleteTransactions > 0 ? 1 : 0);
    // Verdict vocabulary, deliberately not PASS/FAIL. This driver is compiled
    // twice: once for the authority under test (candidate) and once with the
    // pre-fix Rollback() ordering restored (control), where losing the committed
    // edit is the REQUIRED outcome. Bare PASS tokens in a log that a later
    // aggregate parser reads would turn two of the three results into
    // successes, or turn a required control failure into an alarming one.
    //   CONTRACT_SATISFIED = the build met its expectation
    //   CONTRACT_VIOLATED  = the build did not
    std::printf("build_role=%s\n", role.c_str());
    std::printf("RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_JOURNAL_CLOSURE_VERDICT=%s\n",
                survived ? "CONTRACT_SATISFIED" : "CONTRACT_VIOLATED");
    return survived ? 0 : 1;
}
