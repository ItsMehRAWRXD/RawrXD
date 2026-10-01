// ============================================================================
// ckpt_rollback_crash_cert.cpp
//   RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001 — crash/recovery proof
//
// What this proves, and what it does not:
//
//   PROVED: an autonomous multi-file edit is killed by an uncatchable process
//   termination at a named point, and a SEPARATE process — the IDE startup
//   recovery pass — restores every touched file byte-for-byte, removes the
//   files the transaction created, and verifies each restore against the
//   before-state hash that was recorded and flushed BEFORE the crash.
//
//   NOT PROVED: power-loss semantics. TerminateProcess does not flush kernel
//   caches, but it is not identical to a power cut either, and the receipt says
//   so rather than claiming more than was measured.
//
// The edit is driven through the PRODUCTION write authority, not a test-only
// path: rawrxd::agentic::ToolRegistry::Execute("write_file", ...), the same
// call the IDE HTTP routes make.
//
// Crash shape (indices are 1-based over the writes below):
//   1. delta_new.txt  CREATED   -> recovery must delete it
//   2. alpha.cpp      MODIFIED  -> crash torn mid-write, file left half-written
//   3. beta.h         MODIFIED  -> never reached
//   4. gamma.txt      MODIFIED  -> never reached
//   The fault fires at index 2, so the on-disk state after the crash is one
//   corrupt file plus one spurious new file.
//
// Modes:
//   ckpt_rollback_crash_cert                      drive the whole proof
//   ckpt_rollback_crash_cert --crash-child <ws>
//   ckpt_rollback_crash_cert --recover-child <ws>
// ============================================================================
#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <unordered_map>
#include <string>
#include <vector>

#include "agentic/CheckpointRollbackAuthority.h"
#include "agentic/AgentToolRegistry.h"

using rawrxd::ckpt::MeasuredCounters;
using rawrxd::ckpt::RecoveryReport;
using rawrxd::ckpt::Transaction;
namespace agentic = rawrxd::agentic;

namespace {

constexpr DWORD kFaultExitCode = 0xC0FFEE01u;

struct FileSpec {
    const char* name;
    const char* content;
    bool createdByTransaction;
};

const FileSpec kFiles[] = {
    {"alpha.cpp", "// alpha baseline\nint alpha() { return 1; }\n", false},
    {"beta.h", "// beta baseline\n#pragma once\nint beta();\n", false},
    {"gamma.txt", "gamma baseline\n", false},
    {"delta_new.txt", "", true},  // absent until the transaction writes it
};
constexpr int kFileCount = 4;
constexpr int kCrashAtWriteIndex = 2;  // die torn, mid-publish of alpha.cpp

std::string g_workspace;

std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                             nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], needed,
                          nullptr, nullptr);
    return out;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                             nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], needed);
    return out;
}

std::wstring joinW(const std::wstring& dir, const std::string& leaf) {
    std::wstring out = dir;
    if (!out.empty() && out.back() != L'\\') out.push_back(L'\\');
    return out + widen(leaf);
}

bool fileExists(const std::wstring& path) {
    return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool writePlainFile(const std::wstring& path, const std::string& content) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = content.empty() ? TRUE
                                   : ::WriteFile(h, content.data(),
                                                 static_cast<DWORD>(content.size()), &written,
                                                 nullptr);
    ::FlushFileBuffers(h);
    ::CloseHandle(h);
    return ok && written == content.size();
}

struct Snapshot {
    std::map<std::string, std::string> sha;  // empty string => file absent
};

Snapshot TakeSnapshot(const std::wstring& rootW) {
    Snapshot snap;
    for (int i = 0; i < kFileCount; ++i) {
        const std::wstring path = joinW(rootW, kFiles[i].name);
        snap.sha[kFiles[i].name] = fileExists(path) ? rawrxd::ckpt::sha256FileHex(narrow(path))
                                                    : std::string();
    }
    return snap;
}

std::vector<std::string> Diff(const Snapshot& a, const Snapshot& b) {
    std::vector<std::string> diff;
    for (int i = 0; i < kFileCount; ++i) {
        const std::string name = kFiles[i].name;
        const auto ia = a.sha.find(name);
        const auto ib = b.sha.find(name);
        const std::string va = ia == a.sha.end() ? std::string() : ia->second;
        const std::string vb = ib == b.sha.end() ? std::string() : ib->second;
        if (va != vb) diff.push_back(name);
    }
    return diff;
}

void PrintCounters(const char* tag) {
    const MeasuredCounters c = Transaction::Counters();
    std::printf("%s_COUNTERS journalRecords=%llu journalFlushes=%llu atomicPublishes=%llu "
                "fileWrites=%llu fileDeletes=%llu blobWrites=%llu faults=%llu\n",
                tag, static_cast<unsigned long long>(c.journalRecords),
                static_cast<unsigned long long>(c.journalFlushes),
                static_cast<unsigned long long>(c.atomicPublishes),
                static_cast<unsigned long long>(c.fileWrites),
                static_cast<unsigned long long>(c.fileDeletes),
                static_cast<unsigned long long>(c.blobWrites),
                static_cast<unsigned long long>(c.faultsInjected));
    std::fflush(stdout);
}

// ---------------------------------------------------------------------------
// Child: run a multi-file agent edit through the production tool authority and
// die at the armed fault point.
// ---------------------------------------------------------------------------
int RunCrashChild(const std::string& workspace) {
    g_workspace = workspace;

    agentic::ToolPolicy policy;
    policy.allowedRoots.push_back(workspace);
    policy.allowWrite = true;
    policy.allowExecute = false;  // the cert issues no shell commands
    agentic::ToolRegistry& registry = agentic::ToolRegistry::Instance();
    registry.SetPolicy(policy);
    registry.InstallBuiltinTools();

    rawrxd::ckpt::TransactionSpec spec;
    spec.workspaceRoot = workspace;
    spec.intent = "agent multi-file edit (crash proof)";
    spec.plan =
        "1. create delta_new.txt for the new module\n"
        "2. rewrite alpha.cpp with the new implementation\n"
        "3. rewrite beta.h with the new declaration\n"
        "4. rewrite gamma.txt (superseded)\n";
    spec.modelContext =
        "{\"model\":\"deep2\",\"turn\":42,\"history_sha\":"
        "\"1111111111111111111111111111111111111111111111111111111111111111\"}";
    spec.diagnostics = "{\"errors\":0,\"warnings\":3,\"captured_at\":\"pre-edit\"}";

    std::string txId;
    std::string error;
    if (!Transaction::Begin(spec, &txId, &error)) {
        std::fprintf(stderr, "CRASH_CHILD_BEGIN_FAILED=%s\n", error.c_str());
        return 90;
    }
    std::printf("CRASH_CHILD_TXID=%s\n", txId.c_str());
    std::printf("CRASH_CHILD_TOOL_REGISTRY_SIZE=%zu\n", registry.Size());
    std::fflush(stdout);

    // A command the agent ran, journalled before the crash.
    Transaction::RecordCommand("git status --porcelain", 0, " M alpha.cpp\n", "", 4200);

    struct Write {
        const char* rel;
        const char* content;
    };
    const Write writes[] = {
        {"delta_new.txt", "delta created by agent\n"},
        {"alpha.cpp", "// alpha EDITED by agent\nint alpha() { return 2; }\n"},
        {"beta.h", "// beta EDITED by agent\n#pragma once\nint beta(int);\n"},
        {"gamma.txt", "gamma EDITED by agent\n"},
    };

    for (std::size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); ++i) {
        std::unordered_map<std::string, std::string> params;
        params["path"] = writes[i].rel;
        params["content"] = writes[i].content;
        const agentic::ToolResult r = registry.Execute("write_file", params);
        std::printf("CRASH_CHILD_WRITE index=%zu path=%s ok=%d\n", i + 1, writes[i].rel,
                    r.success ? 1 : 0);
        std::fflush(stdout);
        if (!r.success) {
            std::fprintf(stderr, "CRASH_CHILD_WRITE_REFUSED path=%s err=%s\n", writes[i].rel,
                         r.error.c_str());
            return 91;
        }
        PrintCounters("CRASH_CHILD");
    }

    // Reaching here means no fault was armed or the index was out of range.
    std::printf("CRASH_CHILD_COMPLETED_WITHOUT_FAULT=1\n");
    std::fflush(stdout);
    Transaction::Commit(&error);
    return 92;
}

// ---------------------------------------------------------------------------
// Child: the IDE startup recovery pass, in its own process.
// ---------------------------------------------------------------------------
int RunRecoverChild(const std::string& workspace) {
    const RecoveryReport r = rawrxd::ckpt::RecoverWorkspace(workspace, /*writeReceipt=*/true);
    std::printf("RECOVER_JOURNALS_SCANNED=%u\n", r.journalsScanned);
    std::printf("RECOVER_CLOSED_TRANSACTIONS=%u\n", r.closedTransactions);
    std::printf("RECOVER_INCOMPLETE_TRANSACTIONS=%u\n", r.incompleteTransactions);
    std::printf("RECOVER_FILES_RESTORED=%u\n", r.filesRestored);
    std::printf("RECOVER_FILES_DELETED=%u\n", r.filesDeleted);
    std::printf("RECOVER_FILES_VERIFIED=%u\n", r.filesVerified);
    std::printf("RECOVER_FILES_FAILED=%u\n", r.filesFailed);
    std::printf("RECOVER_TORN_RECORDS=%u\n", r.tornRecordsDiscarded);
    std::printf("RECOVER_MISSING_BLOBS=%u\n", r.missingBlobs);
    std::printf("RECOVER_IDENTITY_BEFORE=%s\n", r.identityBeforeSha256.c_str());
    std::printf("RECOVER_IDENTITY_AFTER=%s\n", r.identityAfterSha256.c_str());
    for (const std::string& tx : r.recoveredTxIds) {
        std::printf("RECOVER_TX=%s\n", tx.c_str());
    }
    for (const std::string& p : r.failedPaths) {
        std::printf("RECOVER_FAILED_PATH=%s\n", p.c_str());
    }
    PrintCounters("RECOVER_CHILD");
    std::printf("RECOVER_VERDICT=%s\n", r.AllRestored() ? "RESTORED" : "INCOMPLETE");
    std::fflush(stdout);
    return r.AllRestored() ? 0 : 93;
}

// ---------------------------------------------------------------------------
// Driver helpers
// ---------------------------------------------------------------------------
DWORD RunChild(const std::string& exePath, const std::string& mode, const std::string& workspace,
               const char* faultEnv, std::string& outText) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    SECURITY_ATTRIBUTES noInherit{};
    noInherit.nLength = sizeof(noInherit);

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!::CreatePipe(&readPipe, &writePipe, &sa, 0)) return 0xFFFFFFFFu;
    ::SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    HANDLE nulIn =
        ::CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ, &noInherit, OPEN_EXISTING, 0, nullptr);

    std::wstring cmdLine = L"\"";
    cmdLine += widen(exePath);
    cmdLine += L"\" ";
    cmdLine += widen(mode);
    cmdLine += L" \"";
    cmdLine += widen(workspace);
    cmdLine += L"\"";
    std::vector<char> mutableCmd(cmdLine.begin(), cmdLine.end());
    mutableCmd.push_back('\0');

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = nulIn;

    std::vector<char> envBlock;
    {
        std::map<std::string, std::string> vars;
        char* block = ::GetEnvironmentStringsA();
        if (block) {
            for (char* p = block; *p;) {
                const std::string entry(p);
                p += entry.size() + 1;
                const std::size_t eq = entry.find('=');
                if (eq == std::string::npos) continue;
                vars[entry.substr(0, eq)] = entry.substr(eq + 1);
            }
            ::FreeEnvironmentStringsA(block);
        }
        vars["RAWRXD_CKPT_FAULT"] = faultEnv ? faultEnv : "";
        for (const auto& kv : vars) {
            const std::string entry = kv.first + "=" + kv.second;
            envBlock.insert(envBlock.end(), entry.begin(), entry.end());
            envBlock.push_back('\0');
        }
        envBlock.push_back('\0');
    }

    PROCESS_INFORMATION pi{};
    const BOOL ok = ::CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
                                     CREATE_NO_WINDOW, envBlock.data(), nullptr, &si, &pi);
    ::CloseHandle(writePipe);
    if (nulIn != INVALID_HANDLE_VALUE) ::CloseHandle(nulIn);
    if (!ok) {
        ::CloseHandle(readPipe);
        return 0xFFFFFFFFu;
    }

    char buffer[4096];
    DWORD read = 0;
    while (::ReadFile(readPipe, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        outText.append(buffer, read);
    }
    ::CloseHandle(readPipe);
    ::WaitForSingleObject(pi.hProcess, 60000);
    DWORD exitCode = 0xFFFFFFFFu;
    ::GetExitCodeProcess(pi.hProcess, &exitCode);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return exitCode;
}

bool RemoveTree(const std::wstring& path) {
    const std::wstring pattern = path + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            const std::wstring name(fd.cFileName);
            if (name == L"." || name == L"..") continue;
            const std::wstring child = path + L"\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                RemoveTree(child);
            } else {
                ::DeleteFileW(child.c_str());
            }
        } while (::FindNextFileW(h, &fd));
        ::FindClose(h);
    }
    return ::RemoveDirectoryW(path.c_str()) != 0;
}

std::wstring MakeTempWorkspace() {
    wchar_t tempRoot[MAX_PATH] = {};
    const DWORD got = ::GetTempPathW(MAX_PATH, tempRoot);
    std::wstring base = (got > 0) ? std::wstring(tempRoot, got) : std::wstring(L"F:\\~dev\\");
    char name[64];
    std::snprintf(name, sizeof(name), "rawrxd_ckpt_cert_%lu_%llu",
                  static_cast<unsigned long>(::GetCurrentProcessId()),
                  static_cast<unsigned long long>(::GetTickCount64()));
    return base + widen(name);
}

std::size_t CountOccurrences(const std::string& haystack, const std::string& needle) {
    std::size_t count = 0;
    std::size_t pos = haystack.find(needle);
    while (pos != std::string::npos) {
        ++count;
        pos = haystack.find(needle, pos + needle.size());
    }
    return count;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string mode = (argc > 1) ? argv[1] : "--drive";

    if (mode == "--crash-child") {
        if (argc < 3) {
            std::fprintf(stderr, "usage: --crash-child <workspace>\n");
            return 2;
        }
        return RunCrashChild(argv[2]);
    }
    if (mode == "--recover-child") {
        if (argc < 3) {
            std::fprintf(stderr, "usage: --recover-child <workspace>\n");
            return 2;
        }
        return RunRecoverChild(argv[2]);
    }

    char exePath[32768] = {};
    ::GetModuleFileNameA(nullptr, exePath, sizeof(exePath));
    const std::wstring workspaceW = MakeTempWorkspace();
    const std::string workspace = narrow(workspaceW);
    g_workspace = workspace;

    if (!::CreateDirectoryW(workspaceW.c_str(), nullptr)) {
        std::fprintf(stderr, "cannot create workspace\n");
        return 3;
    }

    std::map<std::string, std::string> baselineContent;
    for (int i = 0; i < kFileCount; ++i) {
        if (kFiles[i].createdByTransaction) continue;
        if (!writePlainFile(joinW(workspaceW, kFiles[i].name), kFiles[i].content)) {
            std::fprintf(stderr, "cannot seed %s\n", kFiles[i].name);
            return 4;
        }
        baselineContent[kFiles[i].name] = kFiles[i].content;
    }

    const Snapshot baseline = TakeSnapshot(workspaceW);
    const std::string identityBaseline = Transaction::CaptureIdentity(workspace).identitySha256;

    std::printf("=== BASELINE ===\n");
    std::printf("WORKSPACE=%s\n", workspace.c_str());
    std::printf("BASELINE_IDENTITY=%s\n", identityBaseline.c_str());
    std::printf("BASELINE_FILES=%d\n", kFileCount);
    for (const auto& kv : baseline.sha) {
        std::printf("BASELINE_SHA[%s]=%s\n", kv.first.c_str(), kv.second.c_str());
    }

    // ---- phase 1: the edit, killed at the armed fault point ----
    char fault[64];
    std::snprintf(fault, sizeof(fault), "crash_torn:%d", kCrashAtWriteIndex);
    std::string crashOut;
    const DWORD crashExit = RunChild(exePath, "--crash-child", workspace, fault, crashOut);
    std::printf("\n=== CRASH CHILD ===\n%s", crashOut.c_str());
    std::printf("CRASH_CHILD_EXIT=0x%08lX\n", static_cast<unsigned long>(crashExit));
    const bool diedByInjection = (crashExit == kFaultExitCode);

    const Snapshot afterCrash = TakeSnapshot(workspaceW);
    const std::vector<std::string> crashDiff = Diff(baseline, afterCrash);
    const std::string identityAfterCrash = Transaction::CaptureIdentity(workspace).identitySha256;
    std::printf("FILES_TOUCHED_BY_CRASH=%zu\n", crashDiff.size());
    for (const std::string& name : crashDiff) std::printf("CRASH_TOUCHED=%s\n", name.c_str());

    // ---- phase 2: a separate process runs the startup recovery pass ----
    std::string recoverOut;
    const DWORD recoverExit = RunChild(exePath, "--recover-child", workspace, "", recoverOut);
    std::printf("\n=== RECOVER CHILD ===\n%s", recoverOut.c_str());
    std::printf("RECOVER_CHILD_EXIT=%lu\n", static_cast<unsigned long>(recoverExit));

    // ---- phase 3: verify independently of the recovery pass's own report ----
    const Snapshot afterRecovery = TakeSnapshot(workspaceW);
    const std::vector<std::string> recoveryDiff = Diff(baseline, afterRecovery);
    const std::string identityAfterRecovery =
        Transaction::CaptureIdentity(workspace).identitySha256;

    int byteMismatches = 0;
    for (const auto& kv : baselineContent) {
        const auto it = afterRecovery.sha.find(kv.first);
        const std::string now = it == afterRecovery.sha.end() ? std::string() : it->second;
        if (now != baseline.sha.at(kv.first)) ++byteMismatches;
    }
    const bool createdFileRemoved = afterRecovery.sha.at("delta_new.txt").empty();

    // Second pass must be a no-op: a closed transaction is never replayed.
    std::string secondOut;
    const DWORD secondExit = RunChild(exePath, "--recover-child", workspace, "", secondOut);
    const bool secondPassNoop =
        secondOut.find("RECOVER_INCOMPLETE_TRANSACTIONS=0") != std::string::npos &&
        secondOut.find("RECOVER_VERDICT=RESTORED") != std::string::npos;
    const Snapshot afterSecond = TakeSnapshot(workspaceW);
    const bool idempotent = Diff(baseline, afterSecond).empty();

    const bool pass = diedByInjection &&
                      crashDiff.size() == 2 &&
                      identityAfterCrash != identityBaseline &&
                      recoverExit == 0 &&
                      recoveryDiff.empty() &&
                      byteMismatches == 0 &&
                      createdFileRemoved &&
                      identityAfterRecovery == identityBaseline &&
                      secondExit == 0 && secondPassNoop && idempotent &&
                      CountOccurrences(recoverOut, "RECOVER_FILES_FAILED=0") == 1;

    std::printf("\n=== MEASURED ===\n");
    std::printf("CRASH_EXIT_CODE_ARMED=0x%08X\n", kFaultExitCode);
    std::printf("CRASH_EXIT_CODE_OBSERVED=0x%08lX\n", static_cast<unsigned long>(crashExit));
    std::printf("CRASH_KILLED_BY_FAULT_INJECTION=%d\n", diedByInjection ? 1 : 0);
    std::printf("CRASH_LEFT_DAMAGED_FILES=%zu\n", crashDiff.size());
    std::printf("IDENTITY_CHANGED_BY_CRASH=%d\n",
                identityAfterCrash != identityBaseline ? 1 : 0);
    std::printf("RECOVERY_CHILD_RESTORED_ALL=%d\n", recoverExit == 0 ? 1 : 0);
    std::printf("FILES_DIFFERING_AFTER_RECOVERY=%zu\n", recoveryDiff.size());
    std::printf("BYTE_MISMATCHES_AFTER_RECOVERY=%d\n", byteMismatches);
    std::printf("TRANSACTION_CREATED_FILE_REMOVED=%d\n", createdFileRemoved ? 1 : 0);
    std::printf("IDENTITY_RESTORED_TO_BASELINE=%d\n",
                identityAfterRecovery == identityBaseline ? 1 : 0);
    std::printf("SECOND_RECOVERY_IS_NOOP=%d\n", secondPassNoop ? 1 : 0);
    std::printf("RECOVERY_IDEMPOTENT=%d\n", idempotent ? 1 : 0);
    std::printf("POWER_LOSS_SEMANTICS_PROVEN=0\n");
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");

    RemoveTree(workspaceW);
    return pass ? 0 : 1;
}