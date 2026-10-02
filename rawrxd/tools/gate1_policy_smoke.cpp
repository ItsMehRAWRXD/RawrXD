// ============================================================================
// gate1_policy_smoke.cpp
//   RAWRXD_IDE_HTTP_ROUTE_CLOSURE_001 — policy-layer runtime smoke
//
// Why this exists as a separate harness from the HTTP smoke
//   The HTTP routes are the transport. The behaviour Gate 1 actually asserts --
//   that a request is served by the REAL sandboxed authority rather than by a
//   route-level 404, and that a write cannot happen without a rollback record --
//   lives below the transport, in rawrxd::agentic::ToolRegistry plus
//   rawrxd::ckpt::Transaction. This harness drives those directly so the claim
//   can be measured even when the server target does not compile because of
//   unrelated in-flight work elsewhere in the tree.
//
//   It is NOT a substitute for the HTTP smoke. The HTTP status codes and routing
//   are proven separately; this proves the authority behind them.
//
//   Every field printed is measured. The verdict is derived.
// ============================================================================
#include <windows.h>

#include <cstdio>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "agentic/AgentToolRegistry.h"
#include "agentic/CheckpointRollbackAuthority.h"

namespace agentic = rawrxd::agentic;
using rawrxd::ckpt::Transaction;

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
std::wstring joinW(const std::wstring& d, const char* leaf) {
    std::wstring o = d;
    if (!o.empty() && o.back() != L'\\') o.push_back(L'\\');
    return o + widen(leaf);
}
bool seedFile(const std::wstring& p, const char* body) {
    HANDLE h = ::CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    ::WriteFile(h, body, (DWORD)std::strlen(body), &w, nullptr);
    ::FlushFileBuffers(h);
    ::CloseHandle(h);
    return true;
}
std::string hashOf(const std::wstring& p) { return rawrxd::ckpt::sha256FileHex(narrow(p)); }

}  // namespace

int main() {
    wchar_t rootBuf[MAX_PATH] = {};
    const DWORD n = ::GetTempPathW(MAX_PATH, rootBuf);
    std::wstring ws = std::wstring(rootBuf, n) + L"gate1_policy_smoke";
    ::CreateDirectoryW(ws.c_str(), nullptr);
    const std::wstring aPath = joinW(ws, "a.txt");
    const std::wstring bPath = joinW(ws, "b.txt");
    const std::wstring cPath = joinW(ws, "c.txt");
    seedFile(aPath, "A original\n");
    seedFile(bPath, "B original\n");
    const std::string aHash0 = hashOf(aPath), bHash0 = hashOf(bPath);
    const std::string wsNarrow = narrow(ws);

    // ---- 1. the root canonicalisation that refused every absolute path -------
    std::string canonical, rootErr;
    const bool rootOk = agentic::CanonicalizeRoot(wsNarrow, canonical, rootErr);
    std::printf("ROOT_CANONICALIZE_OK=%d\n", rootOk ? 1 : 0);
    std::printf("ROOT_CANONICAL=%s\n", canonical.c_str());
    if (!rootOk) std::printf("ROOT_CANONICALIZE_ERROR=%s\n", rootErr.c_str());

    // ---- 2. policy with write enabled and the transactional profile on -------
    agentic::ToolPolicy pol;
    pol.allowedRoots.push_back(canonical.empty() ? wsNarrow : canonical);
    pol.allowWrite = true;
    pol.allowExecute = true;
    pol.writeRequiresTransaction = true;
    agentic::ToolRegistry& reg = agentic::ToolRegistry::Instance();
    reg.SetPolicy(pol);
    reg.InstallBuiltinTools();
    std::printf("TOOL_COUNT=%zu\n", reg.Size());
    for (const std::string& t : reg.GetToolNames()) std::printf("TOOL_NAME=%s\n", t.c_str());

    // ---- 3. a write with no transaction must be refused -----------------------
    {
        std::unordered_map<std::string, std::string> p;
        p["path"] = "a.txt";
        p["content"] = "HIJACK\n";
        const auto r = reg.Execute("write_file", p);
        std::printf("WRITE_WITHOUT_TX_OK=%d\n", r.success ? 1 : 0);
        std::printf("WRITE_WITHOUT_TX_ERR=%s\n", r.error.c_str());
        std::printf("A_UNCHANGED_AFTER_REFUSAL=%d\n", hashOf(aPath) == aHash0 ? 1 : 0);
    }

    // ---- 4. commit path: begin, write two files, commit ----------------------
    {
        rawrxd::ckpt::TransactionSpec spec;
        spec.workspaceRoot = canonical.empty() ? wsNarrow : canonical;
        spec.intent = "gate1 policy smoke";
        spec.plan = "edit a.txt and b.txt";
        spec.modelContext = "turn=1";
        spec.diagnostics = "e=0";
        std::string tx, err;
        const bool began = Transaction::Begin(spec, &tx, &err);
        std::printf("TX_BEGIN_OK=%d\n", began ? 1 : 0);
        std::printf("TX_ID=%s\n", tx.c_str());

        for (const auto& kv : {std::pair<const char*, const char*>{"a.txt", "A committed\n"},
                               {"b.txt", "B committed\n"}}) {
            std::unordered_map<std::string, std::string> p;
            p["path"] = kv.first;
            p["content"] = kv.second;
            const auto r = reg.Execute("write_file", p);
            std::printf("WRITE_IN_TX[%s]_OK=%d\n", kv.first, r.success ? 1 : 0);
            if (!r.success) std::printf("WRITE_IN_TX[%s]_ERR=%s\n", kv.first, r.error.c_str());
        }
        // a command inside the transaction, so CMD is journalled
        {
            std::unordered_map<std::string, std::string> p;
            p["command"] = "cmd /c echo GATE1";
            const auto r = reg.Execute("execute_command", p);
            std::printf("EXEC_IN_TX_OK=%d\n", r.success ? 1 : 0);
            if (!r.success) std::printf("EXEC_IN_TX_ERR=%s\n", r.error.c_str());
        }
        std::printf("COMMIT_OK=%d\n", Transaction::Commit(&err) ? 1 : 0);
        std::printf("A_CHANGED_AFTER_COMMIT=%d\n", hashOf(aPath) == aHash0 ? 0 : 1);
        std::printf("B_CHANGED_AFTER_COMMIT=%d\n", hashOf(bPath) == bHash0 ? 0 : 1);
    }

    // ---- 5. rollback path: begin, write, rollback -----------------------------
    {
        const std::string aHash1 = hashOf(aPath);
        rawrxd::ckpt::TransactionSpec spec;
        spec.workspaceRoot = canonical.empty() ? wsNarrow : canonical;
        spec.intent = "gate1 rollback smoke";
        spec.plan = "edit a.txt, then undo it";
        std::string tx, err;
        Transaction::Begin(spec, &tx, &err);
        std::unordered_map<std::string, std::string> p;
        p["path"] = "a.txt";
        p["content"] = "A overwritten again\n";
        const auto r = reg.Execute("write_file", p);
        std::printf("WRITE_BEFORE_ROLLBACK_OK=%d\n", r.success ? 1 : 0);
        std::printf("A_MODIFIED_BEFORE_ROLLBACK=%d\n", hashOf(aPath) == aHash1 ? 0 : 1);
        const std::string bHash1 = hashOf(bPath);
        std::unordered_map<std::string, std::string> p2;
        p2["path"] = "b.txt";
        p2["content"] = "B also overwritten\n";
        reg.Execute("write_file", p2);
        std::printf("ROLLBACK_OK=%d\n", Transaction::Rollback(&err) ? 1 : 0);
        std::printf("A_RESTORED_EXACT=%d\n", hashOf(aPath) == aHash1 ? 1 : 0);
        std::printf("B_RESTORED_EXACT=%d\n", hashOf(bPath) == bHash1 ? 1 : 0);
    }

    // ---- 6. a file created inside a rolled-back transaction is removed --------
    {
        const bool cExists0 = ::GetFileAttributesW(cPath.c_str()) != INVALID_FILE_ATTRIBUTES;
        rawrxd::ckpt::TransactionSpec spec;
        spec.workspaceRoot = canonical.empty() ? wsNarrow : canonical;
        spec.intent = "gate1 create-then-rollback";
        spec.plan = "create c.txt, then undo";
        std::string tx, err;
        Transaction::Begin(spec, &tx, &err);
        std::unordered_map<std::string, std::string> p;
        p["path"] = "c.txt";
        p["content"] = "C created by the agent\n";
        const auto r = reg.Execute("write_file", p);
        const bool cExists1 = ::GetFileAttributesW(cPath.c_str()) != INVALID_FILE_ATTRIBUTES;
        Transaction::Rollback(&err);
        const bool cExists2 = ::GetFileAttributesW(cPath.c_str()) != INVALID_FILE_ATTRIBUTES;
        std::printf("C_CREATE_OK=%d\n", r.success ? 1 : 0);
        std::printf("C_EXISTS_BEFORE=%d AFTER_CREATE=%d AFTER_ROLLBACK=%d\n",
                    cExists0 ? 1 : 0, cExists1 ? 1 : 0, cExists2 ? 1 : 0);
    }

    // ---- 7. sandbox containment still holds ----------------------------------
    {
        std::unordered_map<std::string, std::string> p;
        p["path"] = "..\\escape.txt";
        p["content"] = "nope\n";
        const auto r = reg.Execute("write_file", p);
        std::printf("ESCAPE_WRITE_OK=%d\n", r.success ? 1 : 0);
        std::printf("ESCAPE_WRITE_ERR=%s\n", r.error.c_str());
    }

    const auto c = Transaction::Counters();
    std::printf("COUNTERS journalRecords=%llu journalFlushes=%llu blobWrites=%llu "
                "atomicPublishes=%llu fileWrites=%llu fileDeletes=%llu\n",
                (unsigned long long)c.journalRecords, (unsigned long long)c.journalFlushes,
                (unsigned long long)c.blobWrites, (unsigned long long)c.atomicPublishes,
                (unsigned long long)c.fileWrites, (unsigned long long)c.fileDeletes);
    return 0;
}
