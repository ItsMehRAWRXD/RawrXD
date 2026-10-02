// tool_sandbox_matrix_cert.cpp
//   RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001 -- sandbox decision matrix
//
// The B83 cert exercised the WRITE path against the sandbox and the rollback
// engine. It did not exercise the other four built-in tools, which share the
// same ResolveUnderRoot()/IsPathAllowed() code that this changeset rewrote. A
// sandbox is only a claim about the paths it accepts, and until every tool has
// been measured against every class of path, "the sandbox refuses traversal"
// is a statement about one call site.
//
// This cert is a decision table, not a story. For each (tool, path class) pair
// it states the expected decision in advance and compares it against the
// measured one. Any disagreement is a failure; a class nobody thought to test
// is simply not in the table, which is why the table is written out in full
// below rather than generated.
//
// Path classes covered:
//   in_root_relative      "notes\a.txt"                     expect ACCEPT
//   in_root_absolute      "F:\...\work\notes\a.txt"         expect ACCEPT
//   root_itself           the workspace directory            expect REFUSE (see note)
//   dot                   "."                                expect REFUSE (P3, known)
//   traversal             "..\..\Windows\win.ini"            expect REFUSE
//   out_root_absolute     "C:\Windows\win.ini"               expect REFUSE
//   drive_relative        "C:win.ini"                        expect REFUSE
//   junction              "escape_link\secret.txt"           expect REFUSE
//   ads                   "a.txt:stream"                     expect REFUSE
//   unc                   "\\server\share\x"                 expect REFUSE
//   device                "\\?\C:\Windows\win.ini"           expect REFUSE
//   embedded_nul          "a.txt\0.txt"                      expect REFUSE
//   ckpt_tree             ".rawrxd\ckpt\journal\x.jrnl"      expect REFUSE
//
// The root_itself and dot rows are expected REFUSES on purpose. Both are the
// fail-closed direction, both are known UX findings rather than security
// holes, and a table that quietly expected them to succeed would be a table
// that hides them.
//
// Usage
//   tool_sandbox_matrix_cert <workspace-dir> [build-role]
//   The workspace must contain notes\a.txt and the junction escape_link -> <dir>
//   (the PowerShell wrapper builds both). Exit 0 iff every row matches.
//
// build-role is "candidate" for the authority under test and "control" for the
// deliberately defective build the falsification probe constructs. It is printed
// into the log so that a reader of this driver's raw output -- or an aggregate
// parser several runs later -- can tell a real certificate from a control that
// was SUPPOSED to violate the contract. This output contains no bare PASS or
// FAIL token: the four verdict terms cannot be mistaken for one another.

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

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

bool WriteSeed(const std::wstring& path, const char* bytes) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    ::WriteFile(h, bytes, static_cast<DWORD>(std::strlen(bytes)), &written, nullptr);
    ::CloseHandle(h);
    return true;
}

enum Decision { Accept, Refuse };

struct Row {
    std::string tool;
    std::string pathClass;
    std::string path;
    Decision expected;
    // For a REFUSE row, the reason the error MUST carry. Checking the boolean
    // alone would let "the sandbox refused it" and "the tool's own argument
    // contract rejected it" pass for the same row, which is exactly the
    // distinction a decision table exists to make.
    const char* mustSay;
    const char* why;  // what a correct sandbox must do here, for the record
};

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: tool_sandbox_matrix_cert <workspace-dir>\n");
        return 2;
    }
    const std::string ws = argv[1];
    const std::string role = (argc >= 3) ? std::string(argv[2]) : std::string("candidate");
    const std::wstring notesDir = widen(ws + "\\notes");
    ::CreateDirectoryW(notesDir.c_str(), nullptr);
    if (!WriteSeed(notesDir + L"\\a.txt", "// seed\n")) {
        std::fprintf(stderr, "SETUP_FAILED: could not seed notes\\a.txt\n");
        return 3;
    }

    using namespace rawrxd;
    agentic::ToolPolicy policy;
    policy.allowedRoots.push_back(ws);
    policy.allowWrite = true;
    policy.writeRequiresTransaction = true;  // the B83 profile, unchanged
    policy.allowExecute = true;              // so the cwd rows are reachable
    agentic::ToolRegistry& reg = agentic::ToolRegistry::Instance();
    reg.SetPolicy(policy);
    reg.InstallBuiltinTools();

    // The write rows need an open transaction, which is itself the thing B83
    // proved must be required. Open it for the whole matrix so that a WRITE
    // refusal can only be a sandbox refusal and not the transaction gate --
    // and T13-style checks in the HTTP cert already cover the gate itself.
    ckpt::TransactionSpec spec;
    spec.workspaceRoot = ws;
    spec.intent = "sandbox decision matrix";
    std::string txId;
    std::string error;
    if (!ckpt::Transaction::Begin(spec, &txId, &error)) {
        std::fprintf(stderr, "SETUP_FAILED: transaction begin: %s\n", error.c_str());
        return 4;
    }

    const std::string wsNotes = ws + "\\notes\\a.txt";
    // A NUL byte cannot travel through JSON, so this class is untestable from
    // the HTTP harness; it can only be reached from a direct caller, which is
    // exactly why it belongs in a table rather than in the route cert.
    std::string nulPath = "notes\\a.txt";
    nulPath.push_back('\0');
    nulPath += ".txt";

    // search_code's declared contract is a FILE, not a directory: its schema
    // says "File to search" and it opens the path with CreateFileW. A directory
    // is therefore refused by the tool's own argument contract, not by the
    // sandbox, and the table says so with mustSay="cannot open". There is no
    // recursive workspace search in this registry -- a finding, not a defect.
    const std::string kEscapes = "escapes the allowed root";
    const std::string kReparse = "reparse point";
    const std::string kScheme = "device, stream";
    const std::string kUnc = "UNC paths are not permitted";

    std::vector<Row> rows = {
        // ---- read_file -------------------------------------------------
        {"read_file", "in_root_relative", "notes\\a.txt", Accept, "", "the ordinary case"},
        {"read_file", "in_root_absolute", wsNotes, Accept, "",
         "an IDE sends absolute paths; declared as relative-only, actually both"},
        {"read_file", "root_itself", ws, Refuse, kEscapes.c_str(),
         "the root has no trailing separator to match"},
        {"read_file", "dot", ".", Refuse, kEscapes.c_str(), "P3 UX finding, fail-closed"},
        {"read_file", "traversal", "..\\..\\Windows\\win.ini", Refuse, kEscapes.c_str(),
         "lexical escape"},
        {"read_file", "out_root_absolute", "C:\\Windows\\win.ini", Refuse, kEscapes.c_str(),
         "absolute escape"},
        {"read_file", "drive_relative", "C:win.ini", Refuse, kScheme.c_str(),
         "per-drive cwd is process state, not a sandbox root"},
        {"read_file", "junction", "escape_link\\secret.txt", Refuse, kReparse.c_str(),
         "reparse point"},
        {"read_file", "ads", "notes\\a.txt:stream", Refuse, kScheme.c_str(),
         "NTFS alternate data stream"},
        {"read_file", "unc", "\\\\server\\share\\x", Refuse, kUnc.c_str(), "UNC"},
        {"read_file", "device", "\\\\?\\C:\\Windows\\win.ini", Refuse, kUnc.c_str(),
         "NT device path"},
        {"read_file", "embedded_nul", nulPath, Refuse, "NUL", "embedded NUL byte"},
        // ---- list_directory --------------------------------------------
        {"list_directory", "in_root_relative", "notes", Accept, "", "the ordinary case"},
        {"list_directory", "in_root_absolute", ws + "\\notes", Accept, "", "absolute in-root"},
        {"list_directory", "dot", ".", Refuse, kEscapes.c_str(), "P3 UX finding, fail-closed"},
        {"list_directory", "traversal", "..\\..", Refuse, kEscapes.c_str(), "lexical escape"},
        {"list_directory", "out_root_absolute", "C:\\Windows", Refuse, kEscapes.c_str(),
         "absolute escape"},
        {"list_directory", "junction", "escape_link", Refuse, kReparse.c_str(),
         "reparse point"},
        {"list_directory", "unc", "\\\\server\\share", Refuse, kUnc.c_str(), "UNC"},
        // ---- search_code (path is a FILE) -------------------------------
        {"search_code", "in_root_relative", "notes\\a.txt", Accept, "", "the ordinary case"},
        {"search_code", "in_root_absolute", wsNotes, Accept, "", "absolute in-root"},
        {"search_code", "directory_is_not_a_file", "notes", Refuse, "cannot open",
         "tool contract: search_code opens a file, it does not walk a tree"},
        {"search_code", "traversal", "..\\..\\Windows\\win.exe", Refuse, kEscapes.c_str(),
         "lexical escape"},
        {"search_code", "out_root_absolute", "C:\\Windows\\win.ini", Refuse, kEscapes.c_str(),
         "absolute escape"},
        {"search_code", "junction", "escape_link\\secret.txt", Refuse, kReparse.c_str(),
         "reparse point"},
        // ---- write_file (transaction already open) ----------------------
        {"write_file", "in_root_relative", "notes\\b.txt", Accept, "", "the ordinary case"},
        {"write_file", "in_root_absolute", ws + "\\notes\\c.txt", Accept, "", "absolute in-root"},
        {"write_file", "traversal", "..\\..\\escape.txt", Refuse, kEscapes.c_str(),
         "lexical escape"},
        {"write_file", "out_root_absolute", "C:\\Windows\\Temp\\planted.txt", Refuse,
         kEscapes.c_str(), "absolute escape"},
        {"write_file", "junction", "escape_link\\planted.txt", Refuse, kReparse.c_str(),
         "reparse point: an arbitrary-write primitive"},
        {"write_file", "ckpt_tree", ".rawrxd\\ckpt\\journal\\forged.jrnl", Refuse,
         "checkpoint tree", "an agent must not be able to erase the record of its own edit"},
        // ---- execute_command (cwd is the only path input) ---------------
        {"execute_command", "in_root_relative", "notes", Accept, "", "cwd inside the root"},
        {"execute_command", "out_root_absolute", "C:\\Windows", Refuse, kEscapes.c_str(),
         "cwd escape"},
        {"execute_command", "junction", "escape_link", Refuse, kReparse.c_str(),
         "cwd through a junction"},
        {"execute_command", "traversal", "..\\..", Refuse, kEscapes.c_str(),
         "cwd lexical escape"},
    };

    int failures = 0;
    int rowsChecked = 0;
    std::printf("tool                path_class                 expected  actual  reason_ok  error\n");
    for (const Row& row : rows) {
        std::unordered_map<std::string, std::string> params;
        if (row.tool == "execute_command") {
            // execute_command takes its path through "cwd", not "path". A row
            // that passed "path" here would silently test the default working
            // directory and prove nothing, which is how three rows in the first
            // run of this table reported a "mismatch" that was the table's bug.
            params["cwd"] = row.path;
            params["command"] = "cmd /d /c exit 0";  // benign; cwd is the subject
        } else {
            params["path"] = row.path;
        }
        if (row.tool == "search_code") params["pattern"] = "seed";
        if (row.tool == "write_file") params["content"] = "matrix\n";
        const agentic::ToolResult r = reg.Execute(row.tool, params);
        const bool accepted = r.success;
        const Decision actual = accepted ? Accept : Refuse;
        rowsChecked++;
        const bool decisionOk = (actual == row.expected);
        const bool reasonOk =
            (row.expected == Accept) || (r.error.find(row.mustSay) != std::string::npos);
        const bool ok = decisionOk && reasonOk;
        if (!ok) failures++;
        std::string err = r.error;
        if (err.size() > 52) err = err.substr(0, 49) + "...";
        std::printf("%-18s %-24s %-9s %-7s %-11s %s%s\n", row.tool.c_str(), row.pathClass.c_str(),
                    row.expected == Accept ? "ACCEPT" : "REFUSE", decisionOk ? "ok" : "MISMATCH",
                    reasonOk ? "ok" : "WRONG-REASON", err.c_str(),
                    ok ? "" : "   <-- EXPECTATION VIOLATED");
    }

    // The matrix asked for writes; they must all be inside the workspace and
    // all of them must be undoable, so the run ends by rolling the transaction
    // back and reporting what the recovery pass actually did.
    ckpt::Transaction::Rollback(&error);
    const auto rep = ckpt::Transaction::LastRecovery();
    std::printf("\nrows=%d\nmismatches=%d\n", rowsChecked, failures);
    std::printf("rollback_files_restored=%d rollback_files_deleted=%d rollback_files_failed=%d\n",
                rep.filesRestored, rep.filesDeleted, rep.filesFailed);
    // Verdict vocabulary, deliberately not PASS/FAIL. A control build is
    // SUPPOSED to violate the contract, so a log full of bare PASS tokens
    // cannot be aggregated honestly: a parser would count the deliberately
    // defective builds as successes.
    //   CONTRACT_SATISFIED = the build met every expectation
    //   CONTRACT_VIOLATED  = the build did not
    std::printf("build_role=%s\n", role.c_str());
    std::printf("RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001_SANDBOX_MATRIX_VERDICT=%s\n",
                failures == 0 ? "CONTRACT_SATISFIED" : "CONTRACT_VIOLATED");
    return failures == 0 ? 0 : 1;
}
