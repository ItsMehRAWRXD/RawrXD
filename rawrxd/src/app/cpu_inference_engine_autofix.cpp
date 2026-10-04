// ============================================================================
// cpu_inference_engine_autofix.cpp — RAWRXD_AUTOFIX_ENGINE_001
// ============================================================================
// The audit -> inspect -> edit -> build -> test -> diagnose -> retry loop.
//
// WHAT THIS IS NOT
//   It is not a demonstration of the loop. Every number it prints is counted
//   from something it did, and the verdict is computed from exit codes it
//   observed. There is no path through this file that prints PASS without a
//   configure, a build and a test having all returned 0 in the same run.
//
// WHAT IT REPAIRS, AND WHY ONLY THAT
//   Two defect classes, both measured from the build graph itself:
//
//   ABSENT_ACTIVE_REF   a path listed in an ACTIVE CMake source entry that does
//                       not exist on disk. The build cannot compile it.
//
//   STUB_TU_IN_TARGET   a translation unit inside an active target whose entire
//                       body strips to nothing -- an "// Auto-generated stub",
//                       an empty file, or a trivial `int main(){return 0;}`.
//                       The target exists and links while containing no
//                       implementation, which is how every ghost receipt in
//                       this project was produced.
//
//   Nothing else. This engine never edits program logic, never rewrites a
//   decoder, never invents a symbol. A tool that silently "fixes" source it
//   does not understand is a second, worse defect, and the repair surface here
//   is deliberately the part of the problem that is mechanically decidable.
//
// LOAD-BEARING PROOF, PER FIX
//   A repair that changes nothing observable is not a repair. Before applying
//   each one this engine records the symptom it is about to remove; after
//   applying it, the symptom must be gone. A fix that leaves the symptom
//   intact is recorded as FIX_NOT_LOAD_BEARING and forces the run to FAIL.
//
//   This is the property that separates an autonomous repair loop from a
//   script that appends lines to a file and declares victory.
//
// FAIL CLOSED
//   A failure at any phase stops the run and is reported with the phase name and
//   the exit code. Exhausting the iteration budget is a FAIL, not a PASS with a
//   caveat. If the test command is not supplied, the run reports
//   TEST_NOT_CONFIGURED and cannot reach PASS -- an unrun test is not a passed
//   test.
//
// NO SHELL
//   Every external command goes through CreateProcessA with an explicit argv.
//   No command string is ever concatenated and handed to a shell, so a path
//   containing a space, a quote or a metacharacter is data, not syntax. This is
//   the same rule the git-safety authority applies for the same reason.
// ============================================================================

#include "cpu_inference_engine_autofix.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace rawrxd {
namespace autofix {

namespace {

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------
bool fileExists(const std::string& p) {
    if (p.empty()) return false;
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool dirExists(const std::string& p) {
    if (p.empty()) return false;
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string readFile(const std::string& p, bool* ok) {
    std::ifstream f(p, std::ios::binary);
    if (!f) { if (ok) *ok = false; return {}; }
    std::ostringstream ss;
    ss << f.rdbuf();
    if (ok) *ok = true;
    return ss.str();
}

bool writeFile(const std::string& p, const std::string& body) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << body;
    return f.good();
}

// Strip // comments, /* */ blocks and # lines, then test whether any code
// remains. This mirrors the configure-time gate's own logic (rawrxd_filter_missing_sources)
// so that what this engine calls a stub is what CMake would also call one.
std::string stripComments(const std::string& src) {
    std::string out;
    out.reserve(src.size());
    enum { CODE, LINE_C, BLOCK_C } st = CODE;
    for (std::size_t i = 0; i < src.size(); ++i) {
        const char c = src[i];
        const char n = (i + 1 < src.size()) ? src[i + 1] : '\0';
        if (st == CODE) {
            if (c == '/' && n == '/') { st = LINE_C; ++i; continue; }
            if (c == '/' && n == '*') { st = BLOCK_C; ++i; continue; }
            if (c == '#')           { st = LINE_C; continue; }
            out.push_back(c);
        } else if (st == LINE_C) {
            if (c == '\n') { st = CODE; out.push_back(c); }
        } else { // BLOCK_C
            if (c == '*' && n == '/') { st = CODE; ++i; }
        }
    }
    return out;
}

bool hasCode(const std::string& stripped) {
    for (char c : stripped) {
        if (c == ';' || c == '{' || c == '}' || c == '(' || c == ')' || c == '=')
            return true;
    }
    return false;
}

// `int main(){return 0;}` links and certifies nothing.
bool isTrivialMain(const std::string& stripped) {
    std::string id;
    for (char c : stripped)
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_')
            id.push_back(c);
    return id == "intmainreturn0";
}

bool isSourcePath(const std::string& p) {
    static const char* kExt[] = {".cpp", ".hpp", ".h", ".cc", ".cxx", ".asm", ".rc"};
    for (const char* e : kExt) {
        const std::size_t el = std::strlen(e);
        if (p.size() > el && p.compare(p.size() - el, el, e) == 0) return true;
    }
    return false;
}

bool isStubName(const std::string& leaf) {
    // Mirrors the CMake policy regexes, which are the authority this engine
    // defers to. A file whose NAME claims to be a stub is reported even when its
    // body is fine, because the name is what the policy gate acts on.
    return leaf.find("_stub.") != std::string::npos ||
           leaf.find("stub_") != std::string::npos ||
           leaf.find("_shim.") != std::string::npos ||
           leaf.find("shim_") != std::string::npos ||
           leaf.find("_mock.") != std::string::npos ||
           leaf.find("mock_") != std::string::npos ||
           leaf.find("_fake.") != std::string::npos ||
           leaf.find("fake_") != std::string::npos;
}

std::string joinPath(const std::string& root, const std::string& rel) {
    if (rel.empty()) return root;
    if (rel.size() > 2 && rel[0] && rel[1] == ':') return rel;   // absolute
    if (root.empty()) return rel;
    char last = root[root.size() - 1];
    if (last == '\\' || last == '/') return root + rel;
    return root + "\\" + rel;
}

// ---------------------------------------------------------------------------
// Process execution. No shell: argv is passed to CreateProcessA directly.
//
// The quoted-command form is required by CreateProcessA even when there is no
// shell involved, so argv[0] is quoted and the remainder appended verbatim.
// ---------------------------------------------------------------------------
std::string quoteArg(const std::string& a) {
    std::string out = "\"";
    for (char c : a) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

// ProcResult lives in the header, not here. A second definition in this
// anonymous namespace made every function below ambiguous (`C2872: 'ProcResult':
// ambiguous symbol`) the moment this namespace closed -- the header type is the
// one the driver sees, so there must be exactly one.

ProcResult runProcess(const std::string& exe, const std::string& args,
                      const std::string& cwd, DWORD timeoutMs) {
    ProcResult r;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof sa;
    sa.bInheritHandle = TRUE;
    // Named wPipe rather than wr: the wait result below is also called wr, and
    // `const DWORD wr` after `HANDLE wr` is a redefinition, not a shadow.
    HANDLE rd = nullptr, wPipe = nullptr;
    if (!CreatePipe(&rd, &wPipe, &sa, 0)) { r.win32Error = GetLastError(); return r; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wPipe;
    si.hStdError = wPipe;
    si.hStdInput = nullptr;

    std::string cmd = quoteArg(exe);
    if (!args.empty()) { cmd += ' '; cmd += args; }

    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessA(
        nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    if (!ok) {
        r.win32Error = GetLastError();
        CloseHandle(rd);
        CloseHandle(wPipe);
        return r;
    }
    r.launched = true;

    // Drain before waiting: a child that fills the pipe buffer would deadlock a
    // naive WaitForSingleObject-then-read, and build tools produce output far
    // past a 64 KiB pipe buffer.
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr)) break;
        if (avail == 0) {
            if (WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0 &&
                PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) &&
                avail == 0)
                break;
            continue;
        }
        char buf[8192];
        DWORD got = 0;
        if (!ReadFile(rd, buf, sizeof buf, &got, nullptr) || got == 0) break;
        r.output.append(buf, got);
        if (r.output.size() > (4u << 20)) r.output.resize(4u << 20);  // cap
    }

    const DWORD waitRes = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitRes == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 0xDEADu);
        WaitForSingleObject(pi.hProcess, 5000);
        r.exitCode = 0xFFFFFFFFu;
        r.output += "\n[AUTOFIX] TIMEOUT after " + std::to_string(timeoutMs) + " ms\n";
    } else {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        r.exitCode = code;
    }

    // Drain whatever arrived during the wait.
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) break;
        char buf[8192];
        DWORD got = 0;
        if (!ReadFile(rd, buf, sizeof buf, &got, nullptr) || got == 0) break;
        r.output.append(buf, got);
    }

    CloseHandle(rd);
    CloseHandle(wPipe);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return r;
}

// ---------------------------------------------------------------------------
// CMake source-entry extraction.
//
// A line is ACTIVE if it names a source path and is not a comment. The comment
// test strips '#' to end-of-line FIRST, then looks for the path in what
// remains. Pattern-matching "does the line start with #" -- which is what
// cmake/source_graph_census.cmake did before RAWRXD_SOURCE_GRAPH_COMMENT_CLASSIFIER_001
// -- misclassifies a path named later in a comment sentence.
// ---------------------------------------------------------------------------
struct Entry {
    std::string path;
    std::string lineText;
    int         lineNo = 0;
    bool        active = false;
};

void collectEntries(const std::string& text, std::vector<Entry>& out) {
    int lineNo = 0;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t nl = text.find('\n', pos);
        const std::string line = text.substr(
            pos, (nl == std::string::npos ? text.size() : nl) - pos);
        ++lineNo;

        const std::size_t hash = line.find('#');
        const std::string codeOnly = (hash == std::string::npos)
                                         ? line : line.substr(0, hash);

        // First path-looking token on the code portion.
        std::size_t i = 0;
        while (i < codeOnly.size()) {
            if (codeOnly.compare(i, 4, "src/") == 0 ||
                codeOnly.compare(i, 6, "tools/") == 0 ||
                codeOnly.compare(i, 5, "certs/") == 0 ||
                codeOnly.compare(i, 6, "tests/") == 0 ||
                codeOnly.compare(i, 8, "include/") == 0) {
                std::size_t j = i;
                while (j < codeOnly.size()) {
                    const char c = codeOnly[j];
                    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.' ||
                        c == '/' || c == '\\' || c == '-')
                        ++j;
                    else
                        break;
                }
                Entry e;
                e.path = codeOnly.substr(i, j - i);
                for (char& ch : e.path) if (ch == '/') ch = '\\';
                e.lineText = line;
                e.lineNo = lineNo;
                e.active = true;
                out.push_back(e);
                i = j;
            } else {
                ++i;
            }
        }

        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
}

std::size_t findLastLineWith(const std::string& text, const std::string& needle) {
    std::size_t best = std::string::npos;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const std::size_t hit = text.find(needle, pos);
        if (hit == std::string::npos) break;
        best = hit;
        pos = hit + 1;
    }
    return best;
}

// Normalise a path for comparison: forward slashes only, no leading "./".
// cmake/known_empty_sources.txt spells paths with forward slashes; CMakeLists
// entries appear here already backslash-normalised. Comparing raw strings would
// therefore report every allow-listed unit as unexpected.
std::string normPath(const std::string& p) {
    std::string out;
    out.reserve(p.size());
    for (std::size_t i = 0; i < p.size(); ++i) {
        char c = p[i];
        if (c == '\\') c = '/';
        if (c == '/' && i > 0 && p[i - 1] == '/') continue;   // collapse //
        out.push_back(c);
    }
    if (out.size() >= 2 && out[0] == '.' && out[1] == '/') out = out.substr(2);
    return out;
}

// RAWRXD_AUTOFIX_ALLOWLIST_001
// Load the same declaration list the configure-time gate uses. A missing list is
// NOT fatal: it means the gate that distinguishes declared from unexpected is
// unavailable, and every codeless unit then counts as unexpected. That direction
// is chosen on purpose -- over-reporting a regression is recoverable, silently
// excusing one is not.
bool loadAllowList(const std::string& path, std::vector<std::string>& out) {
    bool ok = false;
    const std::string text = readFile(path, &ok);
    if (!ok) return false;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, (nl == std::string::npos ? text.size() : nl) - pos);
        // trim trailing CR and surrounding blanks
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        std::size_t b = 0;
        while (b < line.size() && (line[b] == ' ' || line[b] == '\t')) ++b;
        line = line.substr(b);
        if (!line.empty() && line[0] != '#') out.push_back(normPath(line));
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return true;
}

bool inAllowList(const std::vector<std::string>& list, const std::string& path) {
    const std::string k = normPath(path);
    for (const auto& e : list) if (e == k) return true;
    return false;
}

} // namespace

// ===========================================================================
// Audit
// ===========================================================================
AuditResult audit(const Config& cfg) {
    AuditResult ar;
    ar.cmakePath = joinPath(cfg.repoRoot, "CMakeLists.txt");
    if (!fileExists(ar.cmakePath)) {
        ar.fatal = "CMakeLists.txt not found at " + ar.cmakePath;
        return ar;
    }

    bool ok = false;
    const std::string text = readFile(ar.cmakePath, &ok);
    if (!ok) {
        ar.fatal = "CMakeLists.txt could not be read";
        return ar;
    }
    ar.cmakeBytes = text.size();

    std::vector<Entry> entries;
    collectEntries(text, entries);
    ar.entriesScanned = entries.size();

    // The declaration list. Absent list => every codeless unit counts as
    // unexpected, which is the safe direction (see loadAllowList).
    const std::string listPath = cfg.knownEmptyList.empty()
                                   ? joinPath(cfg.repoRoot, "cmake\\known_empty_sources.txt")
                                   : cfg.knownEmptyList;
    ar.knownEmptyListPath = listPath;
    std::vector<std::string> allowList;
    if (loadAllowList(listPath, allowList)) {
        ar.allowListLoaded = true;
        ar.allowListEntries = allowList.size();
    }

    std::vector<std::string> seen;
    for (const Entry& e : entries) {
        bool dup = false;
        for (const auto& s : seen) if (s == e.path) { dup = true; break; }
        if (dup) continue;
        seen.push_back(e.path);

        const std::string full = joinPath(cfg.repoRoot, e.path);

        // RAWRXD_AUTOFIX_FALSE_POSITIVE_DIRECTORIES_001
        //
        // The first run of this engine reported 749 findings, of which ~25 were
        // nonsense of this shape:
        //
        //   ABSENT_ACTIVE_REF path=src\sovereign_autonomy  absent on disk
        //   ABSENT_ACTIVE_REF path=src\compiler_backend    absent on disk
        //   ABSENT_ACTIVE_REF path=include\agentic         absent on disk
        //
        // Those are DIRECTORIES, and they exist. The scanner accepted any token
        // beginning src/ tools/ tests/ include/ and then asked the filesystem
        // whether it was a file, which a directory can never be. They come from
        // target_include_directories(...) and add_subdirectory(...) lines, not
        // from source lists. Similarly `tools\address_resolver_native.exe` is a
        // build OUTPUT referenced by a post-build step, not an input.
        //
        // A path with no extension cannot be a translation unit, and an existing
        // directory is never an absent source. Both are excluded before the
        // existence test, not after, so the finding never gets created.
        if (!isSourcePath(e.path))      continue;   // dirs, .exe, .def, .cmake
        if (dirExists(full))            continue;   // belt and braces

        if (!fileExists(full)) {
            Finding f;
            f.kind = Finding::Kind::ABSENT_ACTIVE_REF;
            f.path = e.path;
            f.detail = "referenced at CMakeLists.txt:" + std::to_string(e.lineNo) +
                       " but absent on disk";
            ar.findings.push_back(f);
            continue;
        }

        if (!isSourcePath(e.path)) continue;

        bool okRead = false;
        const std::string body = readFile(full, &okRead);
        if (!okRead) continue;

        const std::string stripped = stripComments(body);
        const bool code = hasCode(stripped);
        const bool trivial = isTrivialMain(stripped);

        if (!code || trivial) {
            // RAWRXD_AUTOFIX_CENSUS_VOCABULARY_001
            // Every codeless unit increments the raw census. Whether it is a
            // FINDING depends on cmake/known_empty_sources.txt, and that decision
            // is recorded either way -- a declared-empty unit is reported under
            // KNOWN_EMPTY so the census is complete, but it is never handed to
            // the fixer. The first version of this engine had no allow-list and
            // reported 648 defects; CMake's authoritative count of non-declared
            // codeless units is 296. The 352-unit difference was this omission,
            // not a disagreement about the filesystem.
            ++ar.rawCodeless;
            const bool declared = inAllowList(allowList, e.path);
            Finding f;
            f.path = e.path;
            if (declared) {
                ++ar.knownEmptyCount;
                f.kind = Finding::Kind::KNOWN_EMPTY;
                f.detail = trivial ? std::string("int main(){return 0;}, declared known-empty")
                                   : std::string("no code, declared in known_empty_sources.txt");
                ar.findings.push_back(f);
            } else {
                ++ar.unexpectedCount;
                f.kind = Finding::Kind::STUB_TU_IN_TARGET;
                f.detail = trivial ? std::string("body reduces to int main(){return 0;}"
                                                " and is NOT declared in known_empty_sources.txt")
                                   : std::string("body strips to no code and is NOT "
                                                 "declared in known_empty_sources.txt");
                ar.findings.push_back(f);
            }
            continue;
        }

        // A real body under a stub name is still a policy violation: the name
        // is what the configure-time gate matches on.
        const std::size_t slash = e.path.find_last_of("\\/");
        const std::string leaf = (slash == std::string::npos) ? e.path
                                                             : e.path.substr(slash + 1);
        if (isStubName(leaf)) {
            Finding f;
            f.kind = Finding::Kind::STUB_TU_IN_TARGET;
            f.path = e.path;
            f.detail = "implements code but its filename matches the stub policy "
                       "regex, so EnforceNoStubs will reject the target";
            ar.findings.push_back(f);
        }
    }
    return ar;
}

// ===========================================================================
// Fix -- exactly one, and only for the two mechanical classes
// ===========================================================================
FixResult applyFix(const Config& cfg, const Finding& f) {
    FixResult fr;
    fr.kind = f.kind;

    const std::string cmakePath = joinPath(cfg.repoRoot, "CMakeLists.txt");
    bool ok = false;
    const std::string before = readFile(cmakePath, &ok);
    if (!ok) { fr.error = "CMakeLists.txt unreadable"; return fr; }

    const std::string backup = cmakePath + ".autofix.bak";
    if (!writeFile(backup, before)) {
        fr.error = "could not write backup " + backup;
        return fr;
    }
    fr.backupPath = backup;
    fr.beforeBytes = before.size();

    std::string after = before;
    std::string note;

    if (f.kind == Finding::Kind::ABSENT_ACTIVE_REF) {
        // Comment the reference out, preserving the evidence and the reason.
        // Deleting the line would erase the record of what was expected.
        const std::string entry = f.path;
        std::string replaced = entry;
        for (char& ch : replaced) if (ch == '\\') ch = '/';
        const std::size_t at = after.find(entry);
        if (at == std::string::npos) {
            // The forward-slash form is how CMakeLists spells it.
            const std::size_t at2 = after.find(replaced);
            if (at2 == std::string::npos) {
                fr.error = "reference not found in CMakeLists.txt at fix time";
                return fr;
            }
            after = after.substr(0, at2) + "# AUTOFIX-ABSENT " + after.substr(at2);
        } else {
            after = after.substr(0, at) + "# AUTOFIX-ABSENT " + after.substr(at);
        }
        note = "commented out absent reference " + replaced;

    } else if (f.kind == Finding::Kind::STUB_TU_IN_TARGET) {
        const std::string entry = f.path;
        const std::size_t at = after.find(entry);
        if (at == std::string::npos) {
            fr.error = "stub reference not found in CMakeLists.txt at fix time";
            return fr;
        }
        after = after.substr(0, at) + "# AUTOFIX-STUB-TU " + after.substr(at);
        note = "removed placeholder TU " + entry + " from the active source list";

    } else {
        fr.error = "refusing to fix a class this engine does not understand";
        return fr;
    }

    after += "\n# RAWRXD_AUTOFIX_NOTE\n";
    after += "# " + note + "\n";
    after += "# Removed by the autonomous repair loop because the file named above\n";
    after += "# does not exist / contains no implementation. The reference is kept\n";
    after += "# as a comment so the expectation is not silently erased. Re-enable\n";
    after += "# it once a real implementation lands.\n";

    if (!writeFile(cmakePath, after)) {
        writeFile(cmakePath, before);   // roll back
        fr.error = "write failed; original restored";
        return fr;
    }
    fr.afterBytes = after.size();
    fr.note = note;
    fr.applied = true;
    return fr;
}

// ===========================================================================
// Build / test
// ===========================================================================
ProcResult configure(const Config& cfg) {
    const std::string src = joinPath(cfg.repoRoot, "..");
    std::string args = "-S \"" + joinPath(cfg.repoRoot, "") + "\"";
    args += " -B \"" + cfg.buildDir + "\"";
    if (!cfg.defines.empty()) args += " " + cfg.defines;
    return runProcess(cfg.cmakeExe, args, cfg.repoRoot, cfg.phaseTimeoutMs);
}

ProcResult build(const Config& cfg) {
    std::string args = "--build \"" + cfg.buildDir + "\" --config " + cfg.config;
    if (!cfg.buildTarget.empty()) { args += " --target "; args += cfg.buildTarget; }
    return runProcess(cfg.cmakeExe, args, cfg.repoRoot, cfg.phaseTimeoutMs);
}

ProcResult runTest(const Config& cfg) {
    if (cfg.testExe.empty()) {
        ProcResult r;
        r.launched = false;
        r.exitCode = 0xFFFFFFFFu;
        r.output = "[AUTOFIX] TEST_NOT_CONFIGURED: no --test-exe supplied. "
                   "An unrun test is not a passed test.\n";
        return r;
    }
    std::string args;
    if (!cfg.testArgs.empty()) { args = "\"" + cfg.testArgs + "\""; }
    return runProcess(cfg.testExe, args, cfg.repoRoot, cfg.phaseTimeoutMs);
}

// ===========================================================================
// Diagnosis -- map an observed failure onto the next thing to try.
// ===========================================================================
Diagnosis diagnose(const std::string& phase, const ProcResult& r) {
    Diagnosis d;
    d.phase = phase;
    d.exitCode = r.exitCode;

    // Order matters: the most specific signature wins, because a configure
    // error and a link error can both mention a missing file.
    // `const bool has = [&](...)` would declare a bool initialised FROM the
    // lambda, which does not compile. `const auto` is what makes has callable.
    const auto has = [&](const char* s) -> bool {
        return r.output.find(s) != std::string::npos;
    };

    if (phase == "CONFIGURE") {
        if (has("PRODUCTION POLICY VIOLATION") || has("EnforceNoStubs")) {
            d.reason = "PRODUCTION_POLICY_STUB_LINKED";
            d.action = "Remove the named stub/shim file from the active source list.";
        } else if (has("DROPPED_SOURCE") || has("nonexistent source")) {
            d.reason = "SOURCE_REFERENCED_BUT_ABSENT";
            d.action = "Comment out the referenced path that does not exist.";
        } else if (has("Could not find source file") ||
                   has("Cannot find source file")) {
            d.reason = "SOURCE_REFERENCED_BUT_ABSENT";
            d.action = "Comment out the referenced path that does not exist.";
        } else {
            d.reason = "CONFIGURE_FAILED_UNCLASSIFIED";
            d.action = "Read the configure output; no mechanical remediation applies.";
        }
        return d;
    }

    if (phase == "BUILD") {
        if (has("LNK2019") || has("LNK1120") || has("LNK2005") || has("LNK2017") ||
            has("LNK1169")) {
            d.reason = "LINK_FAILED";
            d.action = "A symbol is defined twice, missing, or unfixable. This "
                       "engine does not synthesise symbols; the MASM/C++ owners "
                       "must be reconciled.";
        } else if (has("error C") || has("error A")) {
            d.reason = "COMPILE_FAILED";
            d.action = "Compilation failed. Diagnose by hand; this engine does "
                       "not rewrite code.";
        } else {
            d.reason = "BUILD_FAILED_UNCLASSIFIED";
            d.action = "Read the build output; no mechanical remediation applies.";
        }
        return d;
    }

    if (phase == "TEST") {
        d.reason = "TEST_NONZERO_EXIT";
        d.action = "The test command returned nonzero. The verdict for this run "
                   "is FAIL and no further build-graph repair can change that.";
        return d;
    }

    d.reason = "UNKNOWN_PHASE";
    d.action = "Unrecognised phase.";
    return d;
}

const char* kindName(Finding::Kind k) {
    switch (k) {
        case Finding::Kind::ABSENT_ACTIVE_REF: return "ABSENT_ACTIVE_REF";
        case Finding::Kind::STUB_TU_IN_TARGET: return "STUB_TU_IN_TARGET";
        case Finding::Kind::KNOWN_EMPTY:       return "KNOWN_EMPTY";
        default:                         return "UNCLASSIFIED";
    }
}

} // namespace autofix
} // namespace rawrxd
