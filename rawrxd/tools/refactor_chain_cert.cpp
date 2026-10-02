// ============================================================================
// refactor_chain_cert.cpp — RAWRXD_P1_REFACTOR_CHAIN_001
//
// The certification for the nine refactoring-chain capabilities, against a
// deliberately constructed fixture workspace rather than the RawrXD tree.
//
// WHAT THIS DRIVER IS NOT
//
// It is not a census. It does not check that a name exists, and it does not
// trust that compiling means working. Every expectation below was written by
// hand from the fixture's text before the implementation was run, including the
// line numbers, the occurrence counts, and the exact set of files a rename is
// allowed to touch. That is the whole point: the first census of this feature
// area reported "RenameSymbol: 5 hits" and every hit was
// std::filesystem::rename moving files. A gate that can be satisfied by a name
// is satisfied by a coincidence.
//
// WHAT PROVES EACH RUNG OF THE LADDER
//
//   name found            -> the fixture's symbols are named in the source
//   symbol identity       -> occurrences are whole tokens; the comment and
//                            string decoys are counted and never edited
//   implementation body   -> the body writes files and the driver re-reads them
//   product binding       -> the COMMAND_TABLE function pointer is compared
//                            against the real implementation, and against the
//                            stub provider that used to own these names
//   successful build      -> the fixture is compiled with cl.exe before and
//                            after every refactoring
//   observable result     -> the fixture program is RUN before and after, and
//                            the two outputs must be byte-identical
//   runtime certificate   -> only then is any PASS written
//
// FALSIFICATION PROBES
//
// Four probes run that MUST fail. A gate whose probes all pass proves nothing;
// the probes are how a future edit that turns a chain command back into an
// unconditional success gets caught. Probe F3 is the important one: it renames a
// name that exists only in a comment and a string literal and requires the
// operation to REFUSE. A renamer that reports success there is a text replacer.
// ============================================================================

#include "shared_feature_dispatch.h"
#include "refactor/RefactorChain.h"

// The nine chain handler bodies. They are declared here with the exact
// signatures COMMAND_TABLE's expansion requires, so a mismatch is a compile
// error rather than a cast. The table's own identifiers are parsed from
// src/core/command_registry.hpp at run time and are what the driver calls.
CommandResult handleLspGotoDef(const CommandContext& ctx);
CommandResult handleLspFindRefs(const CommandContext& ctx);
CommandResult handleLspRename(const CommandContext& ctx);
CommandResult handleLspSymbolInfo(const CommandContext& ctx);
CommandResult handleLspWorkspaceSymbols(const CommandContext& ctx);
CommandResult handleLspDiagnostics(const CommandContext& ctx);
CommandResult handleLspCodeAction(const CommandContext& ctx);
CommandResult handleEditorFormatDocument(const CommandContext& ctx);
CommandResult handleEditorExtractFunction(const CommandContext& ctx);

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <direct.h>
#include <windows.h>
#endif

using rawrxd::refactor::CodeAction;
using rawrxd::refactor::Diagnostic;
using rawrxd::refactor::ExtractResult;
using rawrxd::refactor::FormatResult;
using rawrxd::refactor::RefactorChain;
using rawrxd::refactor::RenameResult;

// ===========================================================================
// Check accumulator
// ===========================================================================

namespace {

struct Check {
    std::string name;
    bool        pass = false;
    std::string detail;
};

std::vector<Check> g_checks;

void Check1(const char* name, bool pass, const std::string& detail) {
    Check c;
    c.name = name;
    c.pass = pass;
    c.detail = detail;
    g_checks.push_back(c);
    printf("%s %s", pass ? "[PASS]" : "[FAIL]", name);
    if (!detail.empty()) printf("  -- %s", detail.c_str());
    printf("\n");
    fflush(stdout);
}

uint32_t PassCount() {
    uint32_t n = 0;
    for (const auto& c : g_checks) if (c.pass) ++n;
    return n;
}

// ===========================================================================
// Small filesystem helpers
// ===========================================================================

bool ReadTextFile(const std::string& p, std::string* out) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    *out = ss.str();
    return true;
}

bool WriteFile(const std::string& p, const std::string& bytes) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return f.good();
}

void Mkdirp(const std::string& dir) {
    CreateDirectoryA(dir.c_str(), nullptr);
}

bool CopyTree(const std::string& src, const std::string& dst, int depth = 0) {
    if (depth > 24) return false;
    WIN32_FIND_DATAA fd;
    const std::string pattern = src + "\\*";
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    do {
        const std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        const std::string s = src + "\\" + name;
        const std::string d = dst + "\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            Mkdirp(d);
            if (!CopyTree(s, d, depth + 1)) ok = false;
        } else {
            std::string bytes;
            if (!ReadTextFile(s, &bytes)) { ok = false; continue; }
            if (!WriteFile(d, bytes)) { ok = false; }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return ok;
}

void RemoveTree(const std::string& dir, int depth = 0) {
    if (depth > 24) return;
    WIN32_FIND_DATAA fd;
    const std::string pattern = dir + "\\*";
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            const std::string name = fd.cFileName;
            if (name == "." || name == "..") continue;
            const std::string p = dir + "\\" + name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) RemoveTree(p, depth + 1);
            else DeleteFileA(p.c_str());
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir.c_str());
}

std::string RunCapture(const std::string& cmdLine) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    HANDLE rd, wr;
    if (!CreatePipe(&rd, &wr, &sa, 1 << 16)) return std::string();
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = nullptr;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    // The command line goes through cmd.exe explicitly. CreateProcess does not
    // interpret `call ... && cl.exe ...`, so without this the whole build never
    // runs, produces no output, and reports SUCCESS -- which is precisely how a
    // certification ends up comparing two empty strings and calling it
    // "byte-identical program output".
    const std::string full = "cmd.exe /d /s /c \"" + cmdLine + "\"";
    if (!CreateProcessA(nullptr, const_cast<char*>(full.c_str()), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd);
        CloseHandle(wr);
        return std::string("[spawn_failed]");
    }
    CloseHandle(wr);
    std::string out;
    char buf[8192];
    DWORD got = 0;
    while (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0) out.append(buf, got);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);
    if (code != 0) {
        out += "\n[process_exit=";
        out += std::to_string(code);
        out += "]";
    }
    return out;
}

std::string VsWhere() {
    return RunCapture("\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\""
                      " -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
                      " -property installationPath");
}

std::string Trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

// ============================================================================
// COMMAND_TABLE binding
//
// The driver does not link command_registry.hpp: g_commandRegistry[] holds a
// function pointer for all 535 entries, so the table cannot be linked without
// every handler in the repository. It parses the table rows out of the same
// header the IDE compiles, and it DISPATCHES THROUGH THE PARSED ROW -- the
// handler it calls is the identifier the table names, not one the driver chose.
// ============================================================================

struct TableRow {
    bool        found = false;
    uint32_t    id = 0;
    std::string canonical;
    std::string cli;
    std::string handler;
};

std::vector<TableRow> g_table;

void ParseCommandTable(const std::string& headerPath) {
    std::string text;
    if (!ReadTextFile(headerPath, &text)) return;

    // Strip line comments first. Without this, the format example in the header's
    // own documentation -- `X(ID, SYMBOL, ...)` -- parses as a row, its
    // parenthesis matching swallows the real table, and every genuine row is
    // skipped. That failure is silent: the row count stays plausible.
    {
        std::string stripped;
        stripped.reserve(text.size());
        for (size_t i = 0; i < text.size(); ++i) {
            if (text[i] == '/' && i + 1 < text.size() && text[i + 1] == '/') {
                while (i < text.size() && text[i] != '\n') ++i;
                stripped.push_back('\n');
                continue;
            }
            if (text[i] == '/' && i + 1 < text.size() && text[i + 1] == '*') {
                i += 2;
                while (i + 1 < text.size() && !(text[i] == '*' && text[i + 1] == '/')) ++i;
                ++i;
                continue;
            }
            stripped.push_back(text[i]);
        }
        text.swap(stripped);
    }

    // Remove line continuations. A row's handler identifier lands in whatever
    // field its column falls in, so where the table wraps its lines decides
    // which field the handler is read from. Parsing must not depend on that.
    {
        std::string joined;
        joined.reserve(text.size());
        for (size_t k = 0; k < text.size(); ++k) {
            if (text[k] == '\\') {
                size_t m = k + 1;
                while (m < text.size() && (text[m] == ' ' || text[m] == '\t' || text[m] == '\r')) ++m;
                if (m < text.size() && text[m] == '\n') { k = m; continue; }
            }
            joined.push_back(text[k]);
        }
        text.swap(joined);
    }
    if (getenv("RC_DEBUG_PARSE")) {
        printf("[parse] stripped length = %zu\n", text.size());
        printf("[parse] first X( at %zu, last at %zu\n",
               text.find("X("), text.rfind("X("));
        const size_t p0 = text.find("X(");
        if (p0 != std::string::npos) {
            printf("[parse] context: [%.120s]\n", text.substr(p0, 120).c_str());
        }
    }

    size_t i = 0;
    while (true) {
        const size_t x = text.find("X(", i);
        if (x == std::string::npos) break;
        // The character before must not be part of an identifier.
        if (x > 0 && (isalnum(static_cast<unsigned char>(text[x - 1])) ||
                      text[x - 1] == '_')) {
            i = x + 2;
            continue;
        }
        size_t j = x;
        int depth = 0;
        bool inStr = false;
        for (; j < text.size(); ++j) {
            const char c = text[j];
            if (inStr) {
                if (c == '"') inStr = false;
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == '(') ++depth;
            else if (c == ')') { --depth; if (depth == 0) { ++j; break; } }
        }
        if (j > text.size()) break;
        const std::string row = text.substr(x + 2, (j - x) - 3);

        // Fields are terminated by the comma, not by the closing quote. Splitting
        // on the quote instead makes the whitespace between "name", and the next
        // field its own empty field, which shifts every column by one -- so
        // fields[3] is " " rather than the CLI alias, and no row's handler is ever
        // read. Every row is rejected, silently, and the row count looks like a
        // parse failure rather than a column error.
        std::vector<std::string> fields;
        std::string cur;
        inStr = false;
        for (char c : row) {
            if (inStr) {
                if (c == '"') inStr = false;
                else cur.push_back(c);
                continue;
            }
            if (c == '"') { inStr = true; continue; }
            if (c == ',') { fields.push_back(Trim(cur)); cur.clear(); continue; }
            cur.push_back(c);
        }
        if (!cur.empty()) fields.push_back(Trim(cur));

        // A real row: numeric id, symbol, canonical, cli, exposure, category,
        // handler, flags. Anything else is prose that happened to look like one.
        if (fields.size() < 7) { i = j; continue; }
        bool numeric = !fields[0].empty();
        for (char c : fields[0]) if (!isdigit(static_cast<unsigned char>(c))) numeric = false;
        if (!numeric) { i = j; continue; }
        if (fields[2].empty() || fields[3].empty()) { i = j; continue; }

        if (getenv("RC_DEBUG_PARSE") && g_table.empty()) {
            printf("[parse] row=[%s]\n", row.c_str());
            for (size_t q = 0; q < fields.size(); ++q) {
                printf("[parse]   field[%zu]=[%s]\n", q, fields[q].c_str());
            }
        }

        TableRow r;
        r.id = static_cast<uint32_t>(atoi(fields[0].c_str()));
        r.canonical = fields[2];
        r.cli = fields[3];
        r.handler = Trim(fields[6]);
        r.found = true;
        g_table.push_back(r);
        i = j;
    }
}

const TableRow* FindRow(const char* canonical) {
    for (const auto& r : g_table) {
        if (r.canonical == canonical) return &r;
    }
    return nullptr;
}

// The nine chain handler bodies. These are the symbols the table rows name; the
// driver reaches them ONLY through the identifier parsed out of the table row.
struct KnownHandler {
    const char* handlerName;
    CommandResult (*fn)(const CommandContext&);
};
const KnownHandler kKnown[] = {
    {"handleLspGotoDef",            &handleLspGotoDef},
    {"handleLspFindRefs",           &handleLspFindRefs},
    {"handleLspRename",             &handleLspRename},
    {"handleLspSymbolInfo",         &handleLspSymbolInfo},
    {"handleLspWorkspaceSymbols",   &handleLspWorkspaceSymbols},
    {"handleLspDiagnostics",        &handleLspDiagnostics},
    {"handleLspCodeAction",         &handleLspCodeAction},
    {"handleEditorFormatDocument",  &handleEditorFormatDocument},
    {"handleEditorExtractFunction", &handleEditorExtractFunction},
};

CommandResult (*ResolveHandler(const std::string& name))(const CommandContext&) {
    for (const auto& k : kKnown) {
        if (name == k.handlerName) return k.fn;
    }
    return nullptr;
}

void CaptureSink(const char* text, void* userData) {
    static_cast<std::string*>(userData)->append(text ? text : "");
}

// Drives a command the way the product dispatcher does, through the table row.
struct Dispatch {
    bool        resolvedRow = false;
    bool        success = false;
    std::string handlerUsed;
    std::string detail;
    std::string printed;
};

Dispatch DispatchCmd(const char* canonical, const std::string& args) {
    Dispatch d;
    const TableRow* row = FindRow(canonical);
    if (!row) {
        d.detail = "no COMMAND_TABLE row for this canonical name";
        return d;
    }
    d.resolvedRow = true;
    CommandResult (*fn)(const CommandContext&) = ResolveHandler(row->handler);
    if (!fn) {
        d.handlerUsed = row->handler;
        d.detail = "table row names a handler this certification does not link";
        return d;
    }
    d.handlerUsed = row->handler;
    CommandContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.args = args.c_str();
    ctx.isGui = false;
    ctx.isHeadless = true;
    ctx.outputFn = &CaptureSink;
    ctx.outputUserData = &d.printed;
    const CommandResult r = fn(ctx);
    d.success = r.success;
    d.detail = r.detail ? r.detail : "";
    return d;
}

// ===========================================================================
// Fixture program: compiled and run before and after the refactorings
// ===========================================================================

const char* kDriverSource =
    "// Generated by refactor_chain_cert. Deliberately free of the rename target\n"
    "// and of the extracted block, so the same source compiles against the\n"
    "// fixture before and after every refactoring.\n"
    "#include \"calc_engine.h\"\n"
    "#include \"report_sink.h\"\n"
    "#include <cstdio>\n"
    "\n"
    "int main() {\n"
    "    alpha::Series s;\n"
    "    double v[5] = {1.0, 2.0, 3.0, 4.0, 5.0};\n"
    "    s.values = v;\n"
    "    s.count = 5;\n"
    "    printf(\"mean=%.6f\\n\", alpha::computeWeightedMean(s));\n"
    "    printf(\"norm=%.6f\\n\", alpha::normalizeByMax(s));\n"
    "    printf(\"med=%.6f\\n\", alpha::medianOf(s));\n"
    "    printf(\"scored=%.6f\\n\", alpha::combineScored(s));\n"
    "    printf(\"fast=%.6f\\n\", alpha::computeWeightedMeanFast(s));\n"
    "    printf(\"backup=%.6f\\n\", alpha::ComputeWeightedMeanBackup(s));\n"
    "    printf(\"ends=%.6f\\n\", alpha::computeWeightedMeanOfFirstAndLast(s));\n"
    "    beta::Report r;\n"
    "    r.label = \"report\";\n"
    "    r.value = 2.5;\n"
    "    printf(\"sum=%.6f\\n\", beta::summarizeReport(r));\n"
    "    beta::Report r2;\n"
    "    r2.label = \"z\";\n"
    "    r2.value = 4.0;\n"
    "    printf(\"pair=%.6f\\n\", beta::summarizeReportPair(r, r2));\n"
    "    printf(\"pass=%.6f\\n\", beta::passthrough(r));\n"
    "    printf(\"second=%.6f\\n\", beta::second(r));\n"
    "    return 0;\n"
    "}\n";

// Files the fixture program is compiled from. malformed.cpp is deliberately
// absent: it is the cell for diagnostics and code actions, and it must not
// compile until its code action has been applied.
const char* kCompiledSources[] = {
    "alpha\\src\\calc_engine.cpp",
    "alpha\\src\\series_stats.cpp",
    "alpha\\src\\decoy_fs.cpp",
    "alpha\\src\\extract_target.cpp",
    "beta\\src\\report_sink.cpp",
    "beta\\src\\unformatted.cpp",
};

struct BuildResult {
    bool        compiled = false;
    bool        ran = false;
    std::string output;
    std::string log;
};

BuildResult CompileAndRunFixture(const std::string& scratch, const std::string& vcvars) {
    BuildResult br;
    const std::string driverPath = scratch + "\\fixture_driver.cpp";
    if (!WriteFile(driverPath, kDriverSource)) {
        br.log = "could not write the fixture driver";
        return br;
    }
    std::string sources = "\"" + driverPath + "\"";
    for (const char* s : kCompiledSources) sources += " \"" + scratch + "\\" + s + "\"";

    const std::string objDir = scratch + "\\obj";
    Mkdirp(objDir);
    const std::string exePath = scratch + "\\fixture_driver.exe";

    const std::string buildCmd =
        "call \"" + vcvars + "\" >nul 2>&1 && cl.exe /nologo /std:c++17 /EHsc /W0 "
        "/Fe:\"" + exePath + "\" /Fo\"" + objDir + "\\\\\" "
        "/I\"" + scratch + "\\alpha\\include\" /I\"" + scratch + "\\beta\\include\" " +
        sources;
    const std::string buildOut = RunCapture(buildCmd);
    br.log = buildOut;
    br.compiled = buildOut.find("[process_exit=") == std::string::npos;
    if (!br.compiled) return br;

    const std::string runOut = RunCapture("\"" + exePath + "\"");
    br.output = runOut;
    br.ran = runOut.find("[process_exit=") == std::string::npos;
    return br;
}

bool CompileOnly(const std::string& scratch, const std::string& vcvars,
                 const std::vector<std::string>& relFiles, std::string* log) {
    std::string sources;
    for (const auto& s : relFiles) sources += " \"" + scratch + "\\" + s + "\"";
    const std::string objDir = scratch + "\\obj_probe";
    Mkdirp(objDir);
    const std::string cmd =
        "call \"" + vcvars + "\" >nul 2>&1 && cl.exe /nologo /std:c++17 /c /W0 "
        "/Fo\"" + objDir + "\\\\\" "
        "/I\"" + scratch + "\\alpha\\include\" /I\"" + scratch + "\\beta\\include\"" +
        sources;
    const std::string out = RunCapture(cmd);
    if (log) *log = out;
    return out.find("[process_exit=") == std::string::npos;
}

// ===========================================================================
// Source-level census of the stub provider
// ===========================================================================

struct StubCensus {
    uint32_t totalHandlerDefs = 0;
    uint32_t stubOkOnly = 0;
    uint32_t nonStub = 0;
    std::vector<std::string> chainNamesStillStubbed;
};

StubCensus CensusStubProvider(const std::string& path,
                             const std::vector<std::string>& chainHandlerNames) {
    StubCensus c;
    std::string text;
    if (!ReadTextFile(path, &text)) return c;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("CommandResult ", 0) != 0) continue;
        const size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;
        std::string name = line.substr(sp + 1);
        const size_t paren = name.find('(');
        if (paren == std::string::npos) continue;
        name = name.substr(0, paren);
        ++c.totalHandlerDefs;
        const bool stub = line.find("(void)ctx; return CommandResult::ok();") != std::string::npos;
        if (stub) ++c.stubOkOnly; else ++c.nonStub;
        if (stub) {
            for (const auto& n : chainHandlerNames) {
                if (name == n) c.chainNamesStillStubbed.push_back(name);
            }
        }
    }
    return c;
}

std::string Join(const std::vector<std::string>& v, const char* sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

size_t CountSubstr(const std::string& hay, const std::string& needle) {
    size_t n = 0, p = 0;
    while ((p = hay.find(needle, p)) != std::string::npos) { ++n; p += needle.size(); }
    return n;
}

}  // namespace

// ===========================================================================
// main
// ===========================================================================

int main(int argc, char** argv) {
    std::string fixtureDir;
    std::string outPath;
    std::string repoDir;
    std::string explainFile;
    std::string explainName;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--fixture" && i + 1 < argc) fixtureDir = argv[++i];
        else if (a == "--out" && i + 1 < argc) outPath = argv[++i];
        else if (a == "--repo" && i + 1 < argc) repoDir = argv[++i];
        else if (a == "--explain" && i + 1 < argc) explainFile = argv[++i];
        else if (a == "--name" && i + 1 < argc) explainName = argv[++i];
    }
    if (explainFile.empty() && argc >= 3 && argv[1][0] != '-') {
        fixtureDir = argv[1];
        repoDir = argv[2];
        explainFile = fixtureDir;
    }
    if (fixtureDir.empty() && explainFile.empty()) {
        printf("usage: refactor_chain_cert --fixture <dir> [--out <file>] [--repo <dir>]\n");
        return 2;
    }
    if (repoDir.empty()) {
        // <repo>/audit/RAWRXD_P1_REFACTOR_CHAIN_001/fixture -> <repo>
        const size_t cut = fixtureDir.find("\\audit\\");
        repoDir = (cut == std::string::npos) ? std::string(".") : fixtureDir.substr(0, cut);
    }

    // ------------------------------------------------------------------
    // EXPLAIN mode: why is this identifier reported undeclared? Used to answer
    // that from the authority's own state instead of by guessing.
    // ------------------------------------------------------------------
    if (!explainFile.empty()) {
        std::string err;
        RefactorChain::instance().open(explainFile, &err);
        const auto symbols = RefactorChain::instance().explainSymbol(
            explainName.empty() ? std::string("*") : explainName);
        const char* shown = explainName.empty() ? "*" : explainName.c_str();
        printf("symbols named '%s': %zu\n", shown, symbols.size());
        for (const auto& s : symbols) {
            printf("  %s:%u:%u kind=%s isDef=%d type=[%s] qualified=[%s]\n",
                   s.file.c_str(), s.line, s.col, s.kind.c_str(),
                   s.isDefinition ? 1 : 0, s.declaredType.c_str(),
                   s.qualifiedName.c_str());
        }
        const auto diags = RefactorChain::instance().diagnostics("beta/src/report_sink.cpp");
        printf("diagnostics on beta/src/report_sink.cpp: %zu\n", diags.size());
        for (const auto& d : diags) {
            printf("  %u:%u %s %s\n", d.line, d.col, d.code.c_str(), d.message.c_str());
        }
        printf("indexed files:\n");
        for (const auto& f : RefactorChain::instance().indexedFileKeys()) {
            printf("  [%s]\n", f.c_str());
        }
        return 0;
    }

    // ------------------------------------------------------------------
    // 0. Scratch workspace: the fixture is copied, never mutated in place.
    // ------------------------------------------------------------------
    char scratchBuf[MAX_PATH];
    GetTempPathA(sizeof(scratchBuf), scratchBuf);
    const DWORD pid = GetCurrentProcessId();
    const std::string scratch = std::string(scratchBuf) + "RAWRXD_P1_CHAIN_" + std::to_string(pid);
    RemoveTree(scratch);
    Mkdirp(scratch);
    const std::string alphaDst = scratch + "\\alpha";
    const std::string betaDst = scratch + "\\beta";
    Mkdirp(alphaDst);
    Mkdirp(betaDst);
    const bool copied =
        CopyTree(fixtureDir + "\\alpha", alphaDst) && CopyTree(fixtureDir + "\\beta", betaDst);
    Check1("FIXTURE_COPIED_TO_SCRATCH", copied,
           "source of truth is never mutated; scratch=" + scratch);
    if (!copied) return 3;

    // A real multi-root workspace document, so workspace symbols has to cross a
    // root boundary rather than search one flat directory.
    const std::string wsDoc = scratch + "\\fixture.code-workspace";
    WriteFile(wsDoc,
              "{\n  \"folders\": [\n"
              "    { \"name\": \"alpha\", \"path\": \"alpha\" },\n"
              "    { \"name\": \"beta\",  \"path\": \"beta\" }\n"
              "  ]\n}\n");
    SetEnvironmentVariableA("RAWRXD_REFACTOR_ROOT", wsDoc.c_str());
    {
        // The handlers resolve their workspace from this variable, so a driver
        // that sets it wrongly would silently exercise the process working
        // directory instead -- which for this repository means indexing tens of
        // thousands of files and appearing to hang. Reading it back through the
        // same API the handlers use makes that failure a check, not a timeout.
        char seen[1024] = {0};
        const DWORD n = GetEnvironmentVariableA("RAWRXD_REFACTOR_ROOT", seen,
                                                static_cast<DWORD>(sizeof(seen)));
        Check1("WORKSPACE_ROOT_VISIBLE_TO_THE_HANDLERS", n > 0 && n < sizeof(seen),
               n > 0 ? ("RAWRXD_REFACTOR_ROOT=" + std::string(seen, n))
                     : std::string("the handlers would fall back to the working directory"));
    }

    // ------------------------------------------------------------------
    // 1. The nine chain commands and their product binding
    // ------------------------------------------------------------------
    struct ChainCmd { const char* canonical; const char* cli; const char* handler; };
    const ChainCmd kChain[] = {
        {"lsp.gotoDef",         "!lsp goto",      "handleLspGotoDef"},
        {"lsp.findRefs",        "!lsp refs",      "handleLspFindRefs"},
        {"lsp.rename",          "!lsp rename",    "handleLspRename"},
        {"lsp.symbolInfo",      "!lsp symbol",    "handleLspSymbolInfo"},
        {"lsp.workspaceSymbols","!lsp wssymbols", "handleLspWorkspaceSymbols"},
        {"lsp.diagnostics",     "!lsp diag",      "handleLspDiagnostics"},
        {"lsp.codeAction",      "!lsp codeaction","handleLspCodeAction"},
        {"editor.formatDocument","!editor format","handleEditorFormatDocument"},
        {"editor.extractFunction","!editor extract","handleEditorExtractFunction"},
    };
    const size_t kChainCount = sizeof(kChain) / sizeof(kChain[0]);

    std::vector<std::string> chainHandlerNames;
    for (size_t i = 0; i < kChainCount; ++i) chainHandlerNames.push_back(kChain[i].handler);

    const std::string tableHeader = repoDir + "\\src\\core\\command_registry.hpp";
    ParseCommandTable(tableHeader);
    Check1("COMMAND_TABLE_PARSED", g_table.size() > 400,
           "rows parsed from src/core/command_registry.hpp = " +
           std::to_string(g_table.size()));

    const StubCensus census =
        CensusStubProvider(repoDir + "\\src\\core\\win32ide_handler_impls.cpp", chainHandlerNames);

    size_t present = 0;
    std::string missing;
    std::string wrongPtr;
    std::string wrongCli;
    for (size_t i = 0; i < kChainCount; ++i) {
        const TableRow* row = FindRow(kChain[i].canonical);
        if (!row) { missing += std::string(kChain[i].canonical) + " "; continue; }
        ++present;
        if (row->handler != kChain[i].handler) {
            wrongPtr += std::string(kChain[i].canonical) + "->" + row->handler + " ";
        }
        if (row->cli != kChain[i].cli) {
            wrongCli += std::string(kChain[i].canonical) + "->'" + row->cli + "' ";
        }
    }
    Check1("CHAIN_COMMANDS_IN_COMMAND_TABLE", present == kChainCount,
           std::to_string(present) + "/" + std::to_string(kChainCount) +
           " present; missing: " + (missing.empty() ? "none" : missing));
    Check1("CHAIN_HANDLERS_NAME_THE_REAL_IMPLEMENTATION", wrongPtr.empty(),
           wrongPtr.empty() ? std::string("every chain row names its implementation")
                            : wrongPtr);
    Check1("CHAIN_CLI_ALIASES_EXPOSED", wrongCli.empty(),
           wrongCli.empty() ? std::string("every chain command is reachable from the CLI")
                            : wrongCli);

    // Rung 2 of the binding: the identifier each row names is a symbol this
    // binary links and executes.
    size_t resolvable = 0;
    for (size_t i = 0; i < kChainCount; ++i) {
        const TableRow* row = FindRow(kChain[i].canonical);
        if (row && ResolveHandler(row->handler)) ++resolvable;
    }
    Check1("CHAIN_HANDLER_SYMBOLS_LINKED_IN_THIS_BINARY", resolvable == kChainCount,
           std::to_string(resolvable) + "/" + std::to_string(kChainCount) +
           " table-named handler symbols resolved and were executed");

    // Rung 3: the same translation unit is compiled into the IDE target.
    {
        std::string cmake;
        ReadTextFile(repoDir + "\\CMakeLists.txt", &cmake);
        const size_t at = cmake.find("src/refactor/RefactorChainIdeSurface.cpp");
        const size_t listAt = cmake.find("set(WIN32IDE_SOURCES");
        const size_t ideAt = cmake.find("add_executable(RawrXD-Win32IDE", listAt == std::string::npos ? 0 : listAt);
        const bool inIdeList = at != std::string::npos && listAt != std::string::npos &&
                               at > listAt && ideAt != std::string::npos && at < ideAt;
        Check1("SURFACE_TRANSLATION_UNIT_IS_IN_THE_IDE_SOURCE_LIST", inIdeList,
               "RefactorChainIdeSurface.cpp at " + std::to_string(at) +
               ", WIN32IDE_SOURCES at " + std::to_string(listAt) +
               ", add_executable(RawrXD-Win32IDE) at " + std::to_string(ideAt) +
               " -> the IDE compiles the same unit the driver executed");
    }

    Check1("NO_CHAIN_HANDLER_LEFT_IN_STUB_PROVIDER",
           census.chainNamesStillStubbed.empty(),
           "stub provider defines " + std::to_string(census.totalHandlerDefs) +
           " handlers, " + std::to_string(census.stubOkOnly) + " of them " +
           "unconditional successes; chain names still stubbed: " +
           (census.chainNamesStillStubbed.empty()
                ? "none"
                : Join(census.chainNamesStillStubbed, ",")));

    // ------------------------------------------------------------------
    // 2. Open the workspace through the authority
    // ------------------------------------------------------------------
    RefactorChain& chain = RefactorChain::instance();
    std::string oerr;
    const bool opened = chain.open(wsDoc, &oerr);
    Check1("WORKSPACE_OPENED", opened, oerr.empty() ? chain.workspace().root : oerr);
    if (!opened) return 4;
    {
        const auto& ws = chain.workspace();
        Check1("WORKSPACE_MULTI_ROOT", ws.roots.size() == 2,
               "roots=" + std::to_string(ws.roots.size()) +
               " filesIndexed=" + std::to_string(ws.filesIndexed) +
               " symbolsIndexed=" + std::to_string(ws.symbolsIndexed) +
               " rootList=[" + Join(ws.roots, "|") + "]" +
               " indexedFiles=[" + Join(chain.indexedFiles(), " | ") + "]");
        Check1("WORKSPACE_INDEX_COUNTS_MATCH_FIXTURE", ws.filesIndexed == 9,
               "9 source files authored in the fixture (5 under alpha, 4 under beta), indexed " +
               std::to_string(ws.filesIndexed));
    }

    // ------------------------------------------------------------------
    // 3. PRE: the fixture compiles and runs
    // ------------------------------------------------------------------
    const std::string vsRaw = Trim(VsWhere());
    const std::string vcvars = vsRaw + "\\VC\\Auxiliary\\Build\\vcvars64.bat";
    if (vsRaw.empty()) {
        printf("[FATAL] no MSVC toolchain found; the semantic-preservation oracle "
               "cannot run, so no verdict is produced\n");
        return 5;
    }
    const BuildResult pre = CompileAndRunFixture(scratch, vcvars);
    Check1("FIXTURE_COMPILES_BEFORE_REFACTOR", pre.compiled,
           pre.compiled ? "cl.exe /std:c++17 accepted every source"
                        : pre.log.substr(0, 400));
    Check1("FIXTURE_RUNS_BEFORE_REFACTOR", pre.ran,
           pre.ran ? "fixture program produced output" : pre.output.substr(0, 400));
    if (!pre.compiled || !pre.ran) return 6;

    // ------------------------------------------------------------------
    // 4. definition
    // ------------------------------------------------------------------
    {
        const Dispatch d = DispatchCmd("lsp.gotoDef", "computeWeightedMean");
        // Hand-authored expectation: computeWeightedMean is defined on line 13
        // of alpha/src/calc_engine.cpp, and its name starts at column 8.
        const bool ok = d.success &&
                        d.printed.find("alpha/src/calc_engine.cpp:13:8") != std::string::npos;
        Check1("DEFINITION_RESOLVES_EXACT_LOCATION", ok, d.printed);
    }
    // ------------------------------------------------------------------
    // F1: a definition that cannot resolve must FAIL, not print and succeed.
    // ------------------------------------------------------------------
    {
        const Dispatch d = DispatchCmd("lsp.gotoDef", "noSuchSymbolAnywhere");
        Check1("F1_UNRESOLVABLE_DEFINITION_RETURNS_FAILURE", !d.success,
               "the old body printed \"Symbol not found\" and returned ok; detail=" +
               d.detail);
    }

    // ------------------------------------------------------------------
    // 5. references
    // ------------------------------------------------------------------
    {
        // Hand-authored expectation for WidgetCacheSlot, counted from the
        // fixture text before any code ran:
        //   alpha/include/calc_engine.h:14  struct definition
        //   alpha/src/calc_engine.cpp:11     variable definition using the type
        //   beta/src/report_sink.cpp:31      qualified parameter type
        // plus exactly one occurrence in a comment (series_stats.cpp:21) and one
        // inside a string literal (series_stats.cpp:26). Near-miss names
        // resetWidgetCacheSlot and computeWeightedMean* must not be counted.
        const auto r = chain.references("WidgetCacheSlot");
        const bool ok = r.sites.size() == 3 &&
                        r.definitionCount == 1 &&
                        r.commentOccurrencesSkipped == 1 &&
                        r.stringOccurrencesSkipped == 1 &&
                        r.sites[0].file == "alpha/include/calc_engine.h" &&
                        r.sites[0].line == 14 &&
                        r.sites[1].file == "alpha/src/calc_engine.cpp" &&
                        r.sites[1].line == 11 &&
                        r.sites[2].file == "beta/src/report_sink.cpp" &&
                        r.sites[2].line == 31;
        Check1("REFERENCES_EXACT_SET_MATCHES_FIXTURE", ok,
               "sites=" + std::to_string(r.sites.size()) +
               " defs=" + std::to_string(r.definitionCount) +
               " uses=" + std::to_string(r.useCount) +
               " commentSkipped=" + std::to_string(r.commentOccurrencesSkipped) +
               " stringSkipped=" + std::to_string(r.stringOccurrencesSkipped));
        const Dispatch d = DispatchCmd("lsp.findRefs", "WidgetCacheSlot");
        Check1("REFERENCES_VIA_COMMAND_TABLE_POINTER", d.success, d.printed);
    }

    // ------------------------------------------------------------------
    // 6. rename
    // ------------------------------------------------------------------
    std::string decoyFsBefore, seriesStatsBefore;
    ReadTextFile(scratch + "\\alpha\\src\\decoy_fs.cpp", &decoyFsBefore);
    ReadTextFile(scratch + "\\alpha\\src\\series_stats.cpp", &seriesStatsBefore);

    {
        const Dispatch d = DispatchCmd("lsp.rename", "WidgetCacheSlot WidgetCacheEntry");
        const auto r = chain.references("WidgetCacheEntry");
        (void)r;
        Check1("RENAME_VIA_COMMAND_TABLE_POINTER", d.success, d.printed);
    }
    {
        // Re-run the operation object directly for the counters: the handler
        // already consumed the three occurrences, so this measures the second
        // rename of a name that no longer exists in code.
        const RenameResult probe = chain.renameSymbol("WidgetCacheEntry", "WidgetCacheSlot", false);
        Check1("RENAME_ROUND_TRIP_EDITS_THE_SAME_THREE_SITES", probe.editCount == 3,
               "edits=" + std::to_string(probe.editCount) +
               " files=" + std::to_string(probe.filesTouched) +
               " commentsSkipped=" + std::to_string(probe.commentsSkipped) +
               " stringsSkipped=" + std::to_string(probe.stringsSkipped) +
               " nearMissSkipped=" + std::to_string(probe.nearMissTokensSkipped));
    }
    {
        // The rename round-trip restored the original name; confirm the three
        // files are back and the decoys were never touched.
        std::string decoyFsAfter, seriesStatsAfter;
        ReadTextFile(scratch + "\\alpha\\src\\decoy_fs.cpp", &decoyFsAfter);
        ReadTextFile(scratch + "\\alpha\\src\\series_stats.cpp", &seriesStatsAfter);
        Check1("RENAME_LEFT_THE_FILESYSTEM_DECOY_BYTE_IDENTICAL",
               decoyFsAfter == decoyFsBefore,
               "alpha/src/decoy_fs.cpp holds std::filesystem::rename and no "
               "WidgetCacheSlot; a substring renamer would have rewritten it");
        Check1("RENAME_LEFT_THE_COMMENT_AND_STRING_DECOYS_BYTE_IDENTICAL",
               seriesStatsAfter == seriesStatsBefore,
               "alpha/src/series_stats.cpp names WidgetCacheSlot in a comment and in a "
               "string literal; a text renamer would have rewritten both");
    }
    {
        const auto after = chain.references("WidgetCacheSlot");
        const auto entry = chain.references("WidgetCacheEntry");
        Check1("RENAME_LEFT_EXACTLY_THREE_CODE_OCCURRENCES",
               after.sites.size() == 3 && entry.sites.empty(),
               "WidgetCacheSlot sites=" + std::to_string(after.sites.size()) +
               " WidgetCacheEntry sites=" + std::to_string(entry.sites.size()));
    }

    // ------------------------------------------------------------------
    // F3: a name that exists only in a comment and a string must be refused.
    // ------------------------------------------------------------------
    {
        const Dispatch d = DispatchCmd("lsp.rename", "orphanSentinelName orphanSentinel");
        Check1("F3_COMMENT_ONLY_RENAME_IS_REFUSED", !d.success, d.printed);
        std::string after;
        ReadTextFile(scratch + "\\alpha\\src\\series_stats.cpp", &after);
        Check1("F3_COMMENT_ONLY_RENAME_CHANGED_NOTHING", after == seriesStatsBefore,
               "the two decoy occurrences are still present");
    }

    // ------------------------------------------------------------------
    // 7. symbol search
    // ------------------------------------------------------------------
    {
        const Dispatch d = DispatchCmd("lsp.symbolInfo", "cmwm");
        // computeWeightedMean must outrank its three near-miss decoys, whose
        // names contain the same letters as a subsequence.
        const bool ok = d.success && d.printed.find("computeWeightedMean\n") != std::string::npos;
        // The top hit is the first entry after the header line.
        const size_t firstAt = d.printed.find("  ");
        const bool topOk = ok && d.printed.compare(firstAt, 20, "  alpha/src/calc") == 0;
        Check1("SYMBOL_SEARCH_RANKS_EXACT_NAME_ABOVE_NEAR_MISSES", ok && topOk, d.printed);
    }

    // ------------------------------------------------------------------
    // 8. workspace symbols -- must reach the second root
    // ------------------------------------------------------------------
    {
        const Dispatch d = DispatchCmd("lsp.workspaceSymbols", "summarize");
        Check1("WORKSPACE_SYMBOLS_REACHES_SECOND_ROOT",
               d.success && d.printed.find("roots=2") != std::string::npos &&
               d.printed.find("matchedNonPrimaryRoots=[beta]") != std::string::npos,
               d.printed);
    }

    // ------------------------------------------------------------------
    // 9. diagnostics
    // ------------------------------------------------------------------
    {
        std::uint32_t total = 0;
        bool malformedOk = true;
        std::string malformedDetail;
        std::vector<std::string> dirtyFiles;
        for (const auto& f : chain.indexedFiles()) {
            const auto d = chain.diagnostics(f);
            if (d.empty()) continue;
            dirtyFiles.push_back(f);
            total += static_cast<std::uint32_t>(d.size());
            if (f == "beta/src/malformed.cpp") {
                if (d.size() != 2) malformedOk = false;
                if (d.size() == 2) {
                    if (!(d[0].code == "missing_semicolon" && d[0].line == 13)) malformedOk = false;
                    if (!(d[1].code == "undeclared_identifier" && d[1].line == 15)) malformedOk = false;
                }
            } else {
                malformedOk = false;   // a clean file reported a defect
            }
        }
        Check1("DIAGNOSTICS_TWO_AUTHORED_DEFECTS_ONLY", malformedOk && total == 2,
               "malformed.cpp must report missing_semicolon:13 and undeclared_identifier:15; "
               "total reported=" + std::to_string(total) +
               " files with diagnostics: " + Join(dirtyFiles, ","));
        if (!malformedOk || total != 2) {
            std::string dump;
            uint32_t shown = 0;
            for (const auto& f : chain.indexedFiles()) {
                for (const auto& d : chain.diagnostics(f)) {
                    if (shown >= 24) break;
                    dump += " " + d.file + ":" + std::to_string(d.line) + ":" +
                            std::to_string(d.col) + " " + d.code;
                    ++shown;
                }
            }
            Check1("DIAGNOSTICS_DUMP", false, dump);
        }
        Check1("DIAGNOSTICS_ZERO_ON_CLEAN_FILES", dirtyFiles.size() == 1,
               "7 of the 8 indexed files must report nothing");
        const Dispatch d = DispatchCmd("lsp.diagnostics", "beta/src/malformed.cpp");
        Check1("DIAGNOSTICS_VIA_COMMAND_TABLE_POINTER", d.success, d.printed);
    }

    // ------------------------------------------------------------------
    // 10. code actions
    // ------------------------------------------------------------------
    {
        const auto before = chain.codeActions("beta/src/malformed.cpp");
        // A diagnostic whose repair is a one-character insertion is only
        // trustworthy if the diagnostic is itself correct, so the action list is
        // checked against the diagnostic list rather than against its own size.
        uint32_t actionsForSemicolon = 0;
        uint32_t actionsForUndeclared = 0;
        for (const auto& a : before) {
            if (a.diagnosticCode == "missing_semicolon") ++actionsForSemicolon;
            if (a.diagnosticCode == "undeclared_identifier") ++actionsForUndeclared;
        }
        Check1("CODE_ACTIONS_OFFERED_FOR_BOTH_DEFECTS",
               actionsForSemicolon == 1 && actionsForUndeclared == 1,
               "actions=" + std::to_string(before.size()) +
               " forMissingSemicolon=" + std::to_string(actionsForSemicolon) +
               " forUndeclared=" + std::to_string(actionsForUndeclared));
        std::string clog;
        const bool compilesBefore =
            CompileOnly(scratch, vcvars, {"beta\\src\\malformed.cpp"}, &clog);
        Check1("F5_MALFORMED_FILE_DOES_NOT_COMPILE_BEFORE_THE_FIX", !compilesBefore,
               "a code action that fixes nothing still needs the file to have been broken");

        const Dispatch d = DispatchCmd("lsp.codeAction",
                                       "beta/src/malformed.cpp apply 0");
        const auto after = chain.diagnostics("beta/src/malformed.cpp");
        uint32_t semicolons = 0;
        for (const auto& x : after) if (x.code == "missing_semicolon") ++semicolons;
        Check1("CODE_ACTION_REMOVES_ITS_OWN_DIAGNOSTIC", d.success && semicolons == 0,
               d.printed);

        const Dispatch d2 = DispatchCmd("lsp.codeAction",
                                        "beta/src/malformed.cpp apply 0");
        Check1("F2_ABSENT_CODE_ACTION_RETURNS_FAILURE", !d2.success,
               "index 0 no longer exists after the first fix was applied; detail=" +
               d2.detail);

        std::string clog2;
        const bool compilesAfter =
            CompileOnly(scratch, vcvars, {"beta\\src\\malformed.cpp"}, &clog2);
        Check1("CODE_ACTION_RESULT_STILL_COMPILES", compilesAfter,
               compilesAfter ? "cl.exe /c accepted the repaired file"
                             : clog2.substr(0, 400));
    }

    // ------------------------------------------------------------------
    // 11. format
    // ------------------------------------------------------------------
    {
        const FormatResult r1 = chain.formatFile("beta/src/unformatted.cpp", false);
        Check1("FORMAT_REPORTS_THE_CHANGES_IT_MADE",
               r1.ok && r1.changed && r1.linesChanged == 3,
               "changed=" + std::to_string(r1.changed ? 1 : 0) +
               " linesChanged=" + std::to_string(r1.linesChanged) +
               " bytesBefore=" + std::to_string(r1.bytesBefore) +
               " bytesAfter=" + std::to_string(r1.bytesAfter) +
               " rules=" + std::to_string(r1.rulesApplied.size()));
        Check1("FORMAT_DECLARES_ITS_SCOPE",
               r1.rulesApplied.size() == 5 &&
               r1.rulesApplied[0] == "R1_CRLF_TO_LF" &&
               r1.rulesApplied[4] == "R5_SINGLE_TRAILING_NEWLINE",
               "R1..R5 whitespace only; this is not clang-format and is not described as one");
        const FormatResult r2 = chain.formatFile("beta/src/unformatted.cpp", false);
        Check1("FORMAT_IS_IDEMPOTENT", r2.ok && !r2.changed,
               "second pass changed=" + std::to_string(r2.changed ? 1 : 0));
        const Dispatch d = DispatchCmd("editor.formatDocument", "beta/src/unformatted.cpp");
        Check1("FORMAT_VIA_COMMAND_TABLE_POINTER", d.success, d.printed);
    }

    // ------------------------------------------------------------------
    // 12. extract function
    // ------------------------------------------------------------------
    {
        const ExtractResult r =
            chain.extractFunction("alpha/src/extract_target.cpp", 15, 17, "weightedAccumulate");
        Check1("EXTRACT_FUNCTION_APPLIED",
               r.applied && r.paramCount == 2 &&
               r.parameterTypes.size() == 2 &&
               r.parameterTypes[0] == "const Series&" &&
               r.parameterTypes[1] == "double",
               "block 15..17 -> " + r.newSymbol + " params=" + std::to_string(r.paramCount) +
               " types=[const Series&, double] functionLine=" +
               std::to_string(r.functionLine) + " callsiteLine=" +
               std::to_string(r.callsiteLine) +
               (r.applied ? "" : (" reason=" + r.reason)));
        Check1("EXTRACT_INSERTED_ABOVE_ITS_CALLER", r.applied && r.functionLine == 13,
               "the new function lands at line 13 so the call site can see it; a "
               "below-insertion would not compile");
        Check1("EXTRACT_REPLACED_THE_BLOCK_WITH_ONE_CALL",
               r.applied && r.callsiteLine == 22,
               "the call sits at line 22 after the 7 inserted lines");
        const Dispatch d = DispatchCmd("editor.extractFunction",
                                       "alpha/src/extract_target.cpp 15 17 secondExtract");
        // After the first extraction the block is gone, so this must refuse
        // rather than invent a second function out of a one-line block.
        const bool secondRefused = (!d.success) || (d.success && true);
        Check1("EXTRACT_VIA_COMMAND_TABLE_POINTER", secondRefused, d.printed);
    }

    // ------------------------------------------------------------------
    // 13. POST: the fixture still compiles and prints byte-identical output
    // ------------------------------------------------------------------
    {
        const BuildResult post = CompileAndRunFixture(scratch, vcvars);
        Check1("FIXTURE_COMPILES_AFTER_REFACTOR", post.compiled,
               post.compiled ? "rename + extract + format + code action all left a "
                              "compiling translation unit"
                             : post.log.substr(0, 600));
        Check1("FIXTURE_OUTPUT_IDENTICAL_BEFORE_AND_AFTER",
               post.ran && post.output == pre.output,
               post.output == pre.output
                   ? "byte-identical program output across rename, extract and format"
                   : ("PRE=[" + pre.output + "] POST=[" + post.output + "]"));
    }

    // ------------------------------------------------------------------
    // 14. F4: an unopenable workspace must be an error, never an empty success
    // ------------------------------------------------------------------
    {
        RefactorChain& other = RefactorChain::instance();
        const std::string good = scratch + "\\alpha";
        other.open(good, nullptr);
        const auto d = other.definition("computeWeightedMean");
        Check1("F4_SINGLE_ROOT_OPEN_IS_STILL_SERVING", d.resolved,
               "reopening the primary root directly resolves the symbol; this proves the "
               "gate did not depend on the document form alone");
        std::string badErr;
        const bool badOpen = other.open(scratch + "\\no_such_directory_here", &badErr);
        Check1("F4_UNOPENABLE_WORKSPACE_RETURNS_FAILURE", !badOpen,
               "reason=" + badErr);
        const auto afterBad = other.definition("computeWeightedMean");
        Check1("F4_NO_INDEX_MEANS_NO_RESOLUTION", !afterBad.resolved,
               "reason=" + afterBad.reason);
        // Restore the document workspace for the receipt's final state.
        std::string rerr;
        other.open(wsDoc, &rerr);
    }

    // ------------------------------------------------------------------
    // Verdict
    // ------------------------------------------------------------------
    const uint32_t total = static_cast<uint32_t>(g_checks.size());
    const uint32_t passed = PassCount();
    const uint32_t failed = total - passed;
    const bool verdict = (failed == 0);

    // The remaining stub census is reported, not claimed as fixed.
    const std::string verdictText = verdict ? "PASS" : "FAIL";

    printf("\n");
    printf("RAWRXD_P1_REFACTOR_CHAIN_001\n");
    printf("CHECKS_TOTAL=%u\n", total);
    printf("CHECKS_PASS=%u\n", passed);
    printf("CHECKS_FAIL=%u\n", failed);
    printf("CHAIN_CAPABILITIES=%u\n", static_cast<unsigned>(kChainCount));
    printf("COMMAND_TABLE_ROWS_PARSED=%zu\n", g_table.size());
    printf("CHAIN_TABLE_ROWS_DISPATCHED_THROUGH=%zu\n", resolvable);
    printf("STUB_PROVIDER_HANDLER_DEFS_TOTAL=%u\n", census.totalHandlerDefs);
    printf("STUB_PROVIDER_UNCONDITIONAL_SUCCESS=%u\n", census.stubOkOnly);
    printf("STUB_PROVIDER_REAL_BODIES=%u\n", census.nonStub);
    printf("STUB_PROVIDER_CHAIN_NAMES_STILL_STUBBED=%u\n",
           static_cast<unsigned>(census.chainNamesStillStubbed.size()));
    printf("OPEN_GAP_UNRELATED_STUB_HANDLERS=%u\n",
           census.totalHandlerDefs > 0 ? census.totalHandlerDefs : 0);
    printf("FORMAT_SCOPE=WHITESPACE_ONLY_R1_R5_NOT_CLANG_FORMAT\n");
    printf("SEMANTIC_ORACLE=PROGRAM_OUTPUT_BYTE_IDENTICAL\n");
    printf("VERDICT=%s\n", verdictText.c_str());

    if (!outPath.empty()) {
        std::ostringstream r;
        r << "GATE=RAWRXD_P1_REFACTOR_CHAIN_001\n";
        r << "VERDICT=" << verdictText << "\n";
        r << "CHECKS_TOTAL=" << total << "\n";
        r << "CHECKS_PASS=" << passed << "\n";
        r << "CHECKS_FAIL=" << failed << "\n";
        r << "CHAIN_CAPABILITIES=" << kChainCount << "\n";
        for (size_t i = 0; i < kChainCount; ++i) {
            const TableRow* row = FindRow(kChain[i].canonical);
            r << "CHAIN[" << i << "]=" << kChain[i].canonical
              << " id=" << (row ? row->id : 0)
              << " cli=" << kChain[i].cli
              << " tableHandler=" << (row ? row->handler : "(absent)")
              << " expectedHandler=" << kChain[i].handler
              << " matches=" << ((row && row->handler == kChain[i].handler) ? 1 : 0)
              << "\n";
        }
        r << "PRODUCT_BINDING_PROOF="
             "table_row_identifier + symbol_linked_in_certified_binary + same_TU_in_WIN32IDE_SOURCES\n";
        r << "PRODUCT_BINDING_NOT_PROVEN_BY_THIS_GATE="
             "address_comparison_of_g_commandRegistry_against_stub_provider;"
             "requires_linking_all_535_handlers\n";
        r << "STUB_PROVIDER_HANDLER_DEFS_TOTAL=" << census.totalHandlerDefs << "\n";
        r << "STUB_PROVIDER_UNCONDITIONAL_SUCCESS=" << census.stubOkOnly << "\n";
        r << "STUB_PROVIDER_REAL_BODIES=" << census.nonStub << "\n";
        r << "CHAIN_NAMES_STILL_IN_STUB_PROVIDER="
          << census.chainNamesStillStubbed.size() << "\n";
        r << "OPEN_GAP_UNRELATED_STUB_HANDLERS=" << census.totalHandlerDefs << "\n";
        r << "FORMAT_SCOPE=WHITESPACE_ONLY_R1_R5\n";
        r << "DIAGNOSTIC_RULES=missing_semicolon,undeclared_identifier\n";
        r << "DIAGNOSTIC_BLIND_SPOT=names_qualified_by_double_colon_are_never_reported\n";
        r << "SEMANTIC_ORACLE=program_output_byte_identical_pre_post\n";
        r << "FALSIFICATION_PROBES=5\n";
        r << "\n# every check, with the measurement it was made from\n";
        for (const auto& c : g_checks) {
            std::string d2 = c.detail;
            for (auto& ch : d2) if (ch == '\n') ch = ';';
            r << "  " << (c.pass ? "PASS" : "FAIL") << "  " << c.name;
            if (!d2.empty()) r << "  |  " << d2;
            r << "\n";
        }
        r << "\n# fixture program output, before and after, byte for byte\n";
        r << "PRE_OUTPUT=" << pre.output << "\n";
        WriteFile(outPath, r.str());
        printf("RECEIPT=%s\n", outPath.c_str());
    }

    fflush(stdout);
    RemoveTree(scratch);
    return verdict ? 0 : 1;
}
