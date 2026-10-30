// REGISTRY_DISPATCH_SMOKE — Cursor alias + runInTerminal registration.
// PROMOTE=0. Exit 0 only if all gates pass.
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#include "../../src/agentic/tool_core.hpp"
#include "../../src/agentic/AgentMode.h"

namespace fs = std::filesystem;
using namespace rawrxd::tools;
using RawrXD::Agent::AgentMode;
using RawrXD::Agent::ModeRegistry;
using RawrXD::Agent::ToolAuthority;

static int g_fail = 0;
static void expect(bool ok, const char* name) {
    if (ok) {
        std::printf("PASS %s\n", name);
    } else {
        std::printf("FAIL %s\n", name);
        ++g_fail;
    }
}

int main() {
    const fs::path root = fs::temp_directory_path() / "rawrxd_cursor_parity_smoke";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root / "src", ec);
    {
        std::ofstream f(root / "src" / "hello.txt");
        f << "hello_cursor_parity\n";
    }

    Registry reg;
    register_workspace_tools(reg, root);

    const char* required[] = {
        "readFile", "Read", "listDirectory", "fileSearch", "Glob",
        "textSearch", "Grep", "createDirectory", "createFile",
        "writeFile", "Write", "editFiles", "StrReplace",
        "deleteFile", "Delete", "runInTerminal", "Shell",
    };
    for (const char* n : required) {
        Tool t;
        expect(reg.find(n, t), n);
    }

    Tool shellT, runT;
    expect(reg.find("Shell", shellT) && reg.find("runInTerminal", runT) &&
               shellT.risk == Risk::Execute && runT.risk == Risk::Execute,
           "Shell_risk_eq_runInTerminal");

    // Outside-workspace path must fail
    {
        Request r;
        r.name = "readFile";
        r.args["path"] = "C:/Windows/win.ini";
        auto res = reg.call(r, [](const Tool&, const Request&) { return true; });
        expect(!res.ok, "outside_workspace_denied");
    }

    // writeFile + Read alias
    {
        Request w;
        w.name = "Write";
        w.args["path"] = "src/out.txt";
        w.args["content"] = "written_by_alias\n";
        auto wr = reg.call(w, [](const Tool&, const Request&) { return true; });
        expect(wr.ok, "Write_alias");
        Request r;
        r.name = "Read";
        r.args["path"] = "src/out.txt";
        auto rr = reg.call(r, [](const Tool&, const Request&) { return true; });
        expect(rr.ok && rr.output.find("written_by_alias") != std::string::npos, "Read_alias");
    }

    // Shell echo
    {
        Request s;
        s.name = "Shell";
        s.args["command"] = "echo cursor_parity_ok";
        auto sr = reg.call(s, [](const Tool&, const Request&) { return true; });
        expect(sr.ok && sr.output.find("cursor_parity_ok") != std::string::npos, "Shell_echo");
    }

    // Ask mode: Shell must be Denied (canonicalize to runInTerminal)
    {
        auto auth = ModeRegistry::Instance().AuthorityFor(AgentMode::Ask, "Shell");
        expect(auth == ToolAuthority::Denied, "Ask_Shell_denied");
        auth = ModeRegistry::Instance().AuthorityFor(AgentMode::Ask, "runInTerminal");
        expect(auth == ToolAuthority::Denied, "Ask_runInTerminal_denied");
        auth = ModeRegistry::Instance().AuthorityFor(AgentMode::Ask, "Write");
        expect(auth == ToolAuthority::Denied, "Ask_Write_denied");
    }

    std::printf("FAIL_COUNT=%d\n", g_fail);
    std::printf("PROMOTE=0\n");
    return g_fail == 0 ? 0 : 1;
}
