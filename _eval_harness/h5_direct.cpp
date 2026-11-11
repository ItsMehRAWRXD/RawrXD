// Deterministic H5 certification: drive the PRODUCTION tool registry from
// src/rawr_core.cpp (registerDefaultTools + ToolRegistry::dispatch + the
// authorization helpers) with crafted arguments. No model, no randomness.
#include "rawr_core.hpp"
#include <cstdio>
#include <string>
using namespace rawr;

static int g_fail = 0;
static void check(bool cond, const std::string& name, const std::string& detail) {
    printf("%-38s %s  %s\n", name.c_str(), cond ? "PASS" : "FAIL", detail.c_str());
    if (!cond) ++g_fail;
}

int main() {
    Workspace ws; ws.setRoot("F:\\rawrxd");
    ToolRegistry reg; registerDefaultTools(reg, ws);
    const ModeProfile* code = findMode("code");
    ToolContext ctx; ctx.mode = code; ctx.ws = &ws;

    auto run = [&](const std::string& tool, const std::string& argsJson) {
        return reg.dispatch(tool, json::parse(argsJson), ctx);
    };
    auto has = [](const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; };

    // 1. Authorized read
    {
        auto r = run("read_file", "{\"path\":\"README_PRODUCTION.md\"}");
        check(r.ok && has(r.output, "RawrXD"), "read authorized README", r.ok ? "ok" : r.output.substr(0,60));
    }
    // 2. Secret-shaped file denied BEFORE access
    {
        auto r = run("read_file", "{\"path\":\".env\"}");
        check(!r.ok && (has(r.output,"access denied")||has(r.output,"outside")), "read .env denied", r.output.substr(0,60));
    }
    // 3. VCS internals denied
    {
        auto r = run("read_file", "{\"path\":\".git/config\"}");
        check(!r.ok && has(r.output,"denied"), "read .git/config denied", r.output.substr(0,60));
    }
    // 4. Workspace traversal (parent escape) denied
    {
        auto r = run("read_file", "{\"path\":\"../../windows/win.ini\"}");
        check(!r.ok, "read ../../windows/win.ini outside workspace", r.output.substr(0,60));
    }
    // 5. Absolute path outside workspace denied
    {
        auto r = run("read_file", "{\"path\":\"C:/Windows/System32/drivers/etc/hosts\"}");
        check(!r.ok, "read C:/Windows/... hosts outside workspace", r.output.substr(0,60));
    }
    // 6. .archive path denied by AUTH (not just default-discovery) -- REAL file
    {
        auto r = run("read_file", "{\"path\":\".archive/Full_Source/CMakeLists.txt.bak\"}");
        check(!r.ok && has(r.output,"denied"), "read real .archive file authorization-denied", r.output.substr(0,70));
    }
    // 7. _pre_merge_backup denied -- REAL file
    {
        auto r = run("read_file", "{\"path\":\"_pre_merge_backup/bbcov_stderr.txt\"}");
        check(!r.ok && has(r.output,"denied"), "read real _pre_merge_backup authorization-denied", r.output.substr(0,70));
    }
    // 7b. .backups denied -- REAL file
    {
        auto r = run("read_file", "{\"path\":\".backups/Subagent-IncludeResolver.ps1.bak\"}");
        check(!r.ok && has(r.output,"denied"), "read real .backups authorization-denied", r.output.substr(0,70));
    }
    // 8. Default search scope: no .archive, no .json/.log hits
    {
        auto r = run("search_text", "{\"query\":\"e\",\"path\":\".\",\"all\":false}");
        bool arch = has(r.output, ".archive"); bool js = has(r.output, ".json");
        check(r.ok && !arch && !js, "default search excludes archive/json", (arch?std::string("has .archive "):"") + (js?std::string("has .json "):""));
    }
    // 9. all=true STILL cannot breach .archive/.git
    {
        auto r = run("search_text", "{\"query\":\"include\",\"path\":\".\",\"all\":true}");
        bool arch = has(r.output, ".archive"); bool git = has(r.output, "/.git/") || has(r.output,"\\.git\\");
        check(r.ok && !arch && !git, "all=true still breaches no archive/.git", (arch?std::string("archive! "):"") + (git?std::string(".git! "):""));
    }
    // 10. list_repo default: no .archive entries
    {
        auto r = run("list_repo", "{\"path\":\".\"}");
        check(r.ok && !has(r.output, ".archive"), "list_repo excludes .archive", "");
    }
    // 11. Unknown tool fails closed
    {
        auto r = run("rm_rf", "{\"path\":\".\"}");
        check(!r.ok && has(r.output,"unknown tool"), "unknown tool rejected", r.output.substr(0,50));
    }
    // 12. ask-mode cannot use CAP_WRITE-only tools (host capability enforcement)
    {
        const ModeProfile* ask = findMode("ask");
        ToolContext actx; actx.mode = ask; actx.ws = &ws;
        auto r = reg.dispatch("write_file", json::parse("{\"path\":\"src/x.txt\",\"action\":\"create\",\"content\":\"x\"}"), actx);
        check(!r.ok && (r.denied || has(r.output,"DENIED")), "ask mode denied write_file (cap policy)", r.output.substr(0,60));
    }

    printf("\nH5_DIRECT: %s (%d failure(s))\n", g_fail==0 ? "ALL PASS" : "FAILURES", g_fail);
    return g_fail==0 ? 0 : 1;
}
