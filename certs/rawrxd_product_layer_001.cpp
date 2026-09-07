// RAWRXD_PRODUCT_LAYER_001 — runtime/context/repo/complete/tools/agent
#include "../src/product/product_layer.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

static int fail(const char* w) {
    fprintf(stderr, "FAIL: %s\n", w);
    puts("RAWRXD_PRODUCT_LAYER_001=FAIL");
    return 1;
}

static bool InferStub(const char* prompt, char* out, size_t cap) {
    const char* t = "int add(int a, int b) { return a + b; }";
    if (prompt && std::strstr(prompt, "broken")) t = "int add(int a, int b {";
    size_t n = std::strlen(t);
    if (n >= cap) n = cap - 1;
    std::memcpy(out, t, n);
    out[n] = 0;
    return true;
}

static void WriteFix(const std::string& dir) {
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_LAYER_001",
                     nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    std::ofstream f(dir + "\\sample.hpp");
    f << "#include \"rawr.hpp\"\nclass Engine {\npublic:\n"
         "  int generate(int n);\n};\nint generate(int n) { return n; }\n";
}

int main() {
    using namespace rawr::product;
    if (!AbiOk() || RawrProductCaps() != CapAll) return fail("abi");
    if (RawrTokenEst(8) != 2) return fail("tokens");
    const char* s = "rawr";
    if (RawrFnv1a32(s, 4) == 0) return fail("fnv");

    ProductSession ps{};
    ps.id = "psess_product_layer";
    ps.workspace = "G:\\~dev\\rawrxd";
    ps.lastPrompt = "complete";
    if (!SaveProductSession(ps)) return fail("sess_save");
    ProductSession loaded{};
    if (!LoadProductSession(ps.id, loaded) || loaded.workspace.empty())
        return fail("sess_load");

    CancelToken c{};
    c.request();
    if (!c.requested()) return fail("cancel");
    c.clear();

    EventBus bus;
    bus.push(EvKind::Editor, 1, "edit", "sample.hpp");
    TaskQueue tq;
    tq.enqueue(TaskPri::Low, "old", "a");
    tq.bumpGen();
    tq.dropStale(tq.currentGen);
    if (!tq.items.empty()) return fail("stale_q");

    std::string ws = TelemetryDir() + "\\ws";
    WriteFix(ws);

    RepoIndex idx;
    if (!ScanRepo(ws, idx, 32) || idx.files.empty()) return fail("scan");
    auto g = BuildGraph(idx.symbols);
    if (g.nodes.empty()) return fail("graph");
    auto hits = HybridSearch(idx.symbols, "generate", 8);
    if (hits.empty()) return fail("search");
    auto im = AnalyzeImpact(g, idx.files[0]);
    (void)im;

    EditorSnap ed{};
    ed.path = ws + "\\sample.hpp";
    ed.prefix = "int generate(int n) {";
    ed.suffix = "}";
    ed.line = 6;
    ed.diagnostics.push_back("error C2065: n");
    ContextEngine ce;
    auto extra = SymbolsToContext(hits);
    auto assembled = ce.assemble(ed, CtxStrategy::Completion, extra, "");
    if (assembled.prompt.find("<PRE>") == std::string::npos)
        return fail("ctx");
    if (EstTokens(assembled.prompt) == 0) return fail("budget");

    CompletionScheduler sch;
    sch.db.delayMs = 0;
    sch.bus = &bus;
    ExecutionRequest req{};
    req.prompt = assembled.prompt;
    sch.submit(req);
    sch.submit(req);
    auto xr = sch.run(InferStub);
    if (!xr.ok || xr.text.find("add") == std::string::npos) return fail("sched");
    auto best = BestCandidate({xr.text, "int add(int a, int b {"}, 1);
    if (!best.syntax) return fail("rank");

    ToolRuntime rt;
    rt.box.workspace = ws;
    rt.box.perm.allow(Perm::Read);
    if (rt.writeFile(ws + "\\x.txt", "no")) return fail("deny_write");
    rt.box.perm.allow(Perm::Write);
    rt.box.perm.allow(Perm::Exec);
    if (!rt.writeFile(ws + "\\x.txt", "ok\n")) return fail("write");
    std::string echo;
    if (rt.execEcho("RAWR_PRODUCT_TOOL_OK", echo) != 0) return fail("exec");

    CodingLoop loop;
    loop.ctx.budget.maxTokens = 2048;
    std::string target = ws + "\\loop.cpp";
    if (!loop.run(ws, target, "int ok() { return 1; }\n")) return fail("loop");
    if (!loop.wit.planned || !loop.wit.scanned || !loop.wit.contexted ||
        !loop.wit.patched || !loop.wit.built || !loop.wit.tested ||
        !loop.wit.confident)
        return fail("wit");

    std::ofstream seal(TelemetryDir() + "\\SEAL.txt");
    seal << "ABI=1\nCAPS=63\nSESSION=1\nCONTEXT=1\nREPO=1\nGRAPH=1\n"
            "SEARCH=1\nCOMPLETE=1\nRANK=1\nTOOLS=1\nAUDIT=1\nLOOP=1\n"
            "RAWRXD_PRODUCT_LAYER_001=PASS\n";
    puts("RAWRXD_PRODUCT_LAYER_001=PASS");
    return 0;
}
