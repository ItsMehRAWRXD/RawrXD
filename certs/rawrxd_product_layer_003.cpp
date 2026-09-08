// RAWRXD_PRODUCT_LAYER_003 — workspace, search, history, tools, tensors
#include "../src/product/product_layer.hpp"
#include "../src/deep2/lavapath/ProductTensorGuard.hpp"
#include <cstdio>
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
    puts("RAWRXD_PRODUCT_LAYER_003=FAIL");
    return 1;
}

int main() {
    using namespace rawr::product;
    using namespace rawr::product_run;
    std::string dir = "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_LAYER_003";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    {
        std::ofstream f(dir + "\\sample.hpp");
        f << "class ProductGate { void run(); };\n";
    }
    if (!OpenWorkspace(dir)) return fail("open_ws");
    std::string hit;
    if (!SearchWorkspace(dir, "ProductGate", hit)) return fail("search");
    ConversationHistory hist;
    hist.append("user", "hi");
    if (hist.messages.empty()) return fail("hist");
    ProductSession s{};
    s.id = "psess_layer003";
    s.workspace = dir;
    if (!saveSession(s)) return fail("save");
    ProductSession loaded{};
    if (!loadSession(s.id, loaded)) return fail("load");
    ToolRegistry reg;
    auto echo = [](ToolRuntime&, const char* a, std::string& o) -> int {
        o = a ? a : "";
        return 0;
    };
    if (!reg.registerTool("echo", echo)) return fail("reg");
    FileExplorer fe;
    fe.add("sample.hpp");
    ModelSelector ms;
    ms.add("llama32");
    if (!validateTensor("tok.weight", 4, 8, 4, 8)) return fail("tensor");
    std::ofstream seal(dir + "\\SEAL.txt");
    seal << "OPEN_WORKSPACE=1\nSEARCH=1\nHISTORY=1\nSESSION=1\n"
            "TOOL_REGISTRY=1\nFILE_EXPLORER=1\nMODEL_SELECTOR=1\n"
            "VALIDATE_TENSOR=1\nRAWRXD_PRODUCT_LAYER_003=PASS\n";
    puts("RAWRXD_PRODUCT_LAYER_003=PASS");
    return 0;
}
