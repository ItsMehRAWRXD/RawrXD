// RAWRXD_EDITOR_AGENT_E2E_001 — editor → context/repo → infer → chrome
#include "../src/product/win32/editor_agent.hpp"
#include "../src/cli/rawr_product_serve.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace rawr::product;
    std::string dir =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_EDITOR_AGENT_E2E_001";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    {
        std::ofstream f(dir + "\\sample.hpp");
        f << "int generate(int n);\n";
    }
    EditorAgentSlice sl;
    bool ok = sl.run(dir, dir + "\\sample.hpp", rawr::ProductLocalInfer);
    std::ofstream seal(dir + "\\SEAL.txt");
    seal << "SCAN=" << sl.scanned << "\nCTX=" << sl.contexted
         << "\nPIPE=" << sl.piped << "\nRECV=" << sl.received
         << "\nPAINT=" << sl.painted
         << "\nRAWRXD_EDITOR_AGENT_E2E_001=" << (ok ? "PASS" : "FAIL") << "\n";
    puts(ok ? "RAWRXD_EDITOR_AGENT_E2E_001=PASS"
            : "RAWRXD_EDITOR_AGENT_E2E_001=FAIL");
    return ok ? 0 : 1;
}
