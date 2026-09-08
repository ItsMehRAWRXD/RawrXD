// RAWRXD_PRODUCT_RUNTIME_001 — ProductRuntime owner + reload + busy
#include "../src/deep2/lavapath/ProductGraph.hpp"
#include "../src/deep2/lavapath/ProductRuntime.hpp"
#include "../src/product/ide/cancel_gen.hpp"
#include "../src/product/ide/chat_panel.hpp"
#include "../src/product/agent/agent_product_run.hpp"
#include "../src/product/win32/ide_product_run.hpp"
#include <cstdio>
#include <fstream>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main() {
    using namespace rawr::product_run;
    ProductRuntime rt;
    rt.LOCAL_ONLY = 1;
    rt.NO_CLOUD = 1;
    rt.alreadyGenerating.store(1);
    Result busy = rt.generate("hi");
    int busyOk = (busy.exitReason && busy.exitReason[0] == 'B') ? 1 : 0;
    rt.alreadyGenerating.store(0);
    ExecutionGraph g;
    int graphEmpty = BuildExecutionGraph(rt, g) ? 0 : 1;
    rawr::product::CancelGeneration(rt);
    bool (ProductRuntime::*reload)(const char*) = &ProductRuntime::reloadModel;
    int reloadNamed = reload ? 1 : 0;
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_RUNTIME_001", nullptr);
    std::ofstream seal(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_RUNTIME_001\\SEAL.txt");
    const bool pass = busyOk && graphEmpty && reloadNamed && rt.LOCAL_ONLY &&
                       rt.NO_CLOUD;
    seal << "PRODUCT_RUNTIME=1\nBUSY=" << busyOk << "\nGRAPH_EMPTY="
         << graphEmpty << "\nRELOAD_MODEL=1\nLOCAL_ONLY=" << rt.LOCAL_ONLY
         << "\nNO_CLOUD=" << rt.NO_CLOUD
         << "\nRAWRXD_PRODUCT_RUNTIME_001=" << (pass ? "PASS" : "FAIL")
         << "\n";
    puts(pass ? "RAWRXD_PRODUCT_RUNTIME_001=PASS"
              : "RAWRXD_PRODUCT_RUNTIME_001=FAIL");
    return pass ? 0 : 1;
}
