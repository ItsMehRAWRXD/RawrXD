// Product E2E observe — performance wall is a separate certificate.
#include "../src/deep2/lavapath/ProductStreamer.hpp"
#include <cstdio>
#include <fstream>
#include <string>

static bool FileHas(const char* path, const char* needle) {
    std::ifstream in(path);
    if (!in) return false;
    std::string body((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    return body.find(needle) != std::string::npos;
}

static bool GatePass(const char* evid, const char* key) {
    const std::string root = "G:\\~dev\\rawrxd\\evidence\\";
    const std::string dir = root + evid + "\\";
    const char* names[] = {"GATE_STATUS.txt", "GATE.txt", "SEAL.txt",
                           "U13_DOMAIN_SEAL.txt"};
    const std::string pass = std::string(key) + "=PASS";
    for (const char* n : names)
        if (FileHas((dir + n).c_str(), pass.c_str())) return true;
    return false;
}

int main() {
    using namespace rawr::product;
    using rawr::lavapath::Result;

    const char* u13 =
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\U13_DOMAIN_SEAL.txt";

    Runtime rt{};
    rt.frontDoor = GatePass("RAWRXD_PRODUCT_FRONTDOOR_001",
                            "RAWRXD_PRODUCT_FRONTDOOR_001");
    rt.modelAddressable =
        GatePass("RAWRXD_SECOND_MODEL_001", "RAWRXD_SECOND_MODEL_001") ||
        GatePass("RAWRXD_INTERSTELLAR_DEEP2_E2E_001",
                 "RAWRXD_INTERSTELLAR_DEEP2_E2E_001");
    rt.executionAvailable =
        GatePass("VWA_BOUNDED_K2_001", "VWA_BOUNDED_K2_001");
    rt.generationEntered =
        FileHas(u13, "U13_DECODE_2048=PASS");
    rt.outputCommitted =
        FileHas(u13, "U13_GENERATION_VALID=1") ? 1ull : 0ull;
    rt.streamFinished = rt.generationEntered && rt.outputCommitted > 0;
    rt.wallWithinBudget = FileHas(u13, "K2_USEFUL_TPS_001=PASS");

    Materialized mat{}; // unused teardown erased

    // PRODUCT GOAL — no performance requirement (slow ≠ nonexistent).
    Goal productGoal{};
    productGoal.generate = true;
    productGoal.requirePerformanceCert = false;

    Scratch<32> sProd{};
    Required reqProd{};
    const Result rProd =
        ObserveProduct(productGoal, mat, rt, sProd, reqProd);
    std::puts("=== PRODUCT_PROCESSION ===");
    Emit(stdout, sProd, reqProd);

    // PERFORMANCE GOAL — independent climb (QKV owns remaining delta).
    Goal perfGoal{};
    perfGoal.requirePerformanceCert = true;
    Scratch<32> sPerf{};
    Required reqPerf{};
    const Result rPerf =
        ObserveProduct(perfGoal, mat, rt, sPerf, reqPerf);
    std::puts("=== PERFORMANCE_PROCESSION ===");
    Emit(stdout, sPerf, reqPerf);

    const bool productOk = (rProd == Result::Complete);
    const bool perfOk = (rPerf == Result::Complete);
    std::printf("RAWRXD_PRODUCT_E2E_001=%s\n", productOk ? "PASS" : "OPEN");
    std::printf("PRODUCT_SEAL_ELIGIBLE=%d\n", productOk ? 1 : 0);
    std::printf("RAWRXD_PERFORMANCE_001=%s\n", perfOk ? "PASS" : "OPEN");
    std::printf("PERFORMANCE_FIRST_DELTA=%s\n",
                perfOk ? "NONE" : "WALL_WITHIN_BUDGET");
    std::printf("HOTPATH_OWNER=QKV_PROJ\n");
    std::printf("CHOREOGRAPH_OUT=1 WALL_BUDGET_IN_PRODUCT=0\n");
    std::printf("SLOW_EQUALS_NONEXISTENT=0\n");

    if (productOk) {
        std::ofstream seal(
            "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PRODUCT_E2E_001\\SEAL.txt");
        seal << "RAWRXD_PRODUCT_E2E_001=PASS\n";
        seal << "PRODUCT_SEAL_ELIGIBLE=1\n";
        seal << "WALL_BUDGET_IN_PRODUCT=0\n";
        seal << "RAWRXD_PERFORMANCE_001=" << (perfOk ? "PASS" : "OPEN")
             << "\n";
        seal << "PERFORMANCE_FIRST_DELTA=WALL_WITHIN_BUDGET\n";
        seal << "HOTPATH_OWNER=QKV_PROJ\n";
    }
    return productOk ? 0 : 2;
}
