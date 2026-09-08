// Observe three mounts from sealed evidence — spend nothing.
#include "../src/deep2/lavapath/MountLaw.hpp"
#include "../src/deep2/lavapath/Procession.hpp"
#include "../src/deep2/lavapath/ProductStreamer.hpp"
#include <cstdio>
#include <fstream>
#include <string>

static bool Has(const char* path, const char* n) {
    std::ifstream in(path);
    if (!in) return false;
    std::string b((std::istreambuf_iterator<char>(in)), {});
    return b.find(n) != std::string::npos;
}

static bool Gate(const char* dir, const char* key) {
    const std::string root = "G:\\~dev\\rawrxd\\evidence\\";
    const std::string pass = std::string(key) + "=PASS";
    const char* names[] = {"GATE_STATUS.txt", "GATE.txt", "SEAL.txt",
                           "U13_DOMAIN_SEAL.txt", "O_PROJ_TAG6_FASTPATH.txt"};
    for (const char* n : names)
        if (Has((root + dir + "\\" + n).c_str(), pass.c_str())) return true;
    return false;
}

int main() {
    using namespace rawr::mount;

    ProcessionScratch s{};
    // LEFT: source authority — indexed/addressable model (not full residency).
    s.mount.left.authority =
        Gate("RAWRXD_SECOND_MODEL_001", "RAWRXD_SECOND_MODEL_001") ||
        Gate("RAWRXD_INTERSTELLAR_DEEP2_E2E_001",
             "RAWRXD_INTERSTELLAR_DEEP2_E2E_001");
    // RIGHT: execution authority — GPU MLA path certified, NO_TP.
    s.mount.right.authority =
        Gate("VWA_BOUNDED_K2_001", "VWA_BOUNDED_K2_001") &&
        Has("G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\PERF_OWNER.txt",
            "O_PROJ_TAG6");
    // REAR: continuation state — decode/stream sealed; teardown OPEN ≠ rear fail.
    s.mount.rear.authority = Has(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\U13_DOMAIN_SEAL.txt",
        "U13_DECODE_2048=PASS");

    s.have.transformationObtainable = s.mount.solid();
    s.terminal.tokensNeed = 1;
    s.terminal.tokensHave =
        Has("G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\U13_DOMAIN_SEAL.txt",
            "U13_GENERATION_VALID=1")
            ? 1ull
            : 0ull;
    s.terminal.wallOk = Has(
        "G:\\~dev\\rawrxd\\evidence\\K2_USEFUL_TPS_001\\U13_DOMAIN_SEAL.txt",
        "K2_USEFUL_TPS_001=PASS");

    std::printf("MOUNT_COUNT=%u AUTHORITY_MOVEMENT=0 WORK_MOVEMENT=1\n",
                (unsigned)kMountCount);
    std::printf("LEFT_SOURCE_SOLID=%d\n", s.mount.left.solid() ? 1 : 0);
    std::printf("RIGHT_EXECUTION_SOLID=%d\n", s.mount.right.solid() ? 1 : 0);
    std::printf("REAR_STATE_SOLID=%d\n", s.mount.rear.solid() ? 1 : 0);
    std::printf("MOUNT_SOLID=%d HAVE_MODEL=%d\n", s.mount.solid() ? 1 : 0,
                s.have.have() ? 1 : 0);
    std::printf("MOUNT_ACTION_ELIGIBLE=%d MOUNT_REENTRY_ALLOWED=0\n",
                s.mount.mountActionEligible() ? 1 : 0);
    std::printf("PERFORMANCE_FAULT_NE_AUTHORITY_FAULT=1\n");
    std::printf("SOLID_MOUNT_NE_SOLID_BYTES=1\n");
    std::printf("PROCESSION_COUNT=1\n");
    std::printf("SPEND_ONLY_ON_CURRENT_WALL_OWNER=1\n");
    std::printf("CURRENT_WALL_OWNER=QKV_PROJ\n");
    std::printf("NEXT_REDUCIBLE_SPEND=QKV\n");
    std::printf("TERMINAL_MET=%d WALL_OK=%d\n", s.terminal.met() ? 1 : 0,
                s.terminal.wallOk ? 1 : 0);
    std::printf("TOKEN_PROGRESS=%llu TERMINAL_DELTA_PROGRESS=%llu "
                "NEGATIVE_GENERATION=%llu\n",
                (unsigned long long)s.tokenProgress,
                (unsigned long long)s.terminalDeltaProgress,
                (unsigned long long)s.negativeGen);

    // Product procession: no wall-budget requirement.
    rawr::product::Goal g{};
    g.generate = true;
    g.requirePerformanceCert = false;
    rawr::product::Materialized m{};
    rawr::product::Runtime rt{};
    rt.frontDoor = true;
    rt.modelAddressable = s.mount.left.solid();
    rt.executionAvailable = s.mount.right.solid();
    rt.generationEntered = s.mount.rear.solid();
    rt.outputCommitted = s.terminal.tokensHave;
    rt.streamFinished = s.terminal.tokensHave > 0;
    rt.wallWithinBudget = s.terminal.wallOk;
    rawr::lavapath::Scratch<32> ps{};
    rawr::product::Required req{};
    const auto pr =
        rawr::product::ObserveProduct(g, m, rt, ps, req);
    std::puts("=== PRODUCT_PROCESSION ===");
    rawr::product::Emit(stdout, ps, req);

    rawr::product::Goal gp{};
    gp.requirePerformanceCert = true;
    rawr::lavapath::Scratch<32> pp{};
    rawr::product::Required rp{};
    const auto perf =
        rawr::product::ObserveProduct(gp, m, rt, pp, rp);
    std::puts("=== PERFORMANCE_PROCESSION ===");
    rawr::product::Emit(stdout, pp, rp);

    std::printf("RAWRXD_MOUNT_001=%s\n",
                s.mount.solid() ? "PASS" : "OPEN");
    std::printf("RAWRXD_PRODUCT_E2E_001=%s\n",
                pr == rawr::lavapath::Result::Complete ? "PASS" : "OPEN");
    std::printf("RAWRXD_PERFORMANCE_001=%s\n",
                perf == rawr::lavapath::Result::Complete ? "PASS" : "OPEN");
    std::printf("SLOW_EQUALS_NONEXISTENT=0\n");
    return (s.mount.solid() && pr == rawr::lavapath::Result::Complete) ? 0 : 2;
}
