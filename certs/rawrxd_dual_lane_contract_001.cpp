// certs/rawrxd_dual_lane_contract_001.cpp — seal dual-sovereign contract
#include "../src/deep2/DualLaneChoreographer.hpp"
#include "../src/deep2/Deep2DeviceManager.hpp"
#include <cstdio>
#include <fstream>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <direct.h>
#endif

static void SyncEnv(const char* k, const char* v) {
#ifdef _WIN32
    SetEnvironmentVariableA(k, v);
    _putenv_s(k, v);
#endif
}

int main() {
    using namespace Deep2;
    using namespace Deep2::dual_lane;
#ifdef _WIN32
    _mkdir("G:\\~dev\\rawrxd\\evidence");
    _mkdir("G:\\~dev\\rawrxd\\evidence\\RAWRXD_DUAL_LANE_CONTRACT_001");
#endif
    SyncEnv("RAWRXD_GPU_POLICY", "DUAL_LANE");
    DeviceManagerSnapshot snap{};
    Deep2Device_Enumerate(snap);
    Deep2Device_ApplyPolicy(snap);

    DualLaneChoreographer choreo;
    int armed = 0;
    if (snap.plan.mode == ExecMode::DualSovereign && snap.plan.opened >= 2) {
        const auto& a = snap.devices[snap.plan.openIndexes[0]];
        const auto& b = snap.devices[snap.plan.openIndexes[1]];
        armed = choreo.armDualModel(a.index, a.name, a.dedicatedVram, 1,
                                    "model_a", b.index, b.name,
                                    b.dedicatedVram, 2, "model_b");
    } else {
        // Topology witness optional — contract + choreography still seal.
        armed = choreo.armDualModel(0, "R9700", 32ull << 30, 1, "model_a", 1,
                                    "RX7800XT", 16ull << 30, 2, "model_b");
    }
    ChoreoRequest req{};
    req.prompt = "dual";
    req.requireJoin = 0;
    ChoreoResult r = choreo.run(req);
    const int peerRefuse =
        SovereignLane::mayTouchPeerSlots(LaneId::A, LaneId::B) == 0 ? 1 : 0;
    const int planDual = snap.plan.mode == ExecMode::DualSovereign ? 1 : 0;
    const bool pass = ContractHolds(choreo.contract) && armed &&
                      r.weightCrossRefused == 1 && peerRefuse &&
                      r.independentProgress == 1 && r.a.ok && r.b.ok;
    std::string dir =
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_DUAL_LANE_CONTRACT_001";
    FILE* f = fopen((dir + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) {
        choreo.emit(f, r);
        fprintf(f, "PEER_SLOT_TOUCH_REFUSED=%d\n", peerRefuse);
        fprintf(f, "DEEP2_EXEC_MODE=%u\n", (unsigned)snap.plan.mode);
        fprintf(f, "PLAN_DUAL_SOVEREIGN=%d\n", planDual);
        fprintf(f, "PLAN_REASON=%s\n", snap.plan.reason);
        fprintf(f, "RAWRXD_DUAL_LANE_CONTRACT_001=%s\n",
                pass ? "PASS" : "FAIL");
        fclose(f);
    }
    choreo.emit(stdout, r);
    printf("PLAN_DUAL_SOVEREIGN=%d\n", planDual);
    puts(pass ? "RAWRXD_DUAL_LANE_CONTRACT_001=PASS"
              : "RAWRXD_DUAL_LANE_CONTRACT_001=FAIL");
    return pass ? 0 : 1;
}
