#pragma once
/* Dual-stick stream windows — E8B0M across R9700 + 7800XT; owns work. */
#include "Deep2DeviceManager.hpp"
#include "ParseMibBudget.hpp"
#include "FreeTokenMicroZone.hpp"
#include "FutureConsumerSpace.hpp"
#include "SetEnvDual.hpp"
#include <cstdio>
#include <cstdint>

namespace Deep2 {

struct DualStickWindowPlan {
    uint64_t totalBudgetBytes = 0;
    uint64_t stick0Bytes = 0;
    uint64_t stick1Bytes = 0;
    uint32_t stickCount = 0;
    char stick0Name[128]{};
    char stick1Name[128]{};
    int noTruncateNeedle = 1;
};

struct DualStickExec {
    int      armed = 0;
    uint64_t acquires = 0;
    uint64_t consumers = 0;
    uint64_t ownershipAdvances = 0;
    uint64_t bytesWorked = 0;
};

DualStickExec& DualStickState();
DualStickWindowPlan PlanDualStickWindows(const DeviceManagerSnapshot& snap,
                                         uint64_t budgetBytes);
void ArmDualStickNoTruncate(const DualStickWindowPlan& p);
void EmitDualStickWindowReceipt(FILE* f, const DualStickWindowPlan& p);
void EmitDualStickMechanics(FILE* f);

/* GpuForward path: stick → FreeToken zone → consumer → retire → Advance. */
uint8_t* DualStickAcquire(unsigned stick, const void* src, size_t n,
                          uint64_t fileOffset, uint32_t layer, uint32_t expert);
void DualStickResolve(unsigned stick, uint32_t layer);

} // namespace Deep2
