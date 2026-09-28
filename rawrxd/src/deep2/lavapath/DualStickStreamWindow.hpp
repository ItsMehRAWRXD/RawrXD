#pragma once
/* Dual-stick stream windows — E8B0M across R9700 + 7800XT; owns work. No external deps. */
#include <cstdio>
#include <cstdint>
#include <cstddef>

namespace Deep2 {

/* Minimal device snapshot used by planner — self-contained, no Deep2DeviceManager.hpp dependency. */
struct DeviceManagerSnapshot {
    uint32_t deviceCount = 0;
    uint64_t totalMemoryBytes = 0;
    uint64_t freeMemoryBytes = 0;
    char     device0Name[128]{};
    char     device1Name[128]{};
    uint64_t device0FreeBytes = 0;
    uint64_t device1FreeBytes = 0;
};

struct DualStickWindowPlan {
    uint64_t totalBudgetBytes = 0;
    uint64_t stick0Bytes = 0;
    uint64_t stick1Bytes = 0;
    uint32_t stickCount = 0;
    char stick0Name[128]{};
    char stick1Name[128]{};
    int noTruncateNeedle = 1;
};

/* Authority split: PLAN / ARM / RUNTIME must not contaminate. */
struct DualStickExec {
    int      requested = 0;
    int      planned = 0;
    int      armed = 0;
    uint64_t armCount = 0;
    uint64_t armAcquires = 0;
    uint64_t armConsumers = 0;
    uint64_t armOwnershipAdvances = 0;
    uint64_t armBytesWorked = 0;
    uint64_t forwardCallsGpu0 = 0;
    uint64_t forwardCallsGpu1 = 0;
    uint64_t runtimeDevices = 0;
    uint64_t runtimeBytesWorked = 0;
};

DualStickExec& DualStickState();
DualStickWindowPlan PlanDualStickWindows(const DeviceManagerSnapshot& snap,
                                         uint64_t budgetBytes);
void ArmDualStickNoTruncate(const DualStickWindowPlan& p);
void EmitDualStickWindowReceipt(FILE* f, const DualStickWindowPlan& p);
void EmitDualStickMechanics(FILE* f);
void DualStickMarkRequested(int requested);
void DualStickEnvSnapRequested();
void DualStickEnvSnapAfterHarness();
void DualStickEnvSnapAfterDualstick();
void EmitDualStickEnvAuthority(FILE* f);

void DualStickArmWarmup(unsigned stick, uint32_t layer);
uint8_t* DualStickAcquire(unsigned stick, const void* src, size_t n,
                          uint64_t fileOffset, uint32_t layer, uint32_t expert);
void DualStickResolve(unsigned stick, uint32_t layer);

} // namespace Deep2

/* Stick-VRAM expert path: bind opened VulkanCompute slots; Note = FWD_G*. */
namespace Deep2 { class VulkanCompute; }
namespace CPUInference { using VulkanCompute = Deep2::VulkanCompute; }
namespace Deep2 {
void DualStickBindVc(unsigned stick, CPUInference::VulkanCompute* vc);
CPUInference::VulkanCompute* DualStickVc(unsigned stick);
void DualStickNoteExpertGpu(unsigned stick, size_t bytes);
/* True stick residency for MoE Place probe / stick affinity retain. */
void DualStickNoteExpertResident(int layer, int expert, unsigned stick,
                                 uint64_t bytes);
void DualStickForgetExpertResident(int layer, int expert);
int DualStickExpertIsResident(int layer, int expert);
int DualStickExpertStickOf(int layer, int expert);
uint64_t DualStickExpertBytesOf(int layer, int expert);
unsigned DualStickPickStick(uint32_t expertId);
uint64_t DualStickStickResBytes(unsigned stick);
void DualStickExpertResidencyReset();
} // namespace Deep2

