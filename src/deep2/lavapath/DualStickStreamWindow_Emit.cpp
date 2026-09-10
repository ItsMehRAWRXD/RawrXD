/* DualStickStreamWindow_Emit.cpp — PLAN/ARM/RUNTIME receipt authority. */
#include "DualStickStreamWindow.hpp"

namespace Deep2 {

void DualStickMarkRequested(int requested) {
    DualStickState().requested = requested ? 1 : 0;
}

void EmitDualStickMechanics(FILE* f) {
    if (!f) f = stderr;
    DualStickExec& e = DualStickState();
    const int runtimeUsed =
        (e.forwardCallsGpu0 > 0 && e.forwardCallsGpu1 > 0) ? 1 : 0;
    const int armExec =
        (e.armed && e.armAcquires > 0 && e.armBytesWorked > 0) ? 1 : 0;
    const int armOnly = (e.armed && !runtimeUsed) ? 1 : 0;
    std::fprintf(f,
        "DUALSTICK_REQUESTED=%d\nDUALSTICK_PLANNED=%d\n"
        "DUALSTICK_ARMED=%d\nDUALSTICK_ARM_COUNT=%llu\n"
        "DUALSTICK_ARM_ACQUIRES=%llu\nDUALSTICK_ARM_BYTES_WORKED=%llu\n"
        "DUALSTICK_ARM_EXEC=%d\n"
        "DUALSTICK_RUNTIME_USED=%d\nDUALSTICK_RUNTIME_DEVICE_COUNT=%llu\n"
        "DUALSTICK_FORWARD_CALLS_GPU0=%llu\nDUALSTICK_FORWARD_CALLS_GPU1=%llu\n"
        "DUALSTICK_RUNTIME_BYTES_WORKED=%llu\n"
        "DUALSTICK_TRUE_RUNTIME=%d\nDUALSTICK_ARM_ONLY=%d\n"
        "DUAL_STICK_ARMED=%d\nDUAL_STICK_EXEC=%d\n"
        "DUAL_STICK_ACQUIRES=%llu\nDUAL_STICK_CONSUMERS=%llu\n"
        "DUAL_STICK_OWNERSHIP_ADVANCES=%llu\nDUAL_STICK_BYTES_WORKED=%llu\n"
        "DUAL_STICK_EXEC_NOTE=alias_of_DUALSTICK_RUNTIME_USED\n",
        e.requested, e.planned, e.armed, (unsigned long long)e.armCount,
        (unsigned long long)e.armAcquires,
        (unsigned long long)e.armBytesWorked, armExec, runtimeUsed,
        (unsigned long long)e.runtimeDevices,
        (unsigned long long)e.forwardCallsGpu0,
        (unsigned long long)e.forwardCallsGpu1,
        (unsigned long long)e.runtimeBytesWorked, runtimeUsed, armOnly,
        e.armed, runtimeUsed, (unsigned long long)e.armAcquires,
        (unsigned long long)e.armConsumers,
        (unsigned long long)e.armOwnershipAdvances,
        (unsigned long long)e.armBytesWorked);
}

} // namespace Deep2
