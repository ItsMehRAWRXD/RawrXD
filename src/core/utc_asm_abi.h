#pragma once
// MASM telemetry ABI only. The native UTC provider lives in namespace utc.
// Do not use 'defined(RAWR_HAS_MASM)': CMake defines it to 0 or 1.
#include <cstdint>
#if defined(RAWRXD_LINK_TELEMETRY_KERNEL_ASM) && RAWRXD_LINK_TELEMETRY_KERNEL_ASM
extern "C" {
extern std::uint64_t g_Counter_Inference;
extern std::uint64_t g_Counter_ScsiFails;
extern std::uint64_t g_Counter_AgentLoop;
extern std::uint64_t g_Counter_BytePatches;
extern std::uint64_t g_Counter_MemPatches;
extern std::uint64_t g_Counter_ServerPatches;
extern std::uint64_t g_Counter_FlushOps;
extern std::uint64_t g_Counter_Errors;
std::uint64_t UTC_ReadCounter(const volatile std::uint64_t* counter);
std::uint64_t UTC_LogEvent(const char* message);
}
#endif
