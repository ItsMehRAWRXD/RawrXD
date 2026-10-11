#include "utc_provider.h"
#include "utc_asm_abi.h"
#include <cstdint>
#include <type_traits>

static_assert(std::is_same<decltype(utc::LogEvent("a", "b")), std::uint64_t>::value,
              "C++ recorder signature must remain namespaced");
static_assert(std::is_same<decltype(utc::ReadCounter(&utc::g_Counter_Inference)), std::uint64_t>::value,
              "C++ atomic counter reader must remain namespaced");
#if defined(RAWRXD_LINK_TELEMETRY_KERNEL_ASM) && RAWRXD_LINK_TELEMETRY_KERNEL_ASM
static_assert(std::is_same<decltype(UTC_LogEvent("message")), std::uint64_t>::value,
              "MASM ABI must retain one-argument logger");
static_assert(std::is_same<decltype(UTC_ReadCounter(&g_Counter_Inference)), std::uint64_t>::value,
              "MASM ABI must retain volatile QWORD counter pointer");
#endif
int main() { return 0; }
