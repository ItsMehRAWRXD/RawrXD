// P1PRA_RuntimeAuthority.cpp — caller-owned ledger glue (no heap)
#include "P1PRA_RuntimeAuthority.hpp"
#include "P1PRA_ProcessState.hpp"

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
#include <intrin.h>

namespace {

constexpr std::size_t kRaStateBytes = 0x50;
constexpr std::size_t kRaRecBytes = 0x40;
constexpr std::size_t kRaCapacity = 2048;

alignas(64) static std::uint8_t g_raState[kRaStateBytes];
alignas(64) static std::uint8_t g_raRecords[kRaCapacity * kRaRecBytes];
static bool g_raReady = false;

}  // namespace

void P1PRA_RuntimeAuthorityInit() noexcept
{
    unsigned int aux = 0;
    const std::uint64_t k0 = __rdtsc();
    const std::uint64_t k1 = static_cast<std::uint64_t>(__rdtscp(&aux)) ^
                             0xA5A5A5A5A5A5A5A5ull;
    g_raReady = RawrXD_RA_Init(g_raState, g_raRecords, kRaCapacity, k0, k1) != 0;
    if (g_raReady)
        P1PRA_Witness("RA_AUTH_INIT", "ok");
    else
        P1PRA_Witness("RA_AUTH_INIT", "fail");
}

void P1PRA_RuntimeAuthorityAppend(const std::uint32_t kind,
                                  const std::uint32_t stage,
                                  const std::uint64_t arg0,
                                  const std::uint64_t arg1,
                                  const std::uint64_t arg2) noexcept
{
    if (!g_raReady)
        return;
    const std::uint64_t tag =
        RawrXD_RA_Append(g_raState, kind, stage, arg0, arg1, arg2);
    if (tag == 0)
        P1PRA_Witness("RA_AUTH_DROP", "1");
}

std::uint64_t P1PRA_RuntimeAuthorityFinalTag() noexcept
{
    if (!g_raReady)
        return 0;
    return *reinterpret_cast<std::uint64_t*>(g_raState + 0x30);
}

std::uint64_t P1PRA_RuntimeAuthorityVerifyChain() noexcept
{
    if (!g_raReady)
        return 0;
    const auto* st = reinterpret_cast<const std::uint64_t*>(g_raState);
    const std::uint64_t head = st[2];
    const std::uint64_t cap = st[1];
    if (cap == 0)
        return 0;
    const std::uint64_t count = (head < cap) ? head : cap;
    if (count == 0)
        return 0;
    const std::uint64_t startSeq = (head > cap) ? (head - cap + 1) : 1;
    const std::uint64_t slot = (startSeq - 1) % cap;
    void* first = g_raRecords + slot * kRaRecBytes;
    return RawrXD_RA_Verify(g_raState, first, count, 0);
}

#endif
