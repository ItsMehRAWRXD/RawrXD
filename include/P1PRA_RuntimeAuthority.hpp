#pragma once
// C++ glue for RawrXD_RuntimeAuthority_x64.asm (P1PRA builds only).

#include <cstdint>

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY

extern "C" {
std::uint32_t RawrXD_RA_Init(void* state, void* recordStorage,
                             std::uint64_t capacityRecords,
                             std::uint64_t key0, std::uint64_t key1);
std::uint64_t RawrXD_RA_Append(void* state, std::uint32_t kind,
                               std::uint32_t stage, std::uint64_t arg0,
                               std::uint64_t arg1, std::uint64_t arg2);
std::uint64_t RawrXD_RA_Verify(void* state, void* firstRecord,
                               std::uint64_t recordCount,
                               std::uint64_t expectedPrevTag);
}

enum P1PRA_RuntimeEvent : std::uint32_t {
    RA_EVT_MODEL_LOAD = 0x00000001,
    RA_EVT_PROMPT_ACCEPT = 0x00000002,
    RA_EVT_INFERENCE_BEGIN = 0x00000003,
    RA_EVT_INFERENCE_END = 0x00000004,
    RA_EVT_DECODE = 0x00000040,
    RA_EVT_UI_EMIT = 0x00000041,
    RA_EVT_FAULT = 0x000000F0,
    RA_EVT_SHUTDOWN = 0x000000FF,
};

void P1PRA_RuntimeAuthorityInit() noexcept;
void P1PRA_RuntimeAuthorityAppend(std::uint32_t kind, std::uint32_t stage,
                                  std::uint64_t arg0 = 0,
                                  std::uint64_t arg1 = 0,
                                  std::uint64_t arg2 = 0) noexcept;
std::uint64_t P1PRA_RuntimeAuthorityFinalTag() noexcept;
std::uint64_t P1PRA_RuntimeAuthorityVerifyChain() noexcept;

#else

inline void P1PRA_RuntimeAuthorityInit() noexcept {}
inline void P1PRA_RuntimeAuthorityAppend(std::uint32_t, std::uint32_t,
                                         std::uint64_t = 0, std::uint64_t = 0,
                                         std::uint64_t = 0) noexcept {}
inline std::uint64_t P1PRA_RuntimeAuthorityFinalTag() noexcept { return 0; }
inline std::uint64_t P1PRA_RuntimeAuthorityVerifyChain() noexcept { return 0; }

#endif
