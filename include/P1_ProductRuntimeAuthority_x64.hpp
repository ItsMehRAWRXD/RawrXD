#pragma once
// P1_PRODUCT_RUNTIME_AUTHORITY_002 — thin ABI declarations only.

#include <cstddef>
#include <cstdint>

extern "C" {

void P1PRA_Initialize(void* state);

std::uint64_t P1PRA_BeginUserPrompt(
    void* state,
    const void* prompt,
    std::uint64_t promptBytes);

std::uint64_t P1PRA_AdvanceStage(
    void* state,
    std::uint64_t requestId,
    std::uint64_t stage);

std::uint64_t P1PRA_AddPhysicalCounter(
    void* state,
    std::uint64_t offset,
    std::uint64_t amount);

std::uint64_t P1PRA_Finalize(void* state);

}  // extern "C"

namespace p1pra {

inline constexpr std::size_t StateSize = 0x100;

inline constexpr std::uint64_t StageNone         = 0;
inline constexpr std::uint64_t StageUserPrompt   = 1;
inline constexpr std::uint64_t StageRouter       = 2;
inline constexpr std::uint64_t StageGgufOpen     = 3;
inline constexpr std::uint64_t StageWeightAccess = 4;
inline constexpr std::uint64_t StageForward      = 5;
inline constexpr std::uint64_t StageSample       = 6;
inline constexpr std::uint64_t StageDecode       = 7;
inline constexpr std::uint64_t StageUiEmit       = 8;

inline constexpr std::size_t OffPromptCount = 0x28;
inline constexpr std::size_t OffPromptBytes = 0x30;
inline constexpr std::size_t OffPromptTsc    = 0x38;
inline constexpr std::size_t OffCurrentRequestId = 0x18;
inline constexpr std::size_t OffCurrentStage = 0x20;
inline constexpr std::size_t OffRouterCount = 0x48;
inline constexpr std::size_t OffGgufOpenCount = 0x50;
inline constexpr std::size_t OffWeightBytes = 0x58;
inline constexpr std::size_t OffForwardCount = 0x60;
inline constexpr std::size_t OffSampleCount = 0x68;
inline constexpr std::size_t OffDecodeBytes = 0x70;
inline constexpr std::size_t OffUiBytes = 0x78;
inline constexpr std::size_t OffFailureFlags = 0x88;

}  // namespace p1pra
