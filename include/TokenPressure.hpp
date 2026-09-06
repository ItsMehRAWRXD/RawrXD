#pragma once
// TOKEN_PRESSURE_VALVE_001 — orthogonal nozzle (not ctx/temp/GPU/path).

#include <cstddef>
#include <cstdint>

extern "C" {
void TokenPressure_Init(void* state);
void TokenPressure_SetSpray(void* state, std::uint64_t mode);
std::uint64_t TokenPressure_Update(void* state, std::uint64_t tokenHash, std::uint64_t flags);
}

namespace token_pressure {

inline constexpr std::size_t StateSize = 0x100;

enum class SprayMode : std::uint64_t {
    Needle = 0,
    Mist = 1,
    Pulse = 2,
    Rinse = 3,
    Cutoff = 4,
    RepairJet = 5,
};

enum class ValveAction : std::uint64_t {
    Pass = 0,
    PenalizeRepeat = 1,
    PreferStop = 2,
    StopRequest = 3,
};

inline constexpr std::uint64_t FlagNewline = 1;
inline constexpr std::uint64_t FlagFence = 2;
inline constexpr std::uint64_t FlagBrace = 4;
inline constexpr std::uint64_t FlagFiller = 8;

void ProcessStartup() noexcept;
void SetSpray(SprayMode mode) noexcept;
ValveAction OnUtf8Chunk(const char* utf8, std::size_t bytes) noexcept;
void ObserveTerminalError() noexcept; // switches RepairJet

}  // namespace token_pressure
