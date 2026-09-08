#pragma once
/* Three-point mount: authority fixed; bytes free to flow. */
#include <cstdint>

namespace rawr::mount {

struct SourceMount {
    bool authority = false;
    bool broken = false; // observably broken — not “slow”
    bool solid() const noexcept { return authority && !broken; }
};

struct ExecutionMount {
    bool authority = false;
    bool broken = false;
    bool solid() const noexcept { return authority && !broken; }
};

struct StateMount {
    bool authority = false;
    bool broken = false;
    bool solid() const noexcept { return authority && !broken; }
};

struct ModelMount {
    SourceMount left{};
    ExecutionMount right{};
    StateMount rear{};

    bool solid() const noexcept {
        return left.solid() && right.solid() && rear.solid();
    }
    /* Remount/reopen/migrate forbidden while solid. */
    bool mountActionEligible() const noexcept {
        return !solid() || left.broken || right.broken || rear.broken;
    }
};

struct HaveModel {
    bool transformationObtainable = false;
    constexpr bool have() const noexcept { return transformationObtainable; }
};

enum class Advance : uint8_t {
    NextProduced = 0,
    TerminalProduced = 1,
    NoNextExists = 2
};

enum class SpendClass : uint8_t {
    GenerationProgress = 0, // TOKEN>0
    UsefulChoreography = 1, // TOKEN=0, terminal delta reduced
    NegativeGeneration = 2  // TOKEN=0, delta not reduced
};

inline constexpr uint32_t kMountCount = 3;
inline constexpr int kAuthorityMovement = 0;
inline constexpr int kWorkMovement = 1;
inline constexpr int kProcessionCount = 1;
inline constexpr int kMountReentryAllowed = 0;

} // namespace rawr::mount
