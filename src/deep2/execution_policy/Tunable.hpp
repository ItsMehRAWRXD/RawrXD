// ============================================================================
// Tunable.hpp — authority-aware setting cell for ExecutionPolicy
// Session > Model > Global > AutoDetect; lower authority cannot overwrite higher.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <optional>

namespace Deep2 {
namespace Exec {

enum class SettingAuthority : uint8_t {
    AutoDetect = 0,
    AutoPlanner,
    RuntimeLearned,
    UserOverride,
    UserLocked,
    Session
};

enum class SettingMutability : uint8_t {
    Immediate = 0,
    TokenBoundary,
    SequenceBoundary,
    ModelReload
};

enum class UiMode : uint8_t {
    Auto = 0,
    Guided,
    Expert
};

inline bool AuthorityOutranks(SettingAuthority a, SettingAuthority b) {
    return static_cast<uint8_t>(a) > static_cast<uint8_t>(b);
}

template <typename T>
struct Tunable {
    T value{};
    SettingAuthority authority = SettingAuthority::AutoDetect;
    SettingMutability mutability = SettingMutability::Immediate;
    bool present = false;

    // Apply only if callerAuthority outranks (or equals and allowed) current.
    bool trySet(const T& v, SettingAuthority caller,
                SettingMutability mut = SettingMutability::Immediate) {
        if (present && AuthorityOutranks(authority, caller))
            return false;
        if (present && authority == SettingAuthority::UserLocked &&
            caller != SettingAuthority::Session &&
            caller != SettingAuthority::UserLocked)
            return false;
        value = v;
        authority = caller;
        mutability = mut;
        present = true;
        return true;
    }

    void force(const T& v, SettingAuthority auth, SettingMutability mut) {
        value = v;
        authority = auth;
        mutability = mut;
        present = true;
    }
};

inline constexpr uint64_t KB = 1024ULL;
inline constexpr uint64_t MB = 1024ULL * KB;
inline constexpr uint64_t GB = 1024ULL * MB;

struct Bytes {
    uint64_t n = 0;
    static Bytes Of(uint64_t v) { return Bytes{v}; }
    static Bytes GiB(double g) { return Bytes{static_cast<uint64_t>(g * GB)}; }
    static Bytes MiB(double m) { return Bytes{static_cast<uint64_t>(m * MB)}; }
};

} // namespace Exec
} // namespace Deep2
