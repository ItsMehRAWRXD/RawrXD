// ============================================================================
// RawrRuntime.hpp — Stub header for RawrRuntime
// ============================================================================

#ifndef RAWR_RUNTIME_HPP
#define RAWR_RUNTIME_HPP

#include <cstdint>
#include <cstddef>
#include <string>

namespace rawr {

enum class LogLevel : uint8_t {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3
};

class RawrRuntime {
public:
    static RawrRuntime& Get();

    void Log(LogLevel level, const char* message);
    void Logf(LogLevel level, const char* fmt, ...);
};

} // namespace rawr

#endif // RAWR_RUNTIME_HPP
