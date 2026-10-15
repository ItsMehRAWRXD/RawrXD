#ifndef DEEP2_FLIGHT_RECORDER_HPP
#define DEEP2_FLIGHT_RECORDER_HPP

#include <cstddef>
#include <cstdint>

namespace rawrxd {
namespace debug {

// Stub flight recorder interface.  The real implementation records detailed
// per-layer timing/telemetry for production builds; for now this is a
// no-op so the engine compiles without it.
class Recorder {
public:
    Recorder() = default;
    bool start(const wchar_t* /*path*/, unsigned /*maxEvents*/, unsigned /*maxScopeDepth*/) { return false; }
    unsigned begin(const char* /*name*/) { return 0; }
    void end(unsigned /*scopeId*/) {}
};

} // namespace debug
} // namespace rawrxd

namespace Deep2 {

// Stub flight recorder interface (alternative name used in some code paths).
class FlightRecorder {
public:
    FlightRecorder() = default;
    void recordLayerStart(size_t /*layer*/) {}
    void recordLayerEnd(size_t /*layer*/) {}
    void recordEvent(const char* /*event*/, size_t /*layer*/, double /*value*/) {}
};

} // namespace Deep2

#endif // DEEP2_FLIGHT_RECORDER_HPP
