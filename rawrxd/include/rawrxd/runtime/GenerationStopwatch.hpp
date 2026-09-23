#pragma once
#include <cstdint>

namespace RawrXD {
namespace Runtime {

class GenerationStopwatch {
public:
    static GenerationStopwatch& instance() {
        static GenerationStopwatch s;
        return s;
    }
    void start() {}
    void stop() {}
    void reset() {}
    void beginGeneration() {}
    void endGeneration() {}
    uint64_t elapsedMs() const { return 0; }
    uint64_t elapsedUs() const { return 0; }
};

} // namespace Runtime
} // namespace RawrXD
