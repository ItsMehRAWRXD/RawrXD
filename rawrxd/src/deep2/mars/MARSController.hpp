#pragma once
// Stub: MARSController (Deep2 namespace)
#include <cstdint>
#include <string>
namespace Deep2 {
struct VRAMLease { uint64_t id = 0; size_t bytes = 0; int gpu = 0; };
struct HotpatchResult { bool ok = false; };
struct DynamicParity { float gpu0Util = 0.0f; float gpu1Util = 0.0f; };
class MARSController {
public:
    bool initialize() { return true; }
    bool submit(const std::string& /*work*/) { return true; }
    bool synchronize() { return true; }
};
} // namespace Deep2
