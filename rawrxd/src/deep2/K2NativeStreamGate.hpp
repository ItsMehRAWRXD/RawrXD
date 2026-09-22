#pragma once
/* K2NativeStreamGate — stub */
namespace Deep2 {
struct K2NativeStreamGate {
    struct Config { int layerIdx = 0; size_t seqLen = 1; };
    struct Result { bool ok = false; float latencyMs = 0.0f; };
};
} // namespace Deep2
