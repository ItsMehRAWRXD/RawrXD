#pragma once
/* SlidingWindowEngine — stub */
#include <cstdint>
#include <vector>
namespace Deep2 {
struct SlidingWindowConfig { int maxWindow = 512; };
class SlidingWindowEngine {
public:
    int max_window_size = 512;
    std::vector<int> token_buffer;
};
} // namespace Deep2
