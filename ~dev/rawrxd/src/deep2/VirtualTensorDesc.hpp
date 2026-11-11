#pragma once
/* VirtualTensorDesc — stub */
#include <cstdint>
#include <vector>
namespace Deep2 {
struct VirtualTensorDesc {
    std::vector<int64_t> shape;
    uint32_t dtype = 0;
};
} // namespace Deep2
