#include "generic_vulkan_matmul.hpp"

namespace RawrXD::Deep2::GenericVulkan {

bool MatVec(int32_t,
            ggml_type,
            const void*,
            size_t,
            size_t,
            size_t,
            const float*,
            float*) {
    return false;
}

bool MatVecBatch(int32_t,
                 ggml_type,
                 const MatVecSlice*,
                 size_t,
                 size_t,
                 size_t,
                 const float*,
                 size_t,
                 float*,
                 size_t) {
    return false;
}

}  // namespace RawrXD::Deep2::GenericVulkan
