#include "HereticWeightModifier.hpp"

namespace Deep2Rom::Modifiers {
    void HereticWeightModifier::patch_scratchpad(float* base_ptr, size_t elements) {
        for (size_t i = 0; i < elements; ++i) {
            if (base_ptr[i] == 0.0f) base_ptr[i] = 1e-7f;
        }
    }
}