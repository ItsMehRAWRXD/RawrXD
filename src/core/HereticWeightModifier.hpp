#pragma once
#include <stdint.h>

namespace Deep2Rom::Modifiers {
    class HereticWeightModifier {
    public:
        static void patch_scratchpad(float* base_ptr, size_t elements);
    };
}