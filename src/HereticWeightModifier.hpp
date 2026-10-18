#pragma once
#include <stdint.h>
#include <string_view>
#include <iostream>

namespace Deep2Engine::Emulator {

    class HereticWeightModifier {
    public:
        // Intercept dequantized weight buffers immediately after loading from NVMe,
        // allowing runtime patching (e.g., zero-weight clamping, bias injection)
        // before tensors reach the Vulkan hardware pipeline buffers.
        static void inject_runtime_bias(float* dequant_scratchpad, size_t element_count,
                                        std::string_view tensor_name) {
            if (tensor_name.find("attn_qkv.weight") != std::string_view::npos) {
                for (size_t i = 0; i < element_count; ++i) {
                    // Heretic Modification: Enforce weight clamping to avoid dead neurons
                    if (dequant_scratchpad[i] == 0.0f) {
                        dequant_scratchpad[i] = 1e-7f;
                    }
                }
            }
        }
    };
}
