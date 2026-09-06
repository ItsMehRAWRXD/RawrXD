#pragma once

#include "Deep2Quantization.hpp"
#include <algorithm>
#include <cmath>

extern "C" {
    void AlignNegativeQuantRange512(int8_t* activations, int8_t maxPositiveVal);
}

class Deep2SymmetricMatrixWrapper {
public:
    static void QuantizeAndBalanceBlock(const float* rawData, int8_t* outQuantized, float& outScale) {
        float maxAbsVal = 0.0f;
        
        // Find the absolute maximum value in the 512-element block
        for (int i = 0; i < 512; ++i) {
            maxAbsVal = std::max(maxAbsVal, std::abs(rawData[i]));
        }

        // Calculate the symmetric scale factor bounded to 127
        outScale = maxAbsVal / 127.0f;
        if (outScale == 0.0f) outScale = 1.0f;

        // Perform the initial quantization pass into the buffer
        int8_t peakPositive = 0;
        for (int i = 0; i < 512; ++i) {
            int32_t quantizedValue = static_cast<int32_t>(std::round(rawData[i] / outScale));
            
            // Explicit clamp to symmetric INT8 limits [-127, 127]
            quantizedValue = std::max(-127, std::min(127, quantizedValue));
            outQuantized[i] = static_cast<int8_t>(quantizedValue);

            if (outQuantized[i] > peakPositive) {
                peakPositive = outQuantized[i];
            }
        }

        // Invoke the assembly kernel to force the negative range down to the exact size of the maximum positive value
        AlignNegativeQuantRange512(outQuantized, peakPositive);
    }
};
