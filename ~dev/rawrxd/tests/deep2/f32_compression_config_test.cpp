#include "F32CompressionConfig.hpp"
#include <cmath>
#include <cstdio>

int main() {
    float value = -1.0f;
    if (!Deep2::TryParseF32CompressionMaxAbsError("0", value) || value != 0.0f)
        return 1;
    if (!Deep2::TryParseF32CompressionMaxAbsError("0.0001", value) ||
        std::fabs(value - 0.0001f) >= 1e-9f)
        return 2;
    if (!Deep2::TryParseF32CompressionMaxAbsError("1.25", value) || value != 1.25f)
        return 3;

    const char* invalid[] = {
        nullptr, "", " ", "-0.1", "nan", "NaN", "inf", "Infinity",
        "1e1000", "0.1junk", "0.1 ", ".", "--1"
    };
    for (const char* candidate : invalid) {
        value = 17.0f;
        if (Deep2::TryParseF32CompressionMaxAbsError(candidate, value) ||
            value != 17.0f)
            return 4;
    }

    std::puts("PASS: Deep2 F32 compression setting parser");
    return 0;
}
