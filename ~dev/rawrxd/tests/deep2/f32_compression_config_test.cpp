#include "F32CompressionConfig.hpp"
#include <cassert>
#include <cmath>
#include <limits>

int main() {
    float value = -1.0f;

    assert(Deep2::TryParseF32CompressionMaxAbsError("0", value));
    assert(value == 0.0f);
    assert(Deep2::TryParseF32CompressionMaxAbsError("0.0001", value));
    assert(std::fabs(value - 0.0001f) < 1e-9f);
    assert(Deep2::TryParseF32CompressionMaxAbsError("1.25", value));
    assert(value == 1.25f);

    const char* invalid[] = {
        nullptr, "", " ", "-0.1", "nan", "NaN", "inf", "Infinity",
        "1e1000", "0.1junk", "0.1 ", ".", "--1"
    };
    for (const char* candidate : invalid) {
        value = 17.0f;
        assert(!Deep2::TryParseF32CompressionMaxAbsError(candidate, value));
        assert(value == 17.0f); // failures never mutate the caller's value
    }

    return 0;
}
