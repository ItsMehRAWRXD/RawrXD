#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>

// Simple workload: compute sum of squares, with injectable failure point
extern "C" int64_t compute_sum_of_squares(const int32_t* data, size_t len) {
    // Failure injection: if fail_at_index is set and within bounds, throw
    static volatile int32_t fail_at_index = -1; // set via env or debugger to inject
    for (size_t i = 0; i < len; ++i) {
        if (i == static_cast<size_t>(fail_at_index)) {
            throw std::runtime_error("Injected failure at index");
        }
    }
    int64_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        int64_t v = data[i];
        sum += v * v;
    }
    return sum;
}

// Reset failure point
extern "C" void reset_injection() {
    static volatile int32_t fail_at_index = -1;
    fail_at_index = -1;
}

// Set failure point (0-based)
extern "C" void set_fail_at_index(int32_t idx) {
    static volatile int32_t fail_at_index = -1;
    fail_at_index = idx;
}