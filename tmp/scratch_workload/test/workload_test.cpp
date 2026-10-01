#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdlib>
extern "C" {
    int64_t compute_sum_of_squares(const int32_t* data, size_t len);
    void reset_injection();
    void set_fail_at_index(int32_t idx);
}

int main() {
    // Simple test data
    std::vector<int32_t> data = {1, 2, 3, 4, 5};
    int64_t expected = 1 + 4 + 9 + 16 + 25; // 55

    // Reset injection
    reset_injection();

    try {
        int64_t result = compute_sum_of_squares(data.data(), data.size());
        if (result != expected) {
            std::cerr << "TEST FAILED: expected " << expected << ", got " << result << std::endl;
            return 1;
        }
        std::cout << "TEST PASSED" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "TEST FAILED with exception: " << e.what() << std::endl;
        return 1;
    }
}