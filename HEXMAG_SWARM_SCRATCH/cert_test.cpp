// HexMag Swarm certification fixture — real assertions.
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstdio>

uint64_t RangeSum(const std::vector<uint64_t>& values, size_t first, size_t last);

static int g_failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("ASSERT FAILED: %s\n", msg); ++g_failures; } } while (0)

int main() {
    const std::vector<uint64_t> v = {10, 20, 30, 40, 50};

    CHECK(RangeSum(v, 0, 4) == 150, "RangeSum(0,4) must be 150 (inclusive of index 4)");
    CHECK(RangeSum(v, 1, 3) == 90,  "RangeSum(1,3) must be 90 (20+30+40)");
    CHECK(RangeSum(v, 2, 2) == 30,  "RangeSum(2,2) must be 30 (single element, inclusive)");
    CHECK(RangeSum(v, 0, 0) == 10,  "RangeSum(0,0) must be 10 (single element, inclusive)");

    if (g_failures != 0) {
        std::printf("RESULT: %d assertion(s) failed\n", g_failures);
        return 1;
    }
    std::printf("RESULT: all assertions passed\n");
    return 0;
}
