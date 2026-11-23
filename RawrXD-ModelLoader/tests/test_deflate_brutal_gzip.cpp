#include "gzip_stored_validator.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <random>
#include <algorithm>

extern "C" void* deflate_brutal_masm(const void*, std::size_t, std::size_t*);

static bool runCase(std::size_t size, bool repetitive) {
    std::vector<std::uint8_t> input(size);
    if (repetitive) {
        for (std::size_t i = 0; i < size; ++i)
            input[i] = static_cast<std::uint8_t>((i / 31) & 7);
    } else {
        std::mt19937 rng(0xC0FFEEu + static_cast<std::uint32_t>(size));
        for (auto& value : input) value = static_cast<std::uint8_t>(rng());
    }

    std::size_t outputSize = 0;
    void* output = deflate_brutal_masm(
        input.empty() ? nullptr : input.data(), input.size(), &outputSize);
    if (!output) return false;
    const bool valid = rawrxd_test::validateStoredGzip(
        static_cast<const std::uint8_t*>(output), outputSize,
        input.empty() ? nullptr : input.data(), input.size());
    if (valid && outputSize >= 8) {
        auto* bytes = static_cast<std::uint8_t*>(output);
        const auto original = bytes[outputSize - 8];
        bytes[outputSize - 8] ^= 0x80;
        const bool corruptRejected = !rawrxd_test::validateStoredGzip(
            bytes, outputSize, input.empty() ? nullptr : input.data(), input.size());
        bytes[outputSize - 8] = original;
        std::free(output);
        return corruptRejected;
    }
    std::free(output);
    return false;
}

int main() {
    const struct { std::size_t size; bool repetitive; } cases[] = {
        {0, false}, {1, false}, {31, true}, {65535, false},
        {65536, true}, {131071, false}, {1048576, false},
        {1048576, true}
    };
    for (const auto& item : cases) {
        if (!runCase(item.size, item.repetitive)) {
            std::fprintf(stderr, "FAIL gzip stored roundtrip size=%zu repetitive=%d\n",
                         item.size, item.repetitive ? 1 : 0);
            return 1;
        }
    }
    std::puts("BRUTAL_MASM_GZIP_ROUNDTRIP=PASS");
    std::puts("BRUTAL_MASM_GZIP_CORRUPTION=PASS");
    std::puts("BRUTAL_MASM_GZIP_EMPTY_INPUT=PASS");
    std::puts("BRUTAL_MASM_GZIP_BOUNDARY_SIZES=PASS");
    return 0;
}
