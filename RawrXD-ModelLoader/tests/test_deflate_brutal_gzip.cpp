#include "gzip_stored_validator.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <random>
#include <algorithm>
#include <fstream>
#include "gzip_crc32.h"

#if defined(RAWRXD_BRUTAL_NEON)
extern "C" void* deflate_brutal_neon(const void*, std::size_t, std::size_t*);
#define DEFLATE_BRUTAL deflate_brutal_neon
#else
extern "C" void* deflate_brutal_masm(const void*, std::size_t, std::size_t*);
#define DEFLATE_BRUTAL deflate_brutal_masm
#endif

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
    void* output = DEFLATE_BRUTAL(
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
    const char* crcVector = "123456789";
    if (rawrxd_gzip_crc32(crcVector, 9) != 0xCBF43926u ||
        rawrxd_test::gzipCrc32(
            reinterpret_cast<const std::uint8_t*>(crcVector), 9) != 0xCBF43926u) {
        std::fprintf(stderr, "FAIL IEEE CRC32 known-answer test\n");
        return 1;
    }
    std::size_t invalidLength = 123;
    if (DEFLATE_BRUTAL(nullptr, 1, &invalidLength) != nullptr ||
        invalidLength != 0 || DEFLATE_BRUTAL(nullptr, 0, nullptr) != nullptr) {
        std::fprintf(stderr, "FAIL invalid argument contract\n");
        return 1;
    }
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
    // Emit a deterministic fixture for an independent platform gzip decoder.
    std::vector<std::uint8_t> fixture(1048576);
    for (std::size_t i = 0; i < fixture.size(); ++i)
        fixture[i] = static_cast<std::uint8_t>((i * 131u + (i >> 5u)) & 0xFFu);
    std::size_t fixtureSize = 0;
    void* fixtureGzip = DEFLATE_BRUTAL(
        fixture.data(), fixture.size(), &fixtureSize);
    if (!fixtureGzip) return 1;
    std::ofstream sourceFile("brutal_gzip_fixture.bin", std::ios::binary);
    std::ofstream gzipFile("brutal_gzip_fixture.gz", std::ios::binary);
    sourceFile.write(reinterpret_cast<const char*>(fixture.data()),
                     static_cast<std::streamsize>(fixture.size()));
    gzipFile.write(static_cast<const char*>(fixtureGzip),
                   static_cast<std::streamsize>(fixtureSize));
    sourceFile.flush();
    gzipFile.flush();
    sourceFile.close();
    gzipFile.close();
    const bool filesOk = sourceFile.good() && gzipFile.good();
    std::free(fixtureGzip);
    if (!filesOk) return 1;

    std::puts("BRUTAL_GZIP_ROUNDTRIP=PASS");
    std::puts("BRUTAL_GZIP_CORRUPTION=PASS");
    std::puts("BRUTAL_GZIP_EMPTY_INPUT=PASS");
    std::puts("BRUTAL_GZIP_BOUNDARY_SIZES=PASS");
    std::puts("BRUTAL_GZIP_CRC32_KNOWN_ANSWER=PASS");
    std::puts("BRUTAL_GZIP_INTEROP_FIXTURE=READY");
    return 0;
}
