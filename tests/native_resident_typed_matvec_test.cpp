#include "native_resident_typed_matvec.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "CHECK failed at %d: %s\n", __LINE__, #x); std::abort(); } } while (0)

static rawrxd::compression::ResidentCompressedTensor load_bytes(
    const std::vector<std::uint8_t>& bytes, const char* path, std::size_t blockBytes) {
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        CHECK(bool(out));
        if (!bytes.empty())
            out.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        CHECK(bool(out));
    }
    rawrxd::compression::FileTensorReader file(path, 0, bytes.size());
    rawrxd::compression::ResidentCompressedTensor tensor(blockBytes);
    tensor.load(file);
    return tensor;
}

int main() {
    using namespace rawrxd::compression;
    const char* path = "native_resident_typed_matvec_fixture.bin";
    const float x4[] = {1.f, 2.f, 3.f, 4.f};

    // F16 values: [1,2,3,4] and [2,3,4,5].
    {
        const std::vector<std::uint8_t> bytes = {
            0x00,0x3c, 0x00,0x40, 0x00,0x42, 0x00,0x44,
            0x00,0x40, 0x00,0x42, 0x00,0x44, 0x00,0x45
        };
        auto tensor = load_bytes(bytes, path, 5);
        const auto y = resident_f16_matvec(tensor, x4, 2, 4, 6);
        CHECK(y.size() == 2);
        CHECK(std::fabs(y[0] - 30.f) < 1e-6f);
        CHECK(std::fabs(y[1] - 40.f) < 1e-6f);
    }

    const float ones[32] = {
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
    };

    // Q8_0: half scale 1.0 followed by 32 signed quantized values.
    {
        std::vector<std::uint8_t> bytes(2 * 34);
        for (std::size_t row = 0; row < 2; ++row) {
            bytes[row * 34] = 0x00; bytes[row * 34 + 1] = 0x3c;
            for (std::size_t i = 0; i < 32; ++i)
                bytes[row * 34 + 2 + i] = static_cast<std::uint8_t>(row ? -1 : 1);
        }
        auto tensor = load_bytes(bytes, path, 17);
        const auto y = resident_q8_0_matvec(tensor, ones, 2, 32, 34);
        CHECK(y.size() == 2);
        CHECK(std::fabs(y[0] - 32.f) < 1e-6f);
        CHECK(std::fabs(y[1] + 32.f) < 1e-6f);
    }

    // Q4_0: scale=1, packed low/high nibbles encode +1 and +2 respectively.
    {
        std::vector<std::uint8_t> bytes(2 * 18);
        for (std::size_t row = 0; row < 2; ++row) {
            bytes[row * 18] = 0x00; bytes[row * 18 + 1] = 0x3c;
            const std::uint8_t q = row ? 0xAAu : 0x99u;
            for (std::size_t i = 0; i < 16; ++i) bytes[row * 18 + 2 + i] = q;
        }
        auto tensor = load_bytes(bytes, path, 9);
        const auto y = resident_q4_0_matvec(tensor, ones, 2, 32, 18);
        CHECK(y.size() == 2);
        CHECK(std::fabs(y[0] - 32.f) < 1e-6f);
        CHECK(std::fabs(y[1] - 64.f) < 1e-6f);
    }

    bool rejected = false;
    try {
        std::vector<std::uint8_t> bytes(18, 0);
        auto tensor = load_bytes(bytes, path, 18);
        (void)resident_q4_0_matvec(tensor, ones, 1, 32, 17);
    } catch (const std::invalid_argument&) { rejected = true; }
    CHECK(rejected);
    CHECK(std::remove(path) == 0);
    return 0;
}
