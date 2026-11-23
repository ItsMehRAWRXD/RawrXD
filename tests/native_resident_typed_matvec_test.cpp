#include "native_resident_typed_matvec.hpp"
#include "../src/TensorView.hpp"
#include <limits>
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

    // GGUF byte geometry must describe real packed storage before the ROM
    // reader can safely stream a quantized tensor into compressed residency.
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q4_0) == 18);
    CHECK(deep2::tensorStorageBytes(64, deep2::TensorType::Q4_0) == 36);
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q4_1) == 20);
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q5_0) == 22);
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q5_1) == 24);
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q8_0) == 34);
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q8_1) == 40);
    CHECK(deep2::tensorTypeBytesPerValue(deep2::TensorType::Q8_1) == 1.25);
    CHECK(deep2::tensorStorageBytes((std::numeric_limits<std::uint64_t>::max)(),
                                    deep2::TensorType::F32) ==
          (std::numeric_limits<std::uint64_t>::max)());

    // Row-only reads return the selected F32 row from compressed backing.
    {
        const float matrix[] = {1.f,2.f,3.f,4.f,5.f,6.f,7.f,8.f};
        std::vector<std::uint8_t> bytes(sizeof(matrix));
        std::memcpy(bytes.data(), matrix, sizeof(matrix));
        auto tensor = load_bytes(bytes, path, 12);
        const auto row = resident_f32_row(tensor, 1, 2, 4, 8);
        CHECK(row.size() == 4);
        CHECK(row[0] == 5.f && row[1] == 6.f && row[2] == 7.f && row[3] == 8.f);
    }

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
        const auto row = resident_f16_row(tensor, 1, 2, 4, 4);
        CHECK(row.size() == 4 && row[0] == 2.f && row[1] == 3.f &&
              row[2] == 4.f && row[3] == 5.f);
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
        const auto row = resident_q8_0_row(tensor, 1, 2, 32, 34);
        CHECK(row.size() == 32);
        for (float value : row) CHECK(value == -1.f);
    }

    // Q4_0: scale=1, packed low/high nibbles encode +1 and +2 respectively.
    {
        std::vector<std::uint8_t> bytes(2 * 18);
        for (std::size_t row = 0; row < 2; ++row) {
            bytes[row * 18] = 0x00; bytes[row * 18 + 1] = 0x3c;
            const std::uint8_t q = static_cast<std::uint8_t>(row ? 0xAAu : 0x99u);
            for (std::size_t i = 0; i < 16; ++i) bytes[row * 18 + 2 + i] = q;
        }
        auto tensor = load_bytes(bytes, path, 9);
        const auto y = resident_q4_0_matvec(tensor, ones, 2, 32, 18);
        CHECK(y.size() == 2);
        CHECK(std::fabs(y[0] - 32.f) < 1e-6f);
        CHECK(std::fabs(y[1] - 64.f) < 1e-6f);
        const auto row = resident_q4_0_row(tensor, 1, 2, 32, 18);
        CHECK(row.size() == 32);
        for (float value : row) CHECK(value == 2.f);
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
