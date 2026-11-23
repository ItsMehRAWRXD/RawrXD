#include <algorithm>
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
    CHECK(deep2::tensorStorageBytes(32, deep2::TensorType::Q8_1) == 36);
    CHECK(deep2::tensorTypeBytesPerValue(deep2::TensorType::Q8_1) == 1.125);
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

    // BF16 uses the upper 16 bits of IEEE F32, not the IEEE F16 exponent
    // layout. Exercise both compressed matrix-vector and one-row decoding.
    {
        const std::vector<std::uint8_t> bytes = {
            0x80,0x3f, 0x00,0x40, 0x40,0x40, 0x80,0x40,
            0x80,0xbf, 0x00,0x3f, 0x00,0x00, 0x00,0x40
        };
        auto tensor = load_bytes(bytes, path, 4);
        const auto y = resident_bf16_matvec(tensor, x4, 2, 4, 4);
        CHECK(y.size() == 2);
        CHECK(std::fabs(y[0] - 30.f) < 1e-6f);
        CHECK(std::fabs(y[1] - 8.f) < 1e-6f);
        const auto row = resident_bf16_row(tensor, 1, 2, 4, 4);
        CHECK(row.size() == 4 && row[0] == -1.f && row[1] == 0.5f &&
              row[2] == 0.f && row[3] == 2.f);
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

    // Q4_1: affine 4-bit values, x = q*d + m.
    {
        std::vector<std::uint8_t> bytes(20, 0x11);
        bytes[0] = 0x00; bytes[1] = 0x3c; // d = 1
        bytes[2] = 0x00; bytes[3] = 0x00; // m = 0
        auto tensor = load_bytes(bytes, path, 10);
        const auto y = resident_q4_1_matvec(tensor, ones, 1, 32, 20);
        CHECK(y.size() == 1 && y[0] == 32.f);
        const auto row = resident_q4_1_row(tensor, 0, 1, 32, 20);
        for (float value : row) CHECK(value == 1.f);
    }

    // Q5_0: qh supplies the fifth bit; all codes are 25, centered at 16.
    {
        std::vector<std::uint8_t> bytes(22, 0x99);
        bytes[0] = 0x00; bytes[1] = 0x3c;
        for (std::size_t i = 2; i < 6; ++i) bytes[i] = 0xff;
        auto tensor = load_bytes(bytes, path, 11);
        const auto y = resident_q5_0_matvec(tensor, ones, 1, 32, 22);
        CHECK(y.size() == 1 && y[0] == 288.f);
        const auto row = resident_q5_0_row(tensor, 0, 1, 32, 22);
        for (float value : row) CHECK(value == 9.f);
    }

    // Q5_1: affine 5-bit values, q=1, d=1, m=2.
    {
        std::vector<std::uint8_t> bytes(24, 0x11);
        bytes[0] = 0x00; bytes[1] = 0x3c;
        bytes[2] = 0x00; bytes[3] = 0x40;
        for (std::size_t i = 4; i < 8; ++i) bytes[i] = 0;
        auto tensor = load_bytes(bytes, path, 12);
        const auto y = resident_q5_1_matvec(tensor, ones, 1, 32, 24);
        CHECK(y.size() == 1 && y[0] == 96.f);
        const auto row = resident_q5_1_row(tensor, 0, 1, 32, 24);
        for (float value : row) CHECK(value == 3.f);
    }

    // Q8_1: fp16 d, fp16 precomputed sum, then 32 signed bytes (36-byte block).
    {
        std::vector<std::uint8_t> bytes(36, 1);
        bytes[0] = 0x00; bytes[1] = 0x3c; // d = 1
        bytes[2] = 0x00; bytes[3] = 0x00; // s = 0
        auto tensor = load_bytes(bytes, path, 18);
        const auto y = resident_q8_1_matvec(tensor, ones, 1, 32, 36);
        CHECK(y.size() == 1 && y[0] == 32.f);
        const auto row = resident_q8_1_row(tensor, 0, 1, 32, 36);
        for (float value : row) CHECK(value == 1.f);
    }


    // K-quants are 256-value superblocks. These fixtures encode an exact
    // constant-one block so each decoder can be checked against a scalar sum.
    CHECK(deep2::tensorStorageBytes(256, deep2::TensorType::Q2_K) == 84);
    CHECK(deep2::tensorStorageBytes(256, deep2::TensorType::Q3_K) == 110);
    CHECK(deep2::tensorStorageBytes(256, deep2::TensorType::Q4_K) == 144);
    CHECK(deep2::tensorStorageBytes(256, deep2::TensorType::Q5_K) == 176);
    CHECK(deep2::tensorStorageBytes(256, deep2::TensorType::Q6_K) == 210);
    const float ones256[256] = {
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
    };
    {
        std::vector<std::uint8_t> bytes(84, 0);
        std::fill(bytes.begin(), bytes.begin() + 16, 0x01); // scale=1,min=0
        std::fill(bytes.begin() + 16, bytes.begin() + 80, 0x55); // q=1
        bytes[80] = 0x00; bytes[81] = 0x3c; // d=1
        auto tensor = load_bytes(bytes, path, 21);
        const auto y = resident_q2_k_matvec(tensor, ones256, 1, 256, 84);
        CHECK(y.size() == 1 && std::fabs(y[0] - 256.f) < 1e-5f);
        const auto row = resident_k_row<84, resident_k_detail::decode_q2>(tensor, 0, 1, 256, 21);
        CHECK(row.size() == 256 && std::all_of(row.begin(), row.end(), [](float v) { return std::fabs(v - 1.0f) < 1e-5f; }));
    }
    {
        std::vector<std::uint8_t> bytes(110, 0);
        std::fill(bytes.begin(), bytes.begin() + 32, 0xff); // high bit set: q=1
        std::fill(bytes.begin() + 32, bytes.begin() + 96, 0x55); // low q=1
        for (std::size_t i = 0; i < 8; ++i) bytes[96 + i] = 0x11; // biased scale 33
        std::fill(bytes.begin() + 104, bytes.begin() + 108, 0xaa); // upper scale bits
        bytes[108] = 0x00; bytes[109] = 0x3c; // d=1
        auto tensor = load_bytes(bytes, path, 22);
        const auto y = resident_q3_k_matvec(tensor, ones256, 1, 256, 110);
        CHECK(y.size() == 1 && std::fabs(y[0] - 256.f) < 1e-5f);
        const auto row = resident_k_row<110, resident_k_detail::decode_q3>(tensor, 0, 1, 256, 22);
        CHECK(row.size() == 256 && std::all_of(row.begin(), row.end(), [](float v) { return std::fabs(v - 1.0f) < 1e-5f; }));
    }
    {
        std::vector<std::uint8_t> bytes(144, 0);
        bytes[0] = 0x00; bytes[1] = 0x3c; // d=1, dmin=0
        for (std::size_t i = 0; i < 4; ++i) bytes[4 + i] = 1;
        for (std::size_t i = 8; i < 12; ++i) bytes[4 + i] = 1;
        std::fill(bytes.begin() + 16, bytes.end(), 0x11);
        auto tensor = load_bytes(bytes, path, 24);
        const auto y = resident_q4_k_matvec(tensor, ones256, 1, 256, 144);
        CHECK(y.size() == 1 && std::fabs(y[0] - 256.f) < 1e-5f);
        const auto row = resident_k_row<144, resident_k_detail::decode_q4>(tensor, 0, 1, 256, 24);
        CHECK(row.size() == 256 && std::all_of(row.begin(), row.end(), [](float v) { return std::fabs(v - 1.0f) < 1e-5f; }));
    }
    {
        std::vector<std::uint8_t> bytes(176, 0);
        bytes[0] = 0x00; bytes[1] = 0x3c; // d=1, dmin=0
        for (std::size_t i = 0; i < 4; ++i) bytes[4 + i] = 1;
        for (std::size_t i = 8; i < 12; ++i) bytes[4 + i] = 1;
        std::fill(bytes.begin() + 48, bytes.end(), 0x11);
        auto tensor = load_bytes(bytes, path, 32);
        const auto y = resident_q5_k_matvec(tensor, ones256, 1, 256, 176);
        CHECK(y.size() == 1 && std::fabs(y[0] - 256.f) < 1e-5f);
        const auto row = resident_k_row<176, resident_k_detail::decode_q5>(tensor, 0, 1, 256, 32);
        CHECK(row.size() == 256 && std::all_of(row.begin(), row.end(), [](float v) { return std::fabs(v - 1.0f) < 1e-5f; }));
    }
    {
        std::vector<std::uint8_t> bytes(210, 0);
        std::fill(bytes.begin(), bytes.begin() + 128, 0x11); // low nibbles=1
        std::fill(bytes.begin() + 128, bytes.begin() + 192, 0xaa); // upper bits=2
        std::fill(bytes.begin() + 192, bytes.begin() + 208, 1); // subscales=1
        bytes[208] = 0x00; bytes[209] = 0x3c; // d=1
        auto tensor = load_bytes(bytes, path, 35);
        const auto y = resident_q6_k_matvec(tensor, ones256, 1, 256, 210);
        CHECK(y.size() == 1 && std::fabs(y[0] - 256.f) < 1e-5f);
        const auto row = resident_k_row<210, resident_k_detail::decode_q6>(tensor, 0, 1, 256, 35);
        CHECK(row.size() == 256 && std::all_of(row.begin(), row.end(), [](float v) { return std::fabs(v - 1.0f) < 1e-5f; }));
    }

    CHECK(deep2::tensorStorageBytes(256, deep2::TensorType::Q8_K) == 292);
    {
        std::vector<std::uint8_t> bytes(292, 0);
        const float scale = 1.0f;
        std::memcpy(bytes.data(), &scale, sizeof(scale));
        std::fill(bytes.begin() + 4, bytes.begin() + 260, 1);
        auto tensor = load_bytes(bytes, path, 73);
        const auto y = resident_q8_k_matvec(tensor, ones256, 1, 256, 292);
        CHECK(y.size() == 1 && std::fabs(y[0] - 256.f) < 1e-5f);
        const auto row = resident_q8_k_row(tensor, 0, 1, 256, 292);
        CHECK(row.size() == 256);
        for (float value : row) CHECK(value == 1.0f);
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
