#include "codec/resident_f32_matvec.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>
int main() {
    constexpr std::size_t rows = 64, cols = 256;
    std::vector<float> matrix(rows * cols);
    std::vector<float> input(cols);
    for (std::size_t c = 0; c < cols; ++c) input[c] = float(int(c % 7) - 3) / 7.0f;
    for (std::size_t i = 0; i < matrix.size(); ++i)
        matrix[i] = float(int(i % 11) - 5) / 11.0f;
    rawrxd::compression::ChunkedResidentBytes resident;
    auto status = resident.assign(reinterpret_cast<const std::uint8_t*>(matrix.data()),
                                  matrix.size() * sizeof(float), 1024);
#ifndef RAWRXD_TEST_REQUIRE_ZLIB
    if (status == rawrxd::compression::Status::Unsupported) return 0;
#endif
    assert(status == rawrxd::compression::Status::Ok);
    assert(resident.compressedBytes() < matrix.size() * sizeof(float));
    std::vector<float> actual(rows), reference(rows);
    assert(rawrxd::compression::residentF32Matvec(resident, rows, cols,
                                                   input.data(), actual.data()) ==
           rawrxd::compression::Status::Ok);
    for (std::size_t r = 0; r < rows; ++r) {
        float sum = 0;
        for (std::size_t c = 0; c < cols; ++c) sum += matrix[r * cols + c] * input[c];
        reference[r] = sum;
        assert(std::fabs(actual[r] - reference[r]) < 1e-5f);
    }
    assert(rawrxd::compression::residentF32Matvec(resident, rows + 1, cols,
                                                   input.data(), actual.data()) ==
           rawrxd::compression::Status::InvalidInput);
    return 0;
}
