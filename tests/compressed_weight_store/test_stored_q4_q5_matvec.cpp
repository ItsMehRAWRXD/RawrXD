#include "../../src/deep2/compression/StoredTensorMatvec.hpp"
#include <cmath>
#include <numeric>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace rawrxd::compression;

static bool run(const char* name, ResidentWeightType type,
                std::uint32_t ggmlType, std::vector<std::uint8_t> bytes,
                float expected) {
    CompressedWeightStore store(0, 64);
    std::string error;
    if (!store.addTensor(name, bytes.data(), bytes.size(), &error, ggmlType, false))
        return false;
    std::vector<float> input(32, 1.0f), output(1, 0.0f);
    StoredTensorMatvec(store, name, type, input.data(), output.data(), 1, 32, 1);
    if (std::fabs(output[0] - expected) > 1e-5f) return false;
    std::vector<float> decodedRow(32, 0.0f);
    StoredTensorReadRow(store, name, type, 0, decodedRow.data(), decodedRow.size());
    const float decodedSum = std::accumulate(decodedRow.begin(), decodedRow.end(), 0.0f);
    if (std::fabs(decodedSum - expected) > 1e-5f) return false;
    std::vector<std::uint8_t> restored(bytes.size());
    if (!store.readRange(name, 0, restored.data(), restored.size(), &error) ||
        restored != bytes) return false;
    bool rejected = false;
    try {
        StoredTensorMatvec(store, name, ResidentWeightType::F16,
                           input.data(), output.data(), 1, 32);
    } catch (const std::invalid_argument&) { rejected = true; }
    return rejected;
}

int main() {
    // Q4_1: d=1, m=2; q0=1 and q1=2 across the two nibble lanes.
    std::vector<std::uint8_t> q4_1(20, 0);
    q4_1[0]=0x00; q4_1[1]=0x3c;
    q4_1[2]=0x00; q4_1[3]=0x40;
    for (std::size_t i=0;i<16;++i) q4_1[4+i]=0x21;
    if (!run("q4_1", ResidentWeightType::Q4_1, 3u, q4_1, 112.0f)) return 1;

    // Q5_0: d=1. The low and high qh lanes set bit 4 for columns 0 and 16.
    // q0 becomes 0 after the signed -16 offset; q1 becomes +1.
    std::vector<std::uint8_t> q5_0(22, 0);
    q5_0[0]=0x00; q5_0[1]=0x3c;
    q5_0[2]=0x01; q5_0[4]=0x01;
    for (std::size_t i=0;i<16;++i) q5_0[6+i]=0x10;
    if (!run("q5_0", ResidentWeightType::Q5_0, 6u, q5_0, -464.0f)) return 2;

    // Q5_1: d=1, m=2, same high-bit pattern; affine values are 18 and 19
    // in the selected columns, with 2 and 3 in the remaining columns.
    std::vector<std::uint8_t> q5_1(24, 0);
    q5_1[0]=0x00; q5_1[1]=0x3c;
    q5_1[2]=0x00; q5_1[3]=0x40;
    q5_1[4]=0x01; q5_1[6]=0x01;
    for (std::size_t i=0;i<16;++i) q5_1[8+i]=0x10;
    if (!run("q5_1", ResidentWeightType::Q5_1, 7u, q5_1, 112.0f)) return 3;
    return 0;
}
