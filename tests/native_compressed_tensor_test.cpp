#include "native_compressed_tensor.hpp"
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL: " #x << " at " << __LINE__ << '\\n'; return EXIT_FAILURE; } } while (false)
int main() {
    using rawrxd::compression::CompressedTensor;
    std::vector<std::uint8_t> input(10000, 0x42);
    input[4096] = 0x12;
    input[8192] = 0x34;
    CompressedTensor tensor(1024);
    tensor.assign(input.data(), input.size());
    CHECK(tensor.size() == input.size());
    CHECK(tensor.block_count() == 10);
    CHECK(tensor.stored_bytes() < tensor.size());
    std::vector<std::uint8_t> slice(5000);
    tensor.read(4000, slice.data(), slice.size());
    CHECK(std::equal(slice.begin(), slice.end(), input.begin() + 4000));
    bool rejected = false;
    try { tensor.read(9999, slice.data(), slice.size()); }
    catch (const std::out_of_range&) { rejected = true; }
    CHECK(rejected);
    tensor.assign(nullptr, 0);
    CHECK(tensor.size() == 0);
    CHECK(tensor.block_count() == 0);
    return EXIT_SUCCESS;
}
