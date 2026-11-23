#include "native_resident_compressed_tensor.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " #x << " at " << __LINE__ << "\n"; return EXIT_FAILURE; } } while (false)
int main() {
    using namespace rawrxd::compression;
    const char* path = "resident_compressed_tensor_test.bin";
    std::vector<std::uint8_t> original(131073, 0x55);
    original[0] = 0x12; original[65536] = 0x34; original.back() = 0x56;
    { std::ofstream f(path, std::ios::binary); f.put('!'); f.write(reinterpret_cast<const char*>(original.data()), original.size()); }
    ResidentCompressedTensor tensor(4096);
    { FileTensorReader source(path, 1, original.size()); tensor.load(source); }
    std::remove(path);
    CHECK(tensor.size() == original.size());
    CHECK(tensor.compressed_bytes() < original.size());
    CHECK(tensor.resident_bytes() >= tensor.compressed_bytes());
    CHECK(tensor.resident_bytes() > 0);
    std::vector<std::uint8_t> slice(9000);
    tensor.read(62000, slice.data(), slice.size());
    CHECK(std::equal(slice.begin(), slice.end(), original.begin() + 62000));
    // Exercise tiny unaligned reads through both RLE and raw block paths.
    for (std::size_t offset : {std::size_t(0), std::size_t(1),
                               std::size_t(4095), std::size_t(4096),
                               std::size_t(65535), std::size_t(65536),
                               original.size() - 1}) {
        std::uint8_t value = 0;
        tensor.read(offset, &value, 1);
        CHECK(value == original[offset]);
    }
    // Incompressible data must use raw blocks, also without full-block copies.
    std::vector<std::uint8_t> raw(4096);
    for (std::size_t i = 0; i < raw.size(); ++i)
        raw[i] = static_cast<std::uint8_t>(i % 251);
    { std::ofstream f(path, std::ios::binary | std::ios::trunc);
      f.write(reinterpret_cast<const char*>(raw.data()), raw.size()); }
    ResidentCompressedTensor rawTensor(4096);
    { FileTensorReader source(path, 0, raw.size()); rawTensor.load(source); }
    std::remove(path);
    CHECK(rawTensor.compressed_bytes() == raw.size());
    std::uint8_t small[3] = {};
    rawTensor.read(251, small, 3);
    CHECK(std::equal(small, small + 3, raw.begin() + 251));
    // General compression path: repeated 251-byte structure is not RLE-friendly.
    std::vector<std::uint8_t> structured(32768);
    for (std::size_t i = 0; i < structured.size(); ++i)
        structured[i] = static_cast<std::uint8_t>((i % 251u) ^ ((i / 251u) & 7u));
    { std::ofstream f(path, std::ios::binary | std::ios::trunc);
      f.write(reinterpret_cast<const char*>(structured.data()), structured.size()); }
    ResidentCompressedTensor lz4Tensor(32768);
    { FileTensorReader source(path, 0, structured.size()); lz4Tensor.load(source); }
    std::remove(path);
    CHECK(lz4Tensor.compressed_bytes() < structured.size());
    std::vector<std::uint8_t> lz4Slice(8193);
    lz4Tensor.read(12001, lz4Slice.data(), lz4Slice.size());
    CHECK(std::equal(lz4Slice.begin(), lz4Slice.end(), structured.begin() + 12001));

    bool rejected = false;
    try { tensor.read(original.size() - 1, slice.data(), slice.size()); }
    catch (const std::out_of_range&) { rejected = true; }
    CHECK(rejected);
    return EXIT_SUCCESS;
}
