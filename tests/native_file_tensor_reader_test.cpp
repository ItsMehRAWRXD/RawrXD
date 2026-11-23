#include "native_file_tensor_reader.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL: " #x << " at " << __LINE__ << '\\n'; return EXIT_FAILURE; } } while (false)
int main() {
    using namespace rawrxd::compression;
    const char* path = "native_file_tensor_reader_test.bin";
    std::vector<std::uint8_t> input(8193, 0x55);
    input[0] = 7; input[8192] = 9;
    { std::ofstream f(path, std::ios::binary); f.put('X'); f.write(reinterpret_cast<const char*>(input.data()), input.size()); }
    std::vector<std::uint8_t> output;
    {
        FileTensorReader reader(path, 1, input.size());
        reader.for_each_compressed_block(1024, [&](std::uint64_t offset, const Block& block) {
            (void)offset;
            auto bytes = decode(block);
            output.insert(output.end(), bytes.begin(), bytes.end());
        });
    }
    std::remove(path);
    CHECK(output == input);
    return EXIT_SUCCESS;
}
