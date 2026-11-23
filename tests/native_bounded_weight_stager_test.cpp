#include "native_bounded_weight_stager.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " #x << " at " << __LINE__ << "\n"; return EXIT_FAILURE; } } while (false)
int main() {
    using namespace rawrxd::compression;
    const char* path = "native_bounded_weight_stager_test.bin";
    std::vector<std::uint8_t> original(65539, 0x43);
    original[1000] = 0x11; original[32768] = 0x22;
    { std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(original.data()), original.size()); }
    ResidentCompressedTensor resident(4096);
    { FileTensorReader reader(path, 0, original.size()); resident.load(reader); }
    std::remove(path);
    BoundedWeightStager stager(1024);
    std::vector<std::uint8_t> observed;
    std::size_t chunks = 0;
    stager.for_each_chunk(resident, 99, 65500, [&](std::size_t offset, const std::uint8_t* bytes, std::size_t n) {
        (void)offset;
        observed.insert(observed.end(), bytes, bytes + n);
        ++chunks;
    });
    CHECK(chunks > 1);
    CHECK(std::equal(observed.begin(), observed.end(), original.begin() + 99));
    bool rejected = false;
    try { stager.for_each_chunk(resident, resident.size(), 1, [](std::size_t, const std::uint8_t*, std::size_t){}); }
    catch (const std::out_of_range&) { rejected = true; }
    CHECK(rejected);
    return EXIT_SUCCESS;
}
