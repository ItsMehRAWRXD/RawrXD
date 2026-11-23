#include "native_resident_f16_matvec.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " #x " line " << __LINE__ << '\n'; return 1; } } while (0)
int main() {
    using namespace rawrxd::compression;
    const char* path = "resident_f16_matvec_test.bin";
    // 3 x 5, intentionally odd row width and chunk boundaries.
    const std::uint16_t h[] = {
        0x3c00,0x4000,0xbc00,0x3800,0x0000,
        0x4000,0x4000,0x4000,0x4000,0x4000,
        0x0000,0x0000,0x0000,0x0000,0x3c00
    };
    { std::ofstream out(path, std::ios::binary);
      for (auto v : h) { out.put(static_cast<char>(v & 255)); out.put(static_cast<char>(v >> 8)); } }
    ResidentCompressedTensor resident(7);
    { FileTensorReader reader(path, 0, sizeof(h)); resident.load(reader); }
    std::remove(path);
    const float x[] = {1,2,3,4,5};
    const auto y = resident_f16_matvec(resident,x,3,5,6);
    CHECK(y.size()==3);
    CHECK(y[0]==4.0f); // 1 + 4 - 3 + 2
    CHECK(y[1]==30.0f);
    CHECK(y[2]==5.0f);
    bool rejected=false;
    try { (void)resident_f16_matvec(resident,x,3,6,6); }
    catch (const std::invalid_argument&) { rejected=true; }
    CHECK(rejected);
    rejected=false;
    try { (void)resident_f16_matvec(resident,x,3,5,1); }
    catch (const std::invalid_argument&) { rejected=true; }
    CHECK(rejected);
    return 0;
}
