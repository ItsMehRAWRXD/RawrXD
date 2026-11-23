#include "native_resident_f32_matvec.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <vector>
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr,"CHECK failed at %d: %s\n",__LINE__,#x); std::abort(); } } while(0)
int main() {
    using namespace rawrxd::compression;
    const char* path = "native_resident_matvec_fixture.bin";
    const float matrix[] = {1.f,2.f,3.f,4.f,5.f,6.f,7.f,8.f,9.f,10.f,11.f,12.f};
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        CHECK(bool(out));
        out.write(reinterpret_cast<const char*>(matrix), sizeof(matrix));
        CHECK(bool(out));
    }
    try {
        FileTensorReader file(path, 0, sizeof(matrix));
        ResidentCompressedTensor tensor(8);
        tensor.load(file);
        const float x[] = {1.f,2.f,3.f,4.f};
        auto y = resident_f32_matvec(tensor, x, 3, 4, 8);
        CHECK(y.size() == 3);
        CHECK(std::fabs(y[0] - 30.f) < 1e-5f);
        CHECK(std::fabs(y[1] - 70.f) < 1e-5f);
        CHECK(std::fabs(y[2] - 110.f) < 1e-5f);
        CHECK(tensor.block_count() == 6);
        CHECK(tensor.size() == sizeof(matrix));
        bool rejected = false;
        try { (void)resident_f32_matvec(tensor, x, 3, 5, 8); }
        catch (const std::invalid_argument&) { rejected = true; }
        CHECK(rejected);
        rejected = false;
        try { (void)resident_f32_matvec(tensor, x, 3, 4, 3); }
        catch (const std::invalid_argument&) { rejected = true; }
        CHECK(rejected);
    } catch (...) { std::remove(path); throw; }
    CHECK(std::remove(path) == 0);
    return 0;
}
