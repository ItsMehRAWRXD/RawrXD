// c++ -std=c++17 -O2 -I. tests/tensor_weight_storage_test.cpp -lz -o storage_test
#include "src/deep2/TensorWeightStorage.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>
using namespace rawrxd::weights;
static bool fails(const std::vector<uint8_t>& bytes) {
    try { (void)deserialize(bytes); return false; }
    catch (const std::runtime_error&) { return true; }
}
int main() {
    std::mt19937 rng(20261123);
    for (size_t n : {size_t(0), size_t(1), size_t(4096), size_t(65537)}) {
        std::vector<uint8_t> original(n);
        for (auto& x:original) x=static_cast<uint8_t>(rng());
        auto encoded=encode(original.data(),original.size(),4,4096);
        auto wire=serialize(encoded);
        auto restored=deserialize(wire);
        assert(decode_range(restored,0,n)==original);
        auto truncated=wire;
        truncated.pop_back();
        assert(fails(truncated));
        auto trailing=wire;
        trailing.push_back(0);
        assert(fails(trailing));
        auto bad_magic=wire;
        bad_magic[0]^=1;
        assert(fails(bad_magic));
        std::cout << "roundtrip input=" << n << " serialized=" << wire.size() << "\n";
    }
    std::cout << "PASS portable tensor storage roundtrip/invalid inputs\n";
}
