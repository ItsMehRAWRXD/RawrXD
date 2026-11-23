#include "../../~dev/rawrxd/src/deep2/GGUFLoader.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>

int main() {
    struct Expected { uint32_t type; size_t elements; size_t bytes; };
    const Expected expected[] = {
        {10,256,84}, {11,256,110}, {12,256,144},
        {13,256,176}, {14,256,210}
    };
    for(const auto& e: expected) {
        size_t elems=0,bytes=0;
        assert(Deep2::GGUFLoader::typeGeometry(e.type,elems,bytes));
        assert(elems==e.elements);
        assert(bytes==e.bytes);
    }
    size_t elems=0,bytes=0;
    assert(!Deep2::GGUFLoader::typeGeometry(31,elems,bytes));
    std::cout<<"Deep2 GGUF loader recognizes standard Q2_K-Q6_K wire geometry\n";
}
