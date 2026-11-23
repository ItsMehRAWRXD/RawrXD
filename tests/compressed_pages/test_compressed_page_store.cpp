#include "CompressedPageStore.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
int main() {
    deep2::CompressedPageStore store(4096);
    std::vector<std::uint8_t> input(65537, 0x5a);
    assert(store.assign(input.data(), input.size()));
    assert(store.originalBytes() == input.size());
    assert(store.residentBytes() < input.size());
    std::vector<std::uint8_t> out(8193);
    assert(store.read(4000, out.size(), out.data()));
    for (auto v : out) assert(v == 0x5a);
    assert(!store.read(65530, 20, out.data()));
    for (std::size_t i = 0; i < input.size(); ++i)
        input[i] = static_cast<std::uint8_t>((i * 1315423911ULL) >> 17);
    assert(store.assign(input.data(), input.size()));
    std::vector<std::uint8_t> restored(input.size());
    assert(store.read(0, restored.size(), restored.data()));
    assert(restored == input);
    assert(store.read(input.size(), 0, nullptr));
    std::cout << "compressed page residency tests passed\n";
}
