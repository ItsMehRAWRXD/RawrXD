#include "../src/CompressedBlockStore.hpp"
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    deep2::CompressedBlockStore store(4096);
    std::vector<std::uint8_t> source(65536, 0x5a);
    for (std::size_t i = 0; i < source.size(); i += 4096)
        source[i] = static_cast<std::uint8_t>(i / 4096);
    store.assign(source.data(), source.size());
    assert(store.blockCount() == 16);
    assert(store.residentBytes() < store.originalBytes());
    std::vector<std::uint8_t> out(9000);
    assert(store.read(3000, out.size(), out.data()));
    for (std::size_t i = 0; i < out.size(); ++i)
        assert(out[i] == source[3000 + i]);
    assert(!store.read(source.size() - 1, 2, out.data()));
    assert(!store.read(0, 1, nullptr));
    assert(store.read(source.size(), 0, nullptr));
    store.assign(nullptr, 0);
    assert(store.blockCount() == 0);
    assert(store.read(0, 0, nullptr));
}
