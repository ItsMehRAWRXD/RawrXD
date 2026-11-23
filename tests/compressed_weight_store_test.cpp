#include "../src/core/CompressedWeightStore.hpp"
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    using rawrxd::memory::CompressedWeightStore;
    std::vector<std::uint8_t> source(1024 * 3 + 17);
    for (std::size_t i = 0; i < source.size(); ++i)
        source[i] = (i / 97) % 5 == 0 ? 0 : static_cast<std::uint8_t>((i * 31) & 0xff);

    auto store = CompressedWeightStore::Build(source.data(), source.size(), 1024, 2048);
    assert(store->SizeBytes() == source.size());
    assert(store->PageCount() == 4);

    std::vector<std::uint8_t> recovered(source.size());
    assert(store->ReadRange(0, recovered.data(), recovered.size()));
    assert(recovered == source);

    std::vector<std::uint8_t> slice(777);
    assert(store->ReadRange(900, slice.data(), slice.size()));
    for (std::size_t i = 0; i < slice.size(); ++i)
        assert(slice[i] == source[900 + i]);

    assert(!store->ReadRange(source.size(), slice.data(), 1));
    assert(!store->AcquirePage(store->PageCount()));

    auto pinned = store->AcquirePage(0);
    assert(pinned && pinned->size() == 1024);
    const auto stats = store->GetStats();
    assert(stats.logical_bytes == source.size());
    assert(stats.compressed_bytes <= source.size() + 32);
    return 0;
}
