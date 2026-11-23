#include "codec/chunked_resident_bytes.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <vector>
int main() {
    std::vector<std::uint8_t> original(1024 * 1024, 0x5a);
    for (std::size_t i = 0; i < original.size(); i += 4096)
        original[i] = static_cast<std::uint8_t>(i / 4096);
    rawrxd::compression::ChunkedResidentBytes resident;
    const auto status = resident.assign(original.data(), original.size(), 4096);
#ifdef RAWRXD_TEST_REQUIRE_ZLIB
    assert(status == rawrxd::compression::Status::Ok);
#else
    if (status == rawrxd::compression::Status::Unsupported) return 0;
    assert(status == rawrxd::compression::Status::Ok);
#endif
    assert(resident.blockCount() == 256);
    assert(resident.peakDecodeBlockBytes() == 4096);
    assert(resident.compressedBytes() < original.size());
    std::vector<std::uint8_t> part(7777);
    assert(resident.read(4000, part.data(), part.size()) == rawrxd::compression::Status::Ok);
    for (std::size_t i = 0; i < part.size(); ++i)
        assert(part[i] == original[4000 + i]);
    assert(resident.read(original.size() - 1, part.data(), 2) ==
           rawrxd::compression::Status::InvalidInput);
    std::vector<std::uint8_t> whole(original.size());
    assert(resident.read(0, whole.data(), whole.size()) == rawrxd::compression::Status::Ok);
    assert(whole == original);
    return 0;
}
