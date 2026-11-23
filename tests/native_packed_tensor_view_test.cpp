#include "../include/native_packed_tensor_view.hpp"
#include <cassert>
#include <cstdint>
#include <stdexcept>
using RawrXD::Compression::PackedTensorView;
int main() {
    uint8_t packed[36] = {};
    packed[18] = 77;
    PackedTensorView v{packed, sizeof(packed), 64, 32, 18};
    assert(v.block_count() == 2 && v.block(1)[0] == 77);
    uint64_t seen = 0;
    v.visit(0, 2, [&](uint64_t index, const uint8_t* ptr, uint32_t size) {
        assert(ptr == packed + index * 18 && size == 18);
        ++seen;
    });
    assert(seen == 2);
    bool rejected = false;
    try { v.block(2); } catch (const std::out_of_range&) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { PackedTensorView{packed, 17, 64, 32, 18}.block_count(); }
    catch (const std::out_of_range&) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { PackedTensorView{packed, 36, 33, 32, 18}.block_count(); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
}
