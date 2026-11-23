#pragma once
// Adapter that binds the lazy compressed page cache directly to TensorROM.
// Keep TensorROM and its TensorEntry alive for the lifetime of this view.
// A caller can pass readRange()'s destination directly to its existing
// CPU/Vulkan staging path; only the requested pages are expanded.
#include "CompressedTensorPager.hpp"
#include "TensorROM.hpp"

namespace deep2 {
class TensorROMCompressedView {
public:
    TensorROMCompressedView(const TensorROM& rom, const TensorEntry& tensor,
                            std::size_t pageSize=256*1024,
                            std::size_t compressedBudget=64*1024*1024)
        : rom_(rom), tensor_(tensor),
          pager_(tensor.byteSize(),
                 [&rom,&tensor](uint64_t offset,uint64_t size,uint8_t* out) {
                     return rom.readTensorRange(tensor,offset,size,out);
                 }, pageSize, compressedBudget) {}
    bool readRange(uint64_t offset,uint64_t size,uint8_t* out) {
        return pager_.read(offset,size,out);
    }
    CompressedTensorPager::Stats stats() const { return pager_.stats(); }
    void clear() { pager_.clear(); }
    uint64_t tensorBytes() const { return tensor_.byteSize(); }
private:
    const TensorROM& rom_;
    const TensorEntry& tensor_;
    CompressedTensorPager pager_;
};
} // namespace deep2
