#pragma once
// Opt-in K2 shard index + ROM Pinball bridge adapter. No Qt, no new dependencies.
#include "ReapRomPinballBridge.hpp"
#include "../K2GlobalTensorIndex.hpp"
#include "../K2ShardIo.hpp"
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace Deep2::ReapRom {
inline Slice ResolveExpert(const GlobalTensorIndex& index,
                           const std::string& tensorName,
                           uint32_t layer, uint32_t expert) {
    const auto ref = index.FindExpertSlice(tensorName, expert);
    if (!ref || !ref->isExpertTensor || ref->layerIndex < 0 ||
        static_cast<uint32_t>(ref->layerIndex) != layer ||
        ref->expertId != expert || !ref->byteSize)
        throw std::invalid_argument("invalid indexed expert");
    const auto& path = index.ShardPath(ref->shardId);
    if (path.empty() || ref->fileOffset >
        std::numeric_limits<uint64_t>::max() - ref->byteOffset)
        throw std::invalid_argument("invalid expert shard offset");
    const uint64_t absolute = ref->fileOffset + ref->byteOffset;
    const uint64_t fileSize = std::filesystem::file_size(path);
    if (absolute > fileSize || ref->byteSize > fileSize - absolute)
        throw std::out_of_range("expert slice beyond shard");
    return Slice{path.string(), absolute, ref->byteSize, layer, expert, ref->ggmlType};
}
inline Read NativeK2Read() {
    return [](const std::string& path, uint64_t offset, void* dst, size_t bytes) {
        return K2ShardIo_Read(path, offset, dst, bytes);
    };
}
// A DeepSeek expert has distinct gate/up/down projections.
// Bridge keys (layer,expert) alone are not sufficient for three projections.
// Use one Bridge instance per projection until a projection-aware key is adopted.
} // namespace Deep2::ReapRom
