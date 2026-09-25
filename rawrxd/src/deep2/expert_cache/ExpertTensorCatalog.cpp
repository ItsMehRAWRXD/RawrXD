#include "ExpertTensorCatalog.h"
#include <algorithm>
#include <charconv>

namespace rawrxd::deep2 {
namespace {

bool parseUnsignedAt(std::string_view s, size_t pos, uint32_t& out) noexcept {
    if (pos >= s.size() || s[pos] < '0' || s[pos] > '9') return false;
    uint32_t value = 0;
    const char* first = s.data() + pos;
    const char* last = s.data() + s.size();
    auto r = std::from_chars(first, last, value);
    if (r.ec != std::errc{}) return false;
    out = value;
    return true;
}

bool parseAfter(std::string_view s, std::string_view token, uint32_t& out) noexcept {
    const size_t p = s.find(token);
    if (p == std::string_view::npos) return false;
    return parseUnsignedAt(s, p + token.size(), out);
}

} // namespace

bool ExpertTensorCatalog::parseExpertKey(std::string_view name, ExpertKey& outKey) noexcept {
    uint32_t layer = 0;
    bool haveLayer = parseAfter(name, "blk.", layer) || parseAfter(name, "layers.", layer) || parseAfter(name, "layer.", layer);
    if (!haveLayer) return false;

    uint32_t expert = 0;
    bool haveExpert = parseAfter(name, ".experts.", expert) ||
                      parseAfter(name, ".expert.", expert) ||
                      parseAfter(name, "_exps.", expert) ||
                      parseAfter(name, ".exps.", expert);
    if (!haveExpert) return false;

    outKey = ExpertKey{layer, expert};
    return true;
}

bool ExpertTensorCatalog::addForKey(ExpertKey key, const ExpertTensorView& tensor) {
    if (!tensor.data || tensor.bytes == 0) return false;
    auto [it, inserted] = groups_.try_emplace(key);
    auto& g = it->second;
    if (inserted) {
        g.key = key;
        ++stats_.expertsDiscovered;
    }
    g.totalBytes += tensor.bytes;
    g.tensors.push_back(tensor);
    return true;
}

bool ExpertTensorCatalog::addTensor(const ExpertTensorView& tensor) {
    ++stats_.tensorsSeen;
    if (!tensor.data || tensor.bytes == 0) {
        ++stats_.rejectedNull;
        return false;
    }

    ExpertKey key{};
    if (!parseExpertKey(tensor.name, key)) {
        ++stats_.rejectedName;
        return false;
    }

    ++stats_.expertTensorsMatched;
    return addForKey(key, tensor);
}

bool ExpertTensorCatalog::addPackedTensor(const PackedTensorDescriptor& tensor, PackedSliceReceipt* receipt) {
    ++stats_.tensorsSeen;
    ++stats_.packedTensorsSeen;
    std::vector<ExpertTensorSlice> slices;
    PackedSliceReceipt local{};
    if (!PackedExpertSlicer::slice(tensor, slices, &local)) {
        ++stats_.packedRejected;
        if (receipt) *receipt = local;
        return false;
    }

    bool ok = true;
    for (const auto& s : slices) {
        ExpertTensorView view{};
        view.name = tensor.name + "#expert=" + std::to_string(s.expert);
        view.data = s.data;
        view.bytes = s.bytes;
        view.fileOffset = s.fileOffset;
        if (!addForKey(ExpertKey{s.layer, s.expert}, view)) ok = false;
        else ++stats_.packedSlicesAdded;
    }
    if (ok) ++stats_.packedTensorsSliced;
    else ++stats_.packedRejected;
    if (receipt) *receipt = local;
    return ok;
}

const ExpertTensorGroup* ExpertTensorCatalog::find(ExpertKey key) const {
    auto it = groups_.find(key);
    return it == groups_.end() ? nullptr : &it->second;
}

std::vector<ExpertKey> ExpertTensorCatalog::keys() const {
    std::vector<ExpertKey> out;
    out.reserve(groups_.size());
    for (const auto& kv : groups_) out.push_back(kv.first);
    std::sort(out.begin(), out.end(), [](const ExpertKey& a, const ExpertKey& b) {
        return a.layer < b.layer || (a.layer == b.layer && a.expert < b.expert);
    });
    return out;
}

} // namespace rawrxd::deep2
