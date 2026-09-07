// vwa/VwaSpace.hpp — mounted tensor address table (RMV → VWA)
#pragma once
#include "VwaBlockMath.hpp"
#include "VwaPhysical.hpp"
#include <unordered_map>

namespace Deep2 {
namespace vwa {

class VwaSpace {
public:
    void SetBackend(IPhysicalBackend* b) { backend_ = b; }
    IPhysicalBackend* Backend() const { return backend_; }

    bool Register(VirtualTensorDesc desc, uint64_t numElements,
                  uint32_t expertCount = 0, uint64_t expertStride = 0,
                  uint32_t classId = 2) {
        if (!desc.addressed || desc.byteLength == 0 || desc.id == 0) return false;
        VirtualTensorRef r{};
        r.desc = desc;
        r.expertCount = expertCount;
        r.expertStrideBytes = expertStride;
        r.classId = classId;
        if (!FillBlockGeometry(r, numElements ? numElements : desc.byteLength))
            return false;
        table_[desc.id] = r;
        return true;
    }

    VirtualTensorRef* Find(TensorId id) {
        auto it = table_.find(id);
        return it == table_.end() ? nullptr : &it->second;
    }
    const VirtualTensorRef* Find(TensorId id) const {
        auto it = table_.find(id);
        return it == table_.end() ? nullptr : &it->second;
    }
    size_t Count() const { return table_.size(); }

    template <typename Fn>
    void ForEach(Fn&& fn) {
        for (auto& kv : table_) fn(kv.second);
    }

private:
    std::unordered_map<TensorId, VirtualTensorRef> table_;
    IPhysicalBackend* backend_ = nullptr;
};

} // namespace vwa
} // namespace Deep2
