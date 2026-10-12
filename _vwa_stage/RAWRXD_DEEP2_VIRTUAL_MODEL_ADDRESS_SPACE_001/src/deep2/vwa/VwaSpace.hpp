// VwaSpace.hpp — existing RMV -> VWA address table, extended with sparse state
#pragma once
#include "VwaBlockMath.hpp"
#include "VwaPhysical.hpp"
#include <unordered_map>
#include <utility>

namespace Deep2 { namespace vwa {
class VwaSpace {
public:
    void SetBackend(IPhysicalBackend* b) { backend_ = b; }
    IPhysicalBackend* Backend() const { return backend_; }
    bool Register(VirtualTensorDesc desc, uint64_t numElements,
                  uint32_t expertCount = 0, uint64_t expertStride = 0,
                  uint32_t classId = 2) {
        if (!desc.addressed || desc.byteLength == 0 || desc.id == 0) return false;
        if (table_.find(desc.id) != table_.end()) return false;
        VirtualTensor r{};
        r.desc = desc; r.expertCount = expertCount;
        r.expertStrideBytes = expertStride; r.classId = classId;
        if (!FillBlockGeometry(r, numElements ? numElements : desc.byteLength)) return false;
        table_.emplace(desc.id, std::move(r));
        return true;
    }
    VirtualTensor* Find(TensorId id) {
        auto it = table_.find(id);
        return it == table_.end() ? nullptr : &it->second;
    }
    const VirtualTensor* Find(TensorId id) const {
        auto it = table_.find(id);
        return it == table_.end() ? nullptr : &it->second;
    }
    size_t Count() const { return table_.size(); }
    uint64_t LogicalBytes() const {
        uint64_t n = 0;
        for (const auto& it : table_) n += it.second.desc.byteLength;
        return n;
    }
    template<typename Fn> void ForEach(Fn&& fn) {
        for (auto& kv : table_) fn(kv.second);
    }
private:
    std::unordered_map<TensorId, VirtualTensor> table_;
    IPhysicalBackend* backend_ = nullptr;
};
} }
