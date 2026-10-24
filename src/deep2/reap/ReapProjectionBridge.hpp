#pragma once
// REAP/ROM projection-aware expert residency, C++20, no external dependencies.
// Safe by default: no speculative fallback, no implicit codec conversion.
// Caller owns GPU allocations and must synchronize before eviction.
#include "ReapRomPinballBridge.hpp"
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2::ReapRom {
enum class Projection : uint8_t { Gate=0, Up=1, Down=2 };
struct ProjectionKey {
    uint32_t layer, expert;
    Projection projection;
    bool operator==(const ProjectionKey& o) const noexcept {
        return layer==o.layer && expert==o.expert && projection==o.projection;
    }
};
struct ProjectionKeyHash {
    size_t operator()(const ProjectionKey& k) const noexcept {
        return KeyHash{}(Key{k.layer,k.expert}) ^ (static_cast<size_t>(k.projection)<<1);
    }
};
class ProjectionBridge {
public:
    using UploadProjection = std::function<bool(Projection,const Slice&,
                                                const std::vector<uint8_t>&,Binding&)>;
    using ExecuteProjection = std::function<bool(Projection,const Binding&,
                                                 uint32_t,uint32_t)>;
    ProjectionBridge(Read read, UploadProjection upload, ExecuteProjection execute,
                     uint64_t maxReadBytes)
        : read_(std::move(read)), upload_(std::move(upload)),
          execute_(std::move(execute)), maxReadBytes_(maxReadBytes) {
        if(!read_ || !upload_ || !execute_ || !maxReadBytes_)
            throw std::invalid_argument("invalid projection bridge");
    }
    void Register(Projection projection, Slice slice) {
        if(slice.path.empty() || !slice.bytes || slice.bytes>maxReadBytes_ ||
           slice.bytes>std::numeric_limits<size_t>::max() ||
           slice.offset>std::numeric_limits<uint64_t>::max()-slice.bytes)
            throw std::invalid_argument("invalid bounded projection slice");
        const ProjectionKey k{slice.layer,slice.expert,projection};
        if(!slices_.emplace(k,std::move(slice)).second)
            throw std::invalid_argument("duplicate projection");
    }
    void Retain(uint32_t layer,uint32_t expert) {
        for(auto p:{Projection::Gate,Projection::Up,Projection::Down})
            if(!slices_.contains({layer,expert,p}))
                throw std::invalid_argument("incomplete expert projections");
        retained_.emplace(Key{layer,expert},true);
    }
    bool Run(uint32_t layer,uint32_t expert) {
        if(!retained_.contains(Key{layer,expert})) { ++stats_.rejected; return false; }
        for(auto p:{Projection::Gate,Projection::Up,Projection::Down}) {
            const ProjectionKey k{layer,expert,p};
            auto it=resident_.find(k);
            if(it==resident_.end()) {
                const auto slice=slices_.find(k);
                if(slice==slices_.end()) { ++stats_.rejected; return false; }
                const Slice& s=slice->second;
                std::vector<uint8_t> packed(static_cast<size_t>(s.bytes));
                ++stats_.readCalls;
                if(!read_(s.path,s.offset,packed.data(),packed.size())) return false;
                stats_.diskBytes+=s.bytes;
                Binding b;
                if(!upload_(p,s,packed,b) || !b.deviceHandle || !b.bytes) return false;
                it=resident_.emplace(k,b).first;
                ++stats_.cacheMisses;
            }
            ++stats_.bindingUses;
            if(!execute_(p,it->second,layer,expert)) return false;
        }
        return true;
    }
    // Does not free GPU memory. Caller synchronizes all in-flight work first.
    void ForgetAfterGpuIdle(uint32_t layer,uint32_t expert) {
        for(auto p:{Projection::Gate,Projection::Up,Projection::Down})
            resident_.erase({layer,expert,p});
    }
    const Counters& Stats() const noexcept { return stats_; }
private:
    Read read_;
    UploadProjection upload_;
    ExecuteProjection execute_;
    uint64_t maxReadBytes_;
    std::unordered_map<ProjectionKey,Slice,ProjectionKeyHash> slices_;
    std::unordered_map<ProjectionKey,Binding,ProjectionKeyHash> resident_;
    std::unordered_map<Key,bool,KeyHash> retained_;
    Counters stats_{};
};
} // namespace Deep2::ReapRom
