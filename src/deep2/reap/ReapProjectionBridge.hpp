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
    using IdleCheck = std::function<bool()>;
    // Callback must release backend allocation; called only after IdleCheck.
    using ReleaseProjection = std::function<void(Projection,const Binding&)>;
    ProjectionBridge(Read read, UploadProjection upload, ExecuteProjection execute,
                     uint64_t maxReadBytes, uint64_t maxResidentBytes=0,
                     IdleCheck idleCheck={}, ReleaseProjection release={})
        : read_(std::move(read)), upload_(std::move(upload)),
          execute_(std::move(execute)), maxReadBytes_(maxReadBytes),
          maxResidentBytes_(maxResidentBytes ? maxResidentBytes : maxReadBytes),
          idleCheck_(std::move(idleCheck)), release_(std::move(release)) {
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
        // Preflight all three projections before the first read/upload/execute.
        // A missing slice or inadequate residency budget must not execute a
        // partially loaded expert. Conservative packed-byte reservation.
        uint64_t required=0;
        for(auto p:{Projection::Gate,Projection::Up,Projection::Down}) {
            const ProjectionKey k{layer,expert,p};
            if(resident_.contains(k)) continue;
            const auto slice=slices_.find(k);
            if(slice==slices_.end() || slice->second.bytes>maxResidentBytes_ ||
               required>maxResidentBytes_-slice->second.bytes) {
                ++stats_.rejected; return false;
            }
            required+=slice->second.bytes;
        }
        if(residentBytes_>maxResidentBytes_ ||
           required>maxResidentBytes_-residentBytes_) {
            ++stats_.rejected; return false;
        }
        for(auto p:{Projection::Gate,Projection::Up,Projection::Down}) {
            const ProjectionKey k{layer,expert,p};
            auto it=resident_.find(k);
            if(it==resident_.end()) {
                const auto slice=slices_.find(k);
                if(slice==slices_.end()) { ++stats_.rejected; return false; }
                const Slice& s=slice->second;
                // The upload callback must report device residency in bytes.
                // Reserve conservatively by packed slice size before any I/O.
                if(s.bytes>maxResidentBytes_ || residentBytes_>maxResidentBytes_-s.bytes) {
                    ++stats_.rejected; return false;
                }
                std::vector<uint8_t> packed(static_cast<size_t>(s.bytes));
                ++stats_.readCalls;
                if(!read_(s.path,s.offset,packed.data(),packed.size())) return false;
                stats_.diskBytes+=s.bytes;
                Binding b;
                const bool uploaded=upload_(p,s,packed,b);
                if(!uploaded || !b.deviceHandle || !b.bytes) {
                    // A failed uploader may still have allocated a binding.
                    // Release only after a positive GPU idle check.
                    if(b.deviceHandle && b.bytes && release_ && idleCheck_ && idleCheck_())
                        release_(p,b);
                    ++stats_.rejected;
                    return false;
                }
                if(b.bytes>maxResidentBytes_ || residentBytes_>maxResidentBytes_-b.bytes) {
                    // Allocation was created but is not admitted; without a
                    // release callback it cannot be safely reclaimed here.
                    if(release_ && idleCheck_ && idleCheck_()) release_(p,b);
                    ++stats_.rejected; return false;
                }
                it=resident_.emplace(k,b).first;
                residentBytes_+=b.bytes;
                ++stats_.cacheMisses;
            }
            ++stats_.bindingUses;
            if(!execute_(p,it->second,layer,expert)) return false;
        }
        return true;
    }
    // The caller owns GPU memory; this only removes bindings AFTER verified idle.
    // Without an idle callback eviction fails closed (cannot assume GPU is idle).
    bool ForgetAfterGpuIdle(uint32_t layer,uint32_t expert) {
        if(!idleCheck_ || !idleCheck_()) return false;
        for(auto p:{Projection::Gate,Projection::Up,Projection::Down}) {
            auto it=resident_.find({layer,expert,p});
            if(it!=resident_.end()) {
                if(release_) release_(p,it->second);
                residentBytes_-=it->second.bytes; resident_.erase(it);
            }
        }
        return true;
    }
    uint64_t ResidentBytes() const noexcept { return residentBytes_; }
    const Counters& Stats() const noexcept { return stats_; }
private:
    Read read_;
    UploadProjection upload_;
    ExecuteProjection execute_;
    uint64_t maxReadBytes_, maxResidentBytes_, residentBytes_=0;
    IdleCheck idleCheck_;
    ReleaseProjection release_;
    std::unordered_map<ProjectionKey,Slice,ProjectionKeyHash> slices_;
    std::unordered_map<ProjectionKey,Binding,ProjectionKeyHash> resident_;
    std::unordered_map<Key,bool,KeyHash> retained_;
    Counters stats_{};
};
} // namespace Deep2::ReapRom
