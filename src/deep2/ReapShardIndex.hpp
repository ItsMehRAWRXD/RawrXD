#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>

namespace Deep2 { namespace ReapQuant {
struct ShardRange {
    uint32_t shard=0;
    uint64_t offset=0, bytes=0;
};
// Offsets are absolute file offsets supplied by the GGUF metadata reader.
// Build before publishing; concurrent const lookup is safe after sealing.
class ShardIndex {
    std::unordered_map<uint32_t,uint64_t> shards_;
    std::unordered_map<std::string,ShardRange> tensors_;
    bool sealed_=false;
public:
    bool AddShard(uint32_t id,uint64_t bytes) {
        return !sealed_ && bytes && shards_.emplace(id,bytes).second;
    }
    bool AddTensor(const std::string& name,ShardRange r) {
        if(sealed_||name.empty()||!r.bytes)return false;
        const auto s=shards_.find(r.shard);
        if(s==shards_.end()||r.offset>s->second||r.bytes>s->second-r.offset)return false;
        return tensors_.emplace(name,r).second;
    }
    bool Seal() noexcept {
        if(shards_.empty()||tensors_.empty())return false;
        sealed_=true;return true;
    }
    bool Resolve(const std::string& name,uint64_t relative,uint64_t bytes,ShardRange& out) const {
        if(!sealed_||!bytes)return false;
        const auto t=tensors_.find(name);
        if(t==tensors_.end())return false;
        const auto& r=t->second;
        if(relative>r.bytes||bytes>r.bytes-relative)return false;
        out={r.shard,r.offset+relative,bytes};return true;
    }
    bool ResolveExpert(const std::string& name,uint64_t expert,uint64_t count,
                       uint64_t stride,uint64_t bytes,ShardRange& out) const {
        if(!count||expert>=count||!stride||!bytes||bytes>stride||count>UINT64_MAX/stride)return false;
        ShardRange whole{};
        if(!Resolve(name,0,count*stride,whole))return false;
        return Resolve(name,expert*stride,bytes,out);
    }
};
} }
