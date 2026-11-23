#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::compression {
struct CompressedBlock {
    std::size_t logical_offset=0, raw_size=0, compressed_offset=0, compressed_size=0;
    std::uint32_t raw_crc32=0;
};
using BlockDecoder = std::function<bool(const std::uint8_t*,std::size_t,std::uint8_t*,std::size_t)>;

inline std::uint32_t crc32_bytes(const std::uint8_t* p,std::size_t n) noexcept {
    std::uint32_t c=0xffffffffu;
    for(std::size_t i=0;i<n;++i){c^=p[i];for(unsigned b=0;b<8;++b)c=(c>>1)^(0xedb88320u&(0u-(c&1u)));}
    return ~c;
}

class CompressedBlockStore final {
public:
    CompressedBlockStore(std::vector<std::uint8_t> compressed,
        std::vector<CompressedBlock> blocks,std::size_t logical_size,
        std::size_t cache_budget,BlockDecoder decoder)
      : compressed_(std::move(compressed)),blocks_(std::move(blocks)),
        logical_size_(logical_size),cache_budget_(cache_budget),decoder_(std::move(decoder)) {
        if(!decoder_)throw std::invalid_argument("decoder required");
        validate();
    }
    std::size_t logical_size()const noexcept{return logical_size_;}
    std::size_t compressed_size()const noexcept{return compressed_.size();}
    std::size_t cached_decoded_bytes()const{std::lock_guard<std::mutex> l(mutex_);return cached_bytes_;}
    void set_cache_budget(std::size_t n){std::lock_guard<std::mutex> l(mutex_);cache_budget_=n;evict();}
    bool read(std::size_t offset,std::size_t length,std::uint8_t* dst)const{
        if(!length)return offset<=logical_size_;
        if(!dst||offset>logical_size_||length>logical_size_-offset)return false;
        const auto end=offset+length;std::size_t copied=0;
        auto it=std::lower_bound(blocks_.begin(),blocks_.end(),offset,
          [](const CompressedBlock& b,std::size_t v){return b.logical_offset+b.raw_size<=v;});
        while(it!=blocks_.end()&&it->logical_offset<end){
            auto decoded=acquire(static_cast<std::size_t>(it-blocks_.begin()));if(!decoded)return false;
            const auto lo=std::max(offset,it->logical_offset);
            const auto hi=std::min(end,it->logical_offset+it->raw_size);
            const auto count=hi-lo;
            std::memcpy(dst+copied,decoded->data()+(lo-it->logical_offset),count);
            copied+=count;++it;
        }
        return copied==length;
    }
private:
    struct Entry{std::shared_ptr<const std::vector<std::uint8_t>> bytes;std::list<std::size_t>::iterator lru;};
    std::vector<std::uint8_t> compressed_;std::vector<CompressedBlock> blocks_;
    std::size_t logical_size_=0,cache_budget_=0;BlockDecoder decoder_;
    mutable std::mutex mutex_;mutable std::unordered_map<std::size_t,Entry> cache_;
    mutable std::list<std::size_t> lru_;mutable std::size_t cached_bytes_=0;
    void validate()const{
        std::size_t next=0;
        for(const auto& b:blocks_){
            if(!b.raw_size||!b.compressed_size||b.logical_offset!=next||
              b.logical_offset>logical_size_||b.raw_size>logical_size_-b.logical_offset||
              b.compressed_offset>compressed_.size()||
              b.compressed_size>compressed_.size()-b.compressed_offset)
                throw std::invalid_argument("invalid compressed block directory");
            next+=b.raw_size;
        }
        if(next!=logical_size_||(logical_size_==0&&!blocks_.empty())||
          (logical_size_!=0&&blocks_.empty()))
            throw std::invalid_argument("block directory does not cover tensor");
    }
    std::shared_ptr<const std::vector<std::uint8_t>> acquire(std::size_t i)const{
        {
            std::lock_guard<std::mutex> l(mutex_);
            auto hit=cache_.find(i);
            if(hit!=cache_.end()){
                lru_.splice(lru_.begin(),lru_,hit->second.lru);
                return hit->second.bytes;
            }
        }
        const auto& block=blocks_[i];
        std::shared_ptr<std::vector<std::uint8_t>> decoded;
        try { decoded=std::make_shared<std::vector<std::uint8_t>>(block.raw_size); }
        catch (...) { return {}; }
        if(!decoder_(compressed_.data()+block.compressed_offset,block.compressed_size,
                     decoded->data(),decoded->size())) return {};
        if(crc32_bytes(decoded->data(),decoded->size())!=block.raw_crc32) return {};

        std::lock_guard<std::mutex> l(mutex_);
        auto existing=cache_.find(i);
        if(existing!=cache_.end()){
            lru_.splice(lru_.begin(),lru_,existing->second.lru);
            return existing->second.bytes;
        }
        if(decoded->size()<=cache_budget_){
            while(cached_bytes_>cache_budget_-decoded->size()&&!lru_.empty()){
                auto victim=lru_.back();lru_.pop_back();auto entry=cache_.find(victim);
                if(entry!=cache_.end()){
                    cached_bytes_-=entry->second.bytes->size();
                    cache_.erase(entry);
                }
            }
            lru_.push_front(i);cached_bytes_+=decoded->size();
            cache_.emplace(i,Entry{decoded,lru_.begin()});
        }
        return decoded;
    }
    void evict()const{
        while(cached_bytes_>cache_budget_&&!lru_.empty()){
            auto victim=lru_.back();lru_.pop_back();auto e=cache_.find(victim);
            if(e!=cache_.end()){cached_bytes_-=e->second.bytes->size();cache_.erase(e);}
        }
    }
};
} // namespace rawrxd::compression
