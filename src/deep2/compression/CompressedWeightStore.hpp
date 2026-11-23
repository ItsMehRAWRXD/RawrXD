#pragma once
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::compression {
struct StoreStats {
    std::uint64_t tensors=0, blocks=0, raw_bytes=0, compressed_bytes=0;
    std::uint64_t cached_decoded_bytes=0, cache_hits=0, cache_misses=0, evictions=0;
};
class CompressedWeightStore {
public:
    static constexpr std::size_t DefaultBlockBytes=64u*1024u;
    using BlockLease=std::shared_ptr<const std::vector<std::uint8_t>>;
    explicit CompressedWeightStore(std::size_t decoded_cache_budget=256u*1024u*1024u,
                                   std::size_t block_bytes=DefaultBlockBytes);
    CompressedWeightStore(const CompressedWeightStore&)=delete;
    CompressedWeightStore& operator=(const CompressedWeightStore&)=delete;
    bool addTensor(std::string name,const void* bytes,std::size_t size,std::string* error=nullptr);
    bool contains(const std::string& name) const;
    std::size_t tensorBytes(const std::string& name) const;
    std::size_t tensorBlocks(const std::string& name) const;
    BlockLease acquireBlock(const std::string& name,std::size_t block_index,std::string* error=nullptr);
    bool readRange(const std::string& name,std::size_t offset,void* destination,std::size_t length,std::string* error=nullptr);
    StoreStats stats() const;
    void setDecodedCacheBudget(std::size_t bytes);
    void clearDecodedCache();
private:
    struct EncodedBlock { std::vector<std::uint8_t> payload; std::uint32_t checksum=0,raw_size=0; bool stored_raw=false; };
    struct Tensor { std::size_t raw_size=0; std::vector<EncodedBlock> blocks; };
    struct CacheEntry { BlockLease data; std::size_t bytes=0; std::list<std::string>::iterator lru; };
    static std::vector<std::uint8_t> encode(const std::uint8_t*,std::size_t,bool&);
    static bool decode(const EncodedBlock&,std::vector<std::uint8_t>&);
    static std::uint32_t crc32(const std::uint8_t*,std::size_t);
    static std::string cacheKey(const std::string&,std::size_t);
    void evictToBudgetLocked();
    const std::size_t block_bytes_;
    mutable std::mutex mutex_;
    std::size_t cache_budget_,cache_bytes_=0;
    std::unordered_map<std::string,Tensor> tensors_;
    std::unordered_map<std::string,CacheEntry> cache_;
    std::list<std::string> lru_;
    StoreStats counters_{};
};
}