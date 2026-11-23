#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::compression {
// GGML-compatible IDs for common scalar formats. Other GGML IDs are retained verbatim.
constexpr std::uint32_t GGML_TYPE_F32 = 0;
constexpr std::uint32_t GGML_TYPE_F16 = 1;
constexpr std::uint32_t GGML_TYPE_OPAQUE = 0xFFFFFFFFu;

inline std::uint16_t floatToHalfRNE(float value) noexcept {
    std::uint32_t bits=0;
    static_assert(sizeof(bits)==sizeof(value),"IEEE-754 float32 required");
    std::memcpy(&bits,&value,sizeof(bits));
    const std::uint32_t sign=(bits>>16)&0x8000u;
    const std::uint32_t exp=(bits>>23)&0xFFu;
    const std::uint32_t mant=bits&0x7FFFFFu;
    if(exp==0xFFu) {
        if(mant==0) return static_cast<std::uint16_t>(sign|0x7C00u);
        std::uint32_t payload=mant>>13;
        if(payload==0) payload=1;
        return static_cast<std::uint16_t>(sign|0x7C00u|payload|0x0200u);
    }
    const int e=static_cast<int>(exp)-127;
    if(e>15) return static_cast<std::uint16_t>(sign|0x7C00u);
    if(e>=-14) {
        std::uint32_t he=static_cast<std::uint32_t>(e+15);
        std::uint32_t rounded=mant+0x0FFFu+((mant>>13)&1u);
        if(rounded&0x800000u) { rounded=0; ++he; }
        if(he>=31) return static_cast<std::uint16_t>(sign|0x7C00u);
        return static_cast<std::uint16_t>(sign|(he<<10)|(rounded>>13));
    }
    if(e < -25 || exp==0) return static_cast<std::uint16_t>(sign);
    const std::uint32_t significand=mant|0x800000u;
    const unsigned shift=static_cast<unsigned>(-e-1);
    std::uint32_t result=significand>>shift;
    const std::uint32_t mask=(1u<<shift)-1u;
    const std::uint32_t remainder=significand&mask;
    const std::uint32_t halfway=1u<<(shift-1u);
    if(remainder>halfway || (remainder==halfway && (result&1u))) ++result;
    return static_cast<std::uint16_t>(sign|result);
}

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
    bool addTensor(std::string name,const void* bytes,std::size_t size,std::string* error=nullptr,
                   std::uint32_t ggml_type=GGML_TYPE_OPAQUE,
                   bool require_savings=false,
                   std::size_t max_encoded_bytes=(std::numeric_limits<std::size_t>::max)());
    bool addTensorF32AsF16(std::string name,const float* values,std::size_t count,std::string* error=nullptr);
    std::uint32_t tensorType(const std::string& name) const;
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
    struct Tensor { std::size_t raw_size=0; std::uint32_t ggml_type=GGML_TYPE_OPAQUE; std::vector<EncodedBlock> blocks; };
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