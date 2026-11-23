#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <iterator>
#include <stdexcept>

namespace rawrxd::compression {
namespace {
constexpr std::size_t kMinMatch=4,kMaxMatch=255,kMaxDistance=65535;
inline std::uint32_t hash4(const std::uint8_t* p) {
 const std::uint32_t v=std::uint32_t(p[0])|(std::uint32_t(p[1])<<8)|(std::uint32_t(p[2])<<16)|(std::uint32_t(p[3])<<24);
 return (v*2654435761u)>>16;
}
}
CompressedWeightStore::CompressedWeightStore(std::size_t budget,std::size_t block_bytes,std::size_t encoded_budget)
 : block_bytes_(block_bytes),cache_budget_(budget),encoded_residency_budget_(encoded_budget) {
 if(!block_bytes_||block_bytes_>static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) throw std::invalid_argument("invalid block size: exceeds signed match index capacity");
}
std::uint32_t CompressedWeightStore::crc32(const std::uint8_t* p,std::size_t n) {
 std::uint32_t crc=0xFFFFFFFFu;
 for(std::size_t i=0;i<n;++i){crc^=p[i];for(unsigned b=0;b<8;++b)crc=(crc>>1)^(0xEDB88320u&(0u-(crc&1u)));}
 return ~crc;
}
// Independent LZ tokens: control byte, then up to eight literals or (distance-1:u16,length:u8) matches.
std::vector<std::uint8_t> CompressedWeightStore::encode(const std::uint8_t* src,std::size_t n,bool& stored_raw) {
 if(n>static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) throw std::length_error("compressed block exceeds 32-bit match index");
 if(n==0){stored_raw=true;return{};}
 std::vector<std::uint8_t> out;out.reserve(n);std::vector<std::int32_t> last(1u<<16,-1);std::size_t pos=0;
 while(pos<n){const auto cp=out.size();out.push_back(0);std::uint8_t control=0;
  for(unsigned bit=0;bit<8&&pos<n;++bit){std::size_t len=0,dist=0;
   if(pos+kMinMatch<=n){const auto h=hash4(src+pos);const auto candidate=last[h];last[h]=static_cast<std::int32_t>(pos);
    if(candidate>=0){const auto c=static_cast<std::size_t>(candidate),d=pos-c;if(d&&d<=kMaxDistance){const auto limit=std::min(kMaxMatch,n-pos);while(len<limit&&src[c+len]==src[pos+len])++len;if(len>=kMinMatch)dist=d;else len=0;}}
   }
   if(len){control|=static_cast<std::uint8_t>(1u<<bit);const auto d=static_cast<std::uint16_t>(dist-1);out.push_back(static_cast<std::uint8_t>(d));out.push_back(static_cast<std::uint8_t>(d>>8));out.push_back(static_cast<std::uint8_t>(len));
    const auto end=pos+len;for(auto q=pos+1;q+kMinMatch<=end;++q)last[hash4(src+q)]=static_cast<std::int32_t>(q);pos=end;
   }else out.push_back(src[pos++]);
  }out[cp]=control;
 }
 stored_raw=out.size()>=n;if(stored_raw)return std::vector<std::uint8_t>(src,src+n);return out;
}
bool CompressedWeightStore::decode(const EncodedBlock& b,std::vector<std::uint8_t>& out) {
 if(b.stored_raw)out=b.payload;else{out.clear();out.reserve(b.raw_size);std::size_t p=0;
  while(p<b.payload.size()&&out.size()<b.raw_size){const auto control=b.payload[p++];for(unsigned bit=0;bit<8&&out.size()<b.raw_size;++bit){
   if(control&(1u<<bit)){if(p+3>b.payload.size())return false;const auto d=std::size_t(b.payload[p])|(std::size_t(b.payload[p+1])<<8);const auto len=b.payload[p+2];p+=3;const auto dist=d+1;
    if(dist>out.size()||len<kMinMatch||len>b.raw_size-out.size())return false;for(std::size_t i=0;i<len;++i)out.push_back(out[out.size()-dist]);
   }else{if(p>=b.payload.size())return false;out.push_back(b.payload[p++]);}
  }}
  if(p!=b.payload.size()) return false;
 }
 return out.size()==b.raw_size&&crc32(out.data(),out.size())==b.checksum;
}
bool CompressedWeightStore::addTensor(std::string name,const void* bytes,std::size_t size,std::string* error,std::uint32_t ggml_type,bool require_savings,std::size_t max_encoded_bytes) {
 if(!bytes&&size){if(error)*error="source bytes are required";return false;}
 return addTensorFromReader(std::move(name),size,
  [](void* context,std::size_t offset,void* destination,std::size_t length)->bool {
   if(length)std::memcpy(destination,static_cast<const std::uint8_t*>(context)+offset,length);
   return true;
  },const_cast<void*>(bytes),error,ggml_type,require_savings,max_encoded_bytes);
}
bool CompressedWeightStore::addTensorFromReader(std::string name,
    std::size_t size, TensorReadCallback reader, void* context,
    std::string* error, std::uint32_t ggml_type, bool require_savings,
    std::size_t max_encoded_bytes) {
    if (name.empty() || !reader) {
        if (error) *error = "name and tensor reader are required";
        return false;
    }
    if (size && size > std::numeric_limits<std::size_t>::max() - (block_bytes_ - 1)) {
        if (error) *error = "tensor size cannot be safely partitioned";
        return false;
    }

    // Take an early budget snapshot to bound temporary candidate allocation.
    // The final publication section rechecks the shared budget because another
    // admission may win capacity while this candidate is being encoded.
    std::size_t admission_limit = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (tensors_.find(name) != tensors_.end()) {
            if (error) *error = "tensor already exists";
            return false;
        }
        const auto resident = static_cast<std::size_t>(counters_.compressed_bytes);
        if (resident > encoded_residency_budget_) {
            if (error) *error = "encoded residency accounting exceeds budget";
            return false;
        }
        admission_limit = std::min(max_encoded_bytes,
                                   encoded_residency_budget_ - resident);
    }

    // Build the immutable candidate without holding the store mutex. Reader
    // callbacks can touch mapped GGUF pages and encoding can be CPU-expensive;
    // neither operation should block inference reads or unrelated admissions.
    Tensor tensor;
    tensor.raw_size = size;
    tensor.ggml_type = ggml_type;
    std::size_t encoded_size = 0;
    try {
        std::vector<std::uint8_t> scratch(block_bytes_);
        for (std::size_t off = 0; off < size;) {
            const auto take = std::min(block_bytes_, size - off);
            if (!reader(context, off, scratch.data(), take)) {
                if (error) *error = "tensor reader failed before completing requested range";
                return false;
            }

            EncodedBlock block;
            block.raw_size = static_cast<std::uint32_t>(take);
            block.checksum = crc32(scratch.data(), take);
            block.payload = encode(scratch.data(), take, block.stored_raw);

            if (encoded_size > admission_limit ||
                block.payload.size() > admission_limit - encoded_size) {
                if (error) *error = "encoded tensor exceeds available residency budget";
                return false;
            }
            encoded_size += block.payload.size();
            tensor.blocks.emplace_back(std::move(block));
            off += take;
        }

        if (require_savings && encoded_size >= size) {
            if (error) *error = "compression did not reduce tensor size";
            return false;
        }

        // Publication is the only critical section. Recheck duplicate names
        // and the shared encoded budget because other candidates may have
        // completed while this one was being built.
        std::lock_guard<std::mutex> lock(mutex_);
        if (tensors_.find(name) != tensors_.end()) {
            if (error) *error = "tensor already exists";
            return false;
        }
        const auto resident = static_cast<std::size_t>(counters_.compressed_bytes);
        if (resident > encoded_residency_budget_ ||
            encoded_size > encoded_residency_budget_ - resident) {
            if (error) *error = "encoded tensor exceeds shared residency budget";
            return false;
        }
        if (encoded_size > std::numeric_limits<std::uint64_t>::max() - counters_.compressed_bytes ||
            size > std::numeric_limits<std::uint64_t>::max() - counters_.raw_bytes ||
            tensor.blocks.size() > std::numeric_limits<std::uint64_t>::max() - counters_.blocks ||
            counters_.tensors == std::numeric_limits<std::uint64_t>::max()) {
            if (error) *error = "compressed residency counters would overflow";
            return false;
        }

        const std::size_t block_count = tensor.blocks.size();
        const auto inserted = tensors_.emplace(std::move(name), std::move(tensor));
        if (!inserted.second) {
            if (error) *error = "tensor publication conflict";
            return false;
        }
        counters_.raw_bytes += size;
        counters_.compressed_bytes += encoded_size;
        counters_.blocks += block_count;
        ++counters_.tensors;
        return true;
    } catch (const std::bad_alloc&) {
        if (error) *error = "allocation failed while admitting compressed tensor";
        return false;
    } catch (const std::exception& ex) {
        if (error) *error = std::string("tensor reader/codec failed: ") + ex.what();
        return false;
    } catch (...) {
        if (error) *error = "unknown failure while admitting compressed tensor";
        return false;
    }
}
bool CompressedWeightStore::addTensorF32AsF16(
    std::string name,const float* values,std::size_t count,std::string* error) {
 return addTensorF32AsF16FromReader(std::move(name),values,count,error);
}
bool CompressedWeightStore::addTensorF32AsF16FromReader(
    std::string name,const void* source_bytes,std::size_t count,std::string* error,
    std::size_t max_encoded_bytes,float max_abs_error,bool reject_non_finite,
    bool* precision_rejected) {
 if(precision_rejected) *precision_rejected=false;
 if(!source_bytes&&count){if(error)*error="source values are required";return false;}
 const auto max=(std::numeric_limits<std::size_t>::max)();
 if(count>max/sizeof(std::uint16_t)||count>max/sizeof(float)){
  if(error)*error="F32-to-F16 tensor size overflow";return false;
 }
 if(std::isnan(max_abs_error)||max_abs_error<0.0f){
  if(error)*error="F32-to-F16 maximum absolute error must be non-negative";return false;
 }
 struct Context {
  const std::uint8_t* source;
  std::size_t count;
  float max_abs_error;
  bool reject_non_finite;
  bool* precision_rejected;
 } context{static_cast<const std::uint8_t*>(source_bytes),count,
           max_abs_error,reject_non_finite,precision_rejected};
 const std::size_t outputBytes=count*sizeof(std::uint16_t);
 const bool admitted=addTensorFromReader(std::move(name),outputBytes,
  [](void* opaque,std::size_t offset,void* destination,std::size_t length)->bool {
   auto* ctx=static_cast<Context*>(opaque);
   const std::size_t total=ctx->count*sizeof(std::uint16_t);
   if(!ctx||(!destination&&length)||offset>total||length>total-offset)
    return false;
   auto* out=static_cast<std::uint8_t*>(destination);
   const std::size_t end=offset+length;
   for(std::size_t i=offset/2;i<(end+1)/2;++i){
    const auto* p=ctx->source+i*sizeof(float);
    const std::uint32_t bits=std::uint32_t(p[0])|
        (std::uint32_t(p[1])<<8)|(std::uint32_t(p[2])<<16)|
        (std::uint32_t(p[3])<<24);
    float value=0.0f;
    std::memcpy(&value,&bits,sizeof(value));
    if(!std::isfinite(value)&&ctx->reject_non_finite){
     if(ctx->precision_rejected) *ctx->precision_rejected=true;
     return false;
    }
    const std::uint16_t half=floatToHalfRNE(value);
    if(std::isfinite(value)){
     const std::uint32_t sign=std::uint32_t(half&0x8000u)<<16;
     std::uint32_t exp=(half>>10)&0x1fu,mant=half&0x03ffu,restoredBits=0;
     if(exp==0){
      if(!mant) restoredBits=sign;
      else {int e=-14;while((mant&0x400u)==0){mant<<=1;--e;}
       mant&=0x3ffu;restoredBits=sign|(std::uint32_t(e+127)<<23)|(mant<<13);}
     }else if(exp==31) restoredBits=sign|0x7f800000u|(mant<<13);
     else restoredBits=sign|((exp+112u)<<23)|(mant<<13);
     float restored=0.0f;std::memcpy(&restored,&restoredBits,sizeof(restored));
     if(std::fabs(value-restored)>ctx->max_abs_error){
      if(ctx->precision_rejected) *ctx->precision_rejected=true;
      return false;
     }
    }
    const std::uint8_t encoded[2]={
     static_cast<std::uint8_t>(half&0xffu),
     static_cast<std::uint8_t>((half>>8)&0xffu)};
    const std::size_t wordStart=i*2;
    const std::size_t copyStart=(std::max)(offset,wordStart);
    const std::size_t copyEnd=(std::min)(end,wordStart+2);
    if(copyEnd>copyStart)
     std::memcpy(out+(copyStart-offset),encoded+(copyStart-wordStart),copyEnd-copyStart);
   }
   return true;
  },&context,error,GGML_TYPE_F16,false,max_encoded_bytes);
 if(!admitted){
  if(precision_rejected&&*precision_rejected&&error)
   *error="F32-to-F16 conversion exceeded the configured error tolerance or contained non-finite data";
  return false;
 }
 {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto add=[](std::uint64_t& total,std::uint64_t value){
   if(value>(std::numeric_limits<std::uint64_t>::max)()-total)
    total=(std::numeric_limits<std::uint64_t>::max)();
   else total+=value;
  };
  add(counters_.f32_to_f16_tensors,1);
  add(counters_.f32_source_bytes,static_cast<std::uint64_t>(count*sizeof(float)));
 }
 return true;
}
std::uint32_t CompressedWeightStore::tensorType(const std::string& n)const {
 std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?GGML_TYPE_OPAQUE:i->second.ggml_type;
}
bool CompressedWeightStore::contains(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);return tensors_.find(n)!=tensors_.end();}
std::size_t CompressedWeightStore::tensorBytes(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?0:i->second.raw_size;}
std::size_t CompressedWeightStore::tensorBlocks(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?0:i->second.blocks.size();}
std::string CompressedWeightStore::cacheKey(const std::string& n,std::size_t i){return std::to_string(n.size())+":"+n+":"+std::to_string(i);}
CompressedWeightStore::BlockLease CompressedWeightStore::acquireBlock(
    const std::string& name, std::size_t index, std::string* error) {
    const std::string key = cacheKey(name, index);
    const EncodedBlock* encodedBlock = nullptr;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto tensor = tensors_.find(name);
        if (tensor == tensors_.end() || index >= tensor->second.blocks.size()) {
            if (error) *error = "unknown tensor or block index out of range";
            return {};
        }

        const auto hit = cache_.find(key);
        if (hit != cache_.end()) {
            ++counters_.cache_hits;
            lru_.splice(lru_.begin(), lru_, hit->second.lru);
            return hit->second.data;
        }

        ++counters_.cache_misses;
        // Tensor entries and their encoded block vectors are immutable after
        // publication. unordered_map rehash preserves references/pointers to
        // elements, so this block remains stable while another tensor is added.
        encodedBlock = &tensor->second.blocks[index];
    }

    // CRC verification and block expansion are deliberately outside mutex_.
    // Concurrent inference readers can decode different blocks in parallel.
    std::vector<std::uint8_t> decoded;
    if (!decode(*encodedBlock, decoded)) {
        if (error) *error = "compressed block corrupt or checksum mismatch";
        return {};
    }
    auto lease = std::make_shared<const std::vector<std::uint8_t>>(std::move(decoded));

    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Another reader may have populated this cache key while we decoded.
        // Reuse that immutable lease instead of admitting duplicate storage.
        const auto raced = cache_.find(key);
        if (raced != cache_.end()) {
            ++counters_.cache_hits;
            lru_.splice(lru_.begin(), lru_, raced->second.lru);
            return raced->second.data;
        }

        // The cache budget tracks allocated vector capacity, not just size.
        const auto bytes = lease->capacity();
        if (bytes <= cache_budget_) {
            lru_.push_front(key);
            try {
                cache_.emplace(key, CacheEntry{lease, bytes, lru_.begin()});
            } catch (...) {
                lru_.pop_front();
                throw;
            }
            cache_bytes_ += bytes;
            evictToBudgetLocked();
        }
    }
    return lease;
}
bool CompressedWeightStore::readRange(const std::string& name,std::size_t offset,void* dst,std::size_t length,std::string* error) {
 if(!contains(name)){if(error)*error="unknown tensor";return false;}
 const auto total=tensorBytes(name);if((!dst&&length)||offset>total||length>total-offset){if(error)*error="range outside tensor bounds";return false;}
 auto* out=static_cast<std::uint8_t*>(dst);while(length){const auto block=offset/block_bytes_,within=offset%block_bytes_;auto lease=acquireBlock(name,block,error);if(!lease||within>=lease->size())return false;const auto take=std::min(length,lease->size()-within);std::memcpy(out,lease->data()+within,take);out+=take;offset+=take;length-=take;}return true;
}
void CompressedWeightStore::evictToBudgetLocked(){
 while(cache_bytes_>cache_budget_&&!lru_.empty()){bool removed=false;for(auto it=lru_.rbegin();it!=lru_.rend();++it){auto e=cache_.find(*it);if(e!=cache_.end()&&e->second.data.use_count()==1){cache_bytes_-=e->second.bytes;auto erase_it=std::next(it).base();cache_.erase(e);lru_.erase(erase_it);++counters_.evictions;removed=true;break;}}if(!removed)break;}
}
StoreStats CompressedWeightStore::stats()const {
 std::lock_guard<std::mutex> lock(mutex_);
 auto s=counters_;
 s.cached_decoded_bytes=cache_bytes_;
 const auto add=[](std::uint64_t& total,std::uint64_t value) {
  if(value>(std::numeric_limits<std::uint64_t>::max)()-total)
   total=(std::numeric_limits<std::uint64_t>::max)();
  else total+=value;
 };
 // Payload size is useful for compression ratios; vector capacity is the
 // allocated backing storage and can be larger after codec growth/reallocation.
 for(const auto& item:tensors_) {
  const auto& name=item.first;
  const auto& tensor=item.second;
  add(s.metadata_bytes_estimate,sizeof(Tensor));
  add(s.metadata_bytes_estimate,name.capacity()+1);
  add(s.metadata_bytes_estimate,tensor.blocks.capacity()*sizeof(EncodedBlock));
  for(const auto& block:tensor.blocks)
   add(s.encoded_capacity_bytes,block.payload.capacity());
 }
 // Include container objects, bucket arrays, approximate node links, cache
 // key copies, and LRU list nodes. This is an estimate, not allocator RSS.
 add(s.metadata_bytes_estimate,sizeof(*this));
 add(s.metadata_bytes_estimate,tensors_.bucket_count()*sizeof(void*));
 add(s.metadata_bytes_estimate,tensors_.size()*(sizeof(void*)*2));
 add(s.metadata_bytes_estimate,cache_.bucket_count()*sizeof(void*));
 add(s.metadata_bytes_estimate,cache_.size()*(sizeof(CacheEntry)+sizeof(void*)*2));
 for(const auto& item:cache_) add(s.metadata_bytes_estimate,item.first.capacity()+1);
 add(s.metadata_bytes_estimate,lru_.size()*(sizeof(std::string)+sizeof(void*)*2));
 for(const auto& key:lru_) add(s.metadata_bytes_estimate,key.capacity()+1);
 s.resident_bytes_estimate=s.encoded_capacity_bytes;
 add(s.resident_bytes_estimate,s.metadata_bytes_estimate);
 add(s.resident_bytes_estimate,s.cached_decoded_bytes);
 return s;
}
void CompressedWeightStore::setDecodedCacheBudget(std::size_t n){std::lock_guard<std::mutex>l(mutex_);cache_budget_=n;evictToBudgetLocked();}
void CompressedWeightStore::clearDecodedCache(){std::lock_guard<std::mutex>l(mutex_);for(auto it=lru_.begin();it!=lru_.end();){auto e=cache_.find(*it);if(e!=cache_.end()&&e->second.data.use_count()==1){cache_bytes_-=e->second.bytes;cache_.erase(e);it=lru_.erase(it);++counters_.evictions;}else ++it;}}
} // namespace rawrxd::compression
