#include "CompressedWeightStore.hpp"
#include "rawrxd/native_lz_block_codec.hpp"
#include "codec/compression_core.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <iterator>
#include <stdexcept>

namespace rawrxd::compression {
CompressedWeightStore::CompressedWeightStore(std::size_t budget,
    std::size_t block_bytes,std::size_t encoded_budget,BlockCodec codec)
 : block_bytes_(block_bytes),cache_budget_(budget),
   encoded_residency_budget_(encoded_budget),codec_(codec) {
 if(!block_bytes_||block_bytes_>static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
  throw std::invalid_argument("invalid block size: exceeds signed codec capacity");
}
std::uint32_t CompressedWeightStore::crc32(const std::uint8_t* p,std::size_t n) {
 std::uint32_t crc=0xFFFFFFFFu;
 for(std::size_t i=0;i<n;++i){crc^=p[i];for(unsigned b=0;b<8;++b)crc=(crc>>1)^(0xEDB88320u&(0u-(crc&1u)));}
 return ~crc;
}
std::vector<std::uint8_t> CompressedWeightStore::encode(
    const std::uint8_t* src,std::size_t size,BlockCodec codec,bool& stored_raw) {
 if(!src&&size) throw std::invalid_argument("null block source");
 if(size==0){stored_raw=true;return{};}
 std::vector<std::uint8_t> encoded;
 if(codec==BlockCodec::NativeLz) {
  if(!native_lz::encode(src,size,encoded))
   throw std::runtime_error("native LZ block encode failed");
 } else if(codec==BlockCodec::Zlib) {
  const auto result=rawrxd::compression::compress(src,size,-1);
  if(!result) throw std::runtime_error("zlib block encode unavailable or failed");
  encoded=result.bytes;
 } else {
  throw std::invalid_argument("unknown compressed-weight codec");
 }
 stored_raw=encoded.size()>=size;
 if(stored_raw) encoded.assign(src,src+size);
 return encoded;
}
bool CompressedWeightStore::decode(const EncodedBlock& block,BlockCodec codec,
                                   std::vector<std::uint8_t>& out) {
 out.clear();
 try {
  if(block.stored_raw) {
   if(block.payload.size()!=block.raw_size) return false;
   out=block.payload;
  } else if(codec==BlockCodec::NativeLz) {
   out.resize(block.raw_size);
   if(!native_lz::decode(block.payload.data(),block.payload.size(),out.data(),out.size())) {
    out.clear();return false;
   }
  } else if(codec==BlockCodec::Zlib) {
   const auto result=rawrxd::compression::decompress(
       block.payload.data(),block.payload.size(),block.raw_size);
   if(!result||result.bytes.size()!=block.raw_size) return false;
   out=result.bytes;
  } else {
   return false;
  }
 } catch(...) { out.clear();return false; }
 return out.size()==block.raw_size&&crc32(out.data(),out.size())==block.checksum;
}
bool CompressedWeightStore::addTensor(std::string name,const void* bytes,std::size_t size,std::string* error,std::uint32_t ggml_type,bool require_savings,std::size_t max_encoded_bytes) {
 if(!bytes&&size){if(error)*error="source bytes are required";return false;}
 return addTensorFromReader(std::move(name),size,
  [](void* context,std::size_t offset,void* destination,std::size_t length)->bool {
   if(length)std::memcpy(destination,static_cast<const std::uint8_t*>(context)+offset,length);
   return true;
  },const_cast<void*>(bytes),error,ggml_type,require_savings,max_encoded_bytes);
}
bool CompressedWeightStore::addTensorFromReader(
    std::string name,std::size_t size,TensorReadCallback reader,void* context,
    std::string* error,std::uint32_t ggml_type,bool require_savings,
    std::size_t max_encoded_bytes) {
 if(name.empty()||!reader){if(error)*error="name and tensor reader are required";return false;}
 if(size && size > std::numeric_limits<std::size_t>::max()-(block_bytes_-1)){
  if(error)*error="tensor size cannot be safely partitioned";return false;
 }

 // Reserve an admission ceiling under lock, then perform potentially slow file
 // reads and codec work without blocking inference readers or other admissions.
 std::size_t admissionSnapshot=0;
 {
  std::lock_guard<std::mutex> lock(mutex_);
  if(tensors_.find(name)!=tensors_.end()){
   if(error)*error="tensor already exists";return false;
  }
  const auto resident=static_cast<std::size_t>(counters_.compressed_bytes);
  if(resident>encoded_residency_budget_){
   if(error)*error="encoded residency accounting exceeds budget";return false;
  }
  admissionSnapshot=std::min(max_encoded_bytes,encoded_residency_budget_-resident);
 }

 Tensor tensor;
 tensor.raw_size=size;
 tensor.ggml_type=ggml_type;
 std::size_t encodedSize=0;
 try {
  std::vector<std::uint8_t> scratch(block_bytes_);
  for(std::size_t offset=0;offset<size;) {
   const auto count=std::min(block_bytes_,size-offset);
   if(!reader(context,offset,scratch.data(),count)){
    if(error)*error="tensor reader failed before completing requested range";
    return false;
   }
   EncodedBlock block;
   block.raw_size=static_cast<std::uint32_t>(count);
   block.checksum=crc32(scratch.data(),count);
   block.payload=encode(scratch.data(),count,codec_,block.stored_raw);
   if(encodedSize>admissionSnapshot||
      block.payload.size()>admissionSnapshot-encodedSize){
    if(error)*error="encoded tensor exceeds residency budget";
    return false;
   }
   encodedSize+=block.payload.size();
   tensor.blocks.emplace_back(std::move(block));
   offset+=count;
  }
  if(require_savings&&encodedSize>=size){
   if(error)*error="compression did not reduce tensor size";
   return false;
  }

  // Publish atomically. Re-check the shared encoded budget because another
  // writer may have committed while this tensor was being encoded.
  std::lock_guard<std::mutex> lock(mutex_);
  if(tensors_.find(name)!=tensors_.end()){
   if(error)*error="tensor publication conflict";return false;
  }
  const auto resident=static_cast<std::size_t>(counters_.compressed_bytes);
  if(resident>encoded_residency_budget_||
     encodedSize>std::min(max_encoded_bytes,encoded_residency_budget_-resident)){
   if(error)*error="encoded residency budget changed during admission";
   return false;
  }
  if(encodedSize>std::numeric_limits<std::uint64_t>::max()-counters_.compressed_bytes||
     size>std::numeric_limits<std::uint64_t>::max()-counters_.raw_bytes||
     tensor.blocks.size()>std::numeric_limits<std::uint64_t>::max()-counters_.blocks){
   if(error)*error="compressed residency counters would overflow";
   return false;
  }
  const std::size_t blockCount=tensor.blocks.size();
  const auto inserted=tensors_.emplace(std::move(name),std::move(tensor));
  if(!inserted.second){if(error)*error="tensor publication conflict";return false;}
  counters_.raw_bytes+=size;
  counters_.compressed_bytes+=encodedSize;
  counters_.blocks+=blockCount;
  ++counters_.tensors;
  return true;
 } catch(const std::bad_alloc&) {
  if(error)*error="allocation failed while admitting compressed tensor";
  return false;
 } catch(const std::exception& ex) {
  if(error)*error=std::string("tensor reader/codec failed: ")+ex.what();
  return false;
 } catch(...) {
  if(error)*error="unknown failure while admitting compressed tensor";
  return false;
 }
}
bool CompressedWeightStore::addTensorF32AsF16(std::string name,const float* values,std::size_t count,std::string* error) {
 if(!values&&count){if(error)*error="source values are required";return false;}
 if(count>std::numeric_limits<std::size_t>::max()/sizeof(std::uint16_t)){if(error)*error="tensor size overflow";return false;}
 std::vector<std::uint16_t> converted(count);
 for(std::size_t i=0;i<count;++i) converted[i]=floatToHalfRNE(values[i]);
 return addTensor(std::move(name),converted.data(),converted.size()*sizeof(std::uint16_t),error,GGML_TYPE_F16);
}
bool CompressedWeightStore::addTensorF32AsF16FromReader(
    std::string name,const float* values,std::size_t count,std::string* error,
    std::size_t max_encoded_bytes) {
 if(!values&&count){if(error)*error="source values are required";return false;}
 if(count>std::numeric_limits<std::size_t>::max()/sizeof(std::uint16_t)){
  if(error)*error="F32-to-F16 tensor size overflow";return false;
 }
 struct Context { const float* values; std::size_t count; } context{values,count};
 const std::size_t outputBytes=count*sizeof(std::uint16_t);
 return addTensorFromReader(std::move(name),outputBytes,
  [](void* opaque,std::size_t offset,void* destination,std::size_t length)->bool {
   auto* ctx=static_cast<Context*>(opaque);
   if(!ctx||(!destination&&length)||offset>ctx->count*2||length>ctx->count*2-offset)
    return false;
   auto* out=static_cast<std::uint8_t*>(destination);
   const std::size_t end=offset+length;
   for(std::size_t i=offset/2;i<(end+1)/2;++i){
    const std::uint16_t half=floatToHalfRNE(ctx->values[i]);
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
}
std::uint32_t CompressedWeightStore::tensorType(const std::string& n)const {
 std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?GGML_TYPE_OPAQUE:i->second.ggml_type;
}
bool CompressedWeightStore::contains(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);return tensors_.find(n)!=tensors_.end();}
std::size_t CompressedWeightStore::tensorBytes(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?0:i->second.raw_size;}
std::size_t CompressedWeightStore::tensorBlocks(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?0:i->second.blocks.size();}
std::string CompressedWeightStore::cacheKey(const std::string& n,std::size_t i){return std::to_string(n.size())+":"+n+":"+std::to_string(i);}
CompressedWeightStore::BlockLease CompressedWeightStore::acquireBlock(
    const std::string& name,std::size_t index,std::string* error) {
 const EncodedBlock* encodedBlock=nullptr;
 const auto key=cacheKey(name,index);
 {
  std::lock_guard<std::mutex> lock(mutex_);
  auto tensor=tensors_.find(name);
  if(tensor==tensors_.end()||index>=tensor->second.blocks.size()){
   if(error)*error="unknown tensor or block index out of range";
   return{};
  }
  auto hit=cache_.find(key);
  if(hit!=cache_.end()){
   ++counters_.cache_hits;
   lru_.splice(lru_.begin(),lru_,hit->second.lru);
   return hit->second.data;
  }
  ++counters_.cache_misses;
  // Tensor objects and their block vectors are immutable after publication;
  // unordered_map insertion does not invalidate references to existing values.
  encodedBlock=&tensor->second.blocks[index];
 }

 std::vector<std::uint8_t> decoded;
 if(!decode(*encodedBlock,codec_,decoded)){
  if(error)*error="compressed block corrupt, unsupported, or checksum mismatch";
  return{};
 }
 BlockLease lease;
 try { lease=std::make_shared<const std::vector<std::uint8_t>>(std::move(decoded)); }
 catch (...) { if(error)*error="decoded block allocation failed";return{}; }

 {
  std::lock_guard<std::mutex> lock(mutex_);
  // Another reader may have decoded this block while we worked outside lock.
  auto existing=cache_.find(key);
  if(existing!=cache_.end()){
   ++counters_.cache_hits;
   lru_.splice(lru_.begin(),lru_,existing->second.lru);
   return existing->second.data;
  }
  const auto bytes=lease->size();
  if(bytes<=cache_budget_){
   lru_.push_front(key);
   cache_.emplace(key,CacheEntry{lease,bytes,lru_.begin()});
   cache_bytes_+=bytes;
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
StoreStats CompressedWeightStore::stats()const{std::lock_guard<std::mutex>l(mutex_);auto s=counters_;s.cached_decoded_bytes=cache_bytes_;return s;}
void CompressedWeightStore::setDecodedCacheBudget(std::size_t n){std::lock_guard<std::mutex>l(mutex_);cache_budget_=n;evictToBudgetLocked();}
void CompressedWeightStore::clearDecodedCache(){std::lock_guard<std::mutex>l(mutex_);for(auto it=lru_.begin();it!=lru_.end();){auto e=cache_.find(*it);if(e!=cache_.end()&&e->second.data.use_count()==1){cache_bytes_-=e->second.bytes;cache_.erase(e);it=lru_.erase(it);++counters_.evictions;}else ++it;}}
} // namespace rawrxd::compression
