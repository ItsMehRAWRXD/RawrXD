#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
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
CompressedWeightStore::CompressedWeightStore(std::size_t budget,std::size_t block_bytes)
 : block_bytes_(block_bytes),cache_budget_(budget) {
 if(!block_bytes_||block_bytes_>std::numeric_limits<std::uint32_t>::max()) throw std::invalid_argument("invalid block size");
}
std::uint32_t CompressedWeightStore::crc32(const std::uint8_t* p,std::size_t n) {
 std::uint32_t crc=0xFFFFFFFFu;
 for(std::size_t i=0;i<n;++i){crc^=p[i];for(unsigned b=0;b<8;++b)crc=(crc>>1)^(0xEDB88320u&(0u-(crc&1u)));}
 return ~crc;
}
// Independent LZ tokens: control byte, then up to eight literals or (distance-1:u16,length:u8) matches.
std::vector<std::uint8_t> CompressedWeightStore::encode(const std::uint8_t* src,std::size_t n,bool& stored_raw) {
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
 }
 return out.size()==b.raw_size&&crc32(out.data(),out.size())==b.checksum;
}
bool CompressedWeightStore::addTensor(std::string name,const void* bytes,std::size_t size,std::string* error) {
 if(name.empty()||(!bytes&&size)){if(error)*error="name and source bytes are required";return false;}
 const auto* src=static_cast<const std::uint8_t*>(bytes);Tensor tensor;tensor.raw_size=size;
 for(std::size_t off=0;off<size;){const auto take=std::min(block_bytes_,size-off);EncodedBlock b;b.raw_size=static_cast<std::uint32_t>(take);b.checksum=crc32(src+off,take);b.payload=encode(src+off,take,b.stored_raw);tensor.blocks.emplace_back(std::move(b));off+=take;}
 std::lock_guard<std::mutex> lock(mutex_);if(tensors_.find(name)!=tensors_.end()){if(error)*error="tensor already exists";return false;}
 counters_.raw_bytes+=size;for(const auto& b:tensor.blocks)counters_.compressed_bytes+=b.payload.size();counters_.blocks+=tensor.blocks.size();++counters_.tensors;tensors_.emplace(std::move(name),std::move(tensor));return true;
}
bool CompressedWeightStore::contains(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);return tensors_.find(n)!=tensors_.end();}
std::size_t CompressedWeightStore::tensorBytes(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?0:i->second.raw_size;}
std::size_t CompressedWeightStore::tensorBlocks(const std::string& n)const{std::lock_guard<std::mutex>l(mutex_);auto i=tensors_.find(n);return i==tensors_.end()?0:i->second.blocks.size();}
std::string CompressedWeightStore::cacheKey(const std::string& n,std::size_t i){return n+'\x1f'+std::to_string(i);}
CompressedWeightStore::BlockLease CompressedWeightStore::acquireBlock(const std::string& name,std::size_t index,std::string* error) {
 std::lock_guard<std::mutex>lock(mutex_);auto t=tensors_.find(name);if(t==tensors_.end()||index>=t->second.blocks.size()){if(error)*error="unknown tensor or block index out of range";return{};}
 const auto key=cacheKey(name,index);auto hit=cache_.find(key);if(hit!=cache_.end()){++counters_.cache_hits;lru_.splice(lru_.begin(),lru_,hit->second.lru);return hit->second.data;}
 ++counters_.cache_misses;std::vector<std::uint8_t>decoded;if(!decode(t->second.blocks[index],decoded)){if(error)*error="compressed block corrupt or checksum mismatch";return{};}
 auto lease=std::make_shared<const std::vector<std::uint8_t>>(std::move(decoded));const auto bytes=lease->size();
 if(bytes<=cache_budget_){lru_.push_front(key);cache_.emplace(key,CacheEntry{lease,bytes,lru_.begin()});cache_bytes_+=bytes;evictToBudgetLocked();}
 return lease;
}
bool CompressedWeightStore::readRange(const std::string& name,std::size_t offset,void* dst,std::size_t length,std::string* error) {
 if(!contains(name)){if(error)*error="unknown tensor";return false;}\n const auto total=tensorBytes(name);if((!dst&&length)||offset>total||length>total-offset){if(error)*error="range outside tensor bounds";return false;}
 auto* out=static_cast<std::uint8_t*>(dst);while(length){const auto block=offset/block_bytes_,within=offset%block_bytes_;auto lease=acquireBlock(name,block,error);if(!lease||within>=lease->size())return false;const auto take=std::min(length,lease->size()-within);std::memcpy(out,lease->data()+within,take);out+=take;offset+=take;length-=take;}return true;
}
void CompressedWeightStore::evictToBudgetLocked(){
 while(cache_bytes_>cache_budget_&&!lru_.empty()){bool removed=false;for(auto it=lru_.rbegin();it!=lru_.rend();++it){auto e=cache_.find(*it);if(e!=cache_.end()&&e->second.data.use_count()==1){cache_bytes_-=e->second.bytes;auto erase_it=std::next(it).base();cache_.erase(e);lru_.erase(erase_it);++counters_.evictions;removed=true;break;}}if(!removed)break;}
}
StoreStats CompressedWeightStore::stats()const{std::lock_guard<std::mutex>l(mutex_);auto s=counters_;s.cached_decoded_bytes=cache_bytes_;return s;}
void CompressedWeightStore::setDecodedCacheBudget(std::size_t n){std::lock_guard<std::mutex>l(mutex_);cache_budget_=n;evictToBudgetLocked();}
void CompressedWeightStore::clearDecodedCache(){std::lock_guard<std::mutex>l(mutex_);for(auto it=lru_.begin();it!=lru_.end();){auto e=cache_.find(*it);if(e!=cache_.end()&&e->second.data.use_count()==1){cache_bytes_-=e->second.bytes;cache_.erase(e);it=lru_.erase(it);++counters_.evictions;}else ++it;}}
} // namespace rawrxd::compression
