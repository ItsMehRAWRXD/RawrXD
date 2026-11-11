#include "deep2_tiered_moe.hpp"
#include <algorithm>
#include <limits>
#include <utility>

namespace deep2::tiered {
Admission admit(const Budget& b, uint64_t required_host) {
  Admission a;
  if (b.kv > b.host || b.scratch > b.host-b.kv || b.staging > b.host-b.kv-b.scratch) {
    a.reason="host reservations exceed physical host budget";
    return a;
  }
  a.usable_host=b.host-b.kv-b.scratch-b.staging;
  a.required_host=required_host;
  a.accepted=required_host<=a.usable_host;
  a.reason=a.accepted?"accepted":"host cache exceeds usable host memory";
  return a;
}
void TensorIndex::add(Tensor t) {
  if (t.name.empty() || t.file.empty() || t.bytes==0 || t.offset>UINT64_MAX-t.bytes)
    throw std::invalid_argument("invalid tensor descriptor");
  if (!tensors_.emplace(t.name,std::move(t)).second)
    throw std::invalid_argument("duplicate tensor name");
}
const Tensor& TensorIndex::at(const std::string& name) const { return tensors_.at(name); }
uint64_t TensorIndex::total_bytes() const {
  uint64_t sum=0;
  for (const auto& [_,t]:tensors_) {
    if (sum>UINT64_MAX-t.bytes) throw std::overflow_error("tensor bytes overflow");
    sum+=t.bytes;
  }
  return sum;
}
std::vector<std::string> TensorIndex::list_names() const {
  std::vector<std::string> out;
  out.reserve(tensors_.size());
  for (const auto& [k,_]:tensors_) out.push_back(k);
  return out;
}
Cache::Cache(uint64_t capacity):capacity_(capacity) {
  if (!capacity) throw std::invalid_argument("cache capacity must be positive");
}
Cache::Lease::Lease(Cache* o,std::string k,std::shared_ptr<const Entry> e)
 :owner_(o),key_(std::move(k)),entry_(std::move(e)){}
Cache::Lease::Lease(Lease&& o) noexcept
 :owner_(std::exchange(o.owner_,nullptr)),key_(std::move(o.key_)),entry_(std::move(o.entry_)){}
Cache::Lease& Cache::Lease::operator=(Lease&& o) noexcept {
  if(this!=&o){release();owner_=std::exchange(o.owner_,nullptr);key_=std::move(o.key_);entry_=std::move(o.entry_);}return *this;
}
Cache::Lease::~Lease(){release();}
void Cache::Lease::release() noexcept {
  if(owner_)owner_->release(key_);
  owner_=nullptr;entry_.reset();key_.clear();
}
std::span<const std::byte> Cache::Lease::bytes() const {
  if(!entry_)throw std::logic_error("empty lease");
  return entry_->data;
}
std::vector<std::byte> Cache::read_exact(const Tensor& t) {
  if(t.bytes>static_cast<uint64_t>(std::numeric_limits<size_t>::max()) ||
     t.offset>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
     t.bytes>static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()))
    throw std::overflow_error("tensor too large for host IO");
  std::ifstream in(t.file,std::ios::binary|std::ios::ate);
  if(!in)throw std::runtime_error("cannot open tensor file: "+t.file.string());
  const auto end=in.tellg();
  if(end<0 || static_cast<uint64_t>(end)<t.offset ||
     t.bytes>static_cast<uint64_t>(end)-t.offset)
    throw std::runtime_error("tensor range outside file: "+t.name);
  std::vector<std::byte> data(static_cast<size_t>(t.bytes));
  in.seekg(static_cast<std::streamoff>(t.offset));
  in.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(t.bytes));
  if(!in || static_cast<uint64_t>(in.gcount())!=t.bytes)
    throw std::runtime_error("short tensor read: "+t.name);
  return data;
}
bool Cache::evict_until(uint64_t needed) {
  while(stats_.resident_bytes>capacity_-needed) {
    auto victim=lru_.end();
    for(auto it=lru_.rbegin();it!=lru_.rend();++it){
      if(slots_.at(*it).pins==0){victim=std::prev(it.base());break;}
    }
    if(victim==lru_.end())return false;
    auto it=slots_.find(*victim);
    stats_.resident_bytes-=it->second.entry->bytes;
    ++stats_.evictions;
    slots_.erase(it);lru_.erase(victim);
  }
  return true;
}
Cache::Lease Cache::acquire(const Tensor& t) {
  if(t.bytes>capacity_)throw std::runtime_error("tensor exceeds cache capacity: "+t.name);
  // Serialize miss loading to guarantee capacity accounting and lease safety.
  std::lock_guard lock(mu_);
  const std::string key=t.file.lexically_normal().string()+"|"+std::to_string(t.offset)+"|"+std::to_string(t.bytes);
  if(auto it=slots_.find(key);it!=slots_.end()) {
    ++stats_.hits;++it->second.pins;stats_.pinned_bytes+=it->second.entry->bytes;
    lru_.splice(lru_.begin(),lru_,it->second.lru);
    return Lease(this,key,it->second.entry);
  }
  ++stats_.misses;
  if(!evict_until(t.bytes))throw std::runtime_error("cache full: all eviction candidates pinned");
  auto data=read_exact(t); // no cache mutation on failed read
  auto entry=std::make_shared<Entry>();entry->bytes=t.bytes;entry->data=std::move(data);
  lru_.push_front(key);
  try { slots_.emplace(key,Slot{entry,1,lru_.begin()}); }
  catch(...) {lru_.pop_front();throw;}
  stats_.resident_bytes+=t.bytes;stats_.pinned_bytes+=t.bytes;
  stats_.peak_resident_bytes=std::max(stats_.peak_resident_bytes,stats_.resident_bytes);
  ++stats_.disk_reads;stats_.disk_bytes+=t.bytes;
  return Lease(this,key,std::move(entry));
}
void Cache::release(const std::string& key) noexcept {
  std::lock_guard lock(mu_);
  auto it=slots_.find(key);
  if(it!=slots_.end() && it->second.pins){
    --it->second.pins;stats_.pinned_bytes-=it->second.entry->bytes;
  }
}
Stats Cache::stats() const {std::lock_guard lock(mu_);return stats_;}
}
