#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <algorithm>
#include <limits>

namespace rawrxd {
using Bytes=std::vector<uint8_t>;
inline uint64_t fingerprint(const Bytes& b) { uint64_t h=14695981039346656037ull; for(uint8_t x:b){h^=x;h*=1099511628211ull;} return h; }
struct Page { uint64_t id=0, version=0, digest=0; Bytes data; };
struct Frozen { uint64_t epoch=0; std::vector<Page> pages; uint64_t root=0; };
inline uint64_t root_digest(const Frozen& s) {
  uint64_t h=14695981039346656037ull;
  auto mix=[&](uint64_t n){for(int i=0;i<8;++i){h^=static_cast<uint8_t>(n>>(i*8));h*=1099511628211ull;}};
  mix(s.epoch); for(const auto& p:s.pages){mix(p.id);mix(p.version);mix(p.digest);mix(p.data.size());} return h;
}
class FrozenStream {
  std::unordered_map<uint64_t,Page> current_;
  uint64_t epoch_=0;
public:
  // Publish a complete page with optimistic version check; no partial mutation on conflict.
  bool publish(uint64_t id,uint64_t expected_version,Bytes bytes) {
    auto it=current_.find(id);
    const uint64_t prior=(it==current_.end()?0:it->second.version);
    if(prior!=expected_version || prior==std::numeric_limits<uint64_t>::max())return false;
    Page p{id,prior+1,fingerprint(bytes),std::move(bytes)};
    current_.insert_or_assign(id,std::move(p)); ++epoch_; return true;
  }
  Frozen freeze() const {
    Frozen s; s.epoch=epoch_;
    for(const auto& pair:current_)s.pages.push_back(pair.second);
    std::sort(s.pages.begin(),s.pages.end(),[](const Page&a,const Page&b){return a.id<b.id;});
    s.root=root_digest(s); return s;
  }
  static bool validate(const Frozen& s){
    if(root_digest(s)!=s.root)return false;
    uint64_t last=0; bool first=true;
    for(const auto& p:s.pages){if(!first && p.id<=last)return false;first=false;last=p.id;
      if(!p.version || fingerprint(p.data)!=p.digest)return false;}
    return true;
  }
  // Reconstruct exact bytes from a validated frozen snapshot, in deterministic page order.
  template<class Sink> static void replay(const Frozen& s,Sink sink){
    if(!validate(s))throw std::runtime_error("snapshot integrity failure");
    for(const auto& p:s.pages)sink(p.id,p.version,p.data);
  }
  // Restore exact frozen state; never infer missing bytes.
  void restore(const Frozen& s){
    if(!validate(s))throw std::runtime_error("snapshot integrity failure");
    std::unordered_map<uint64_t,Page> next;
    for(const auto& p:s.pages)next.emplace(p.id,p);
    current_.swap(next);epoch_=s.epoch;
  }
};
}
