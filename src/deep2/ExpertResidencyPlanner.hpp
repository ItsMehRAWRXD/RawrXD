#pragma once
// Metadata-only expert residency planner. Callers own buffers and transfers.
// Native C++20; no third-party dependencies.
#include <cstdint>
#include <cstddef>
#include <unordered_map>
#include <vector>
namespace rawrxd::deep2 {
struct ExpertKey {
 uint32_t layer=0, expert=0;
 bool operator==(const ExpertKey& b) const noexcept { return layer==b.layer && expert==b.expert; }
};
struct ExpertKeyHash {
 size_t operator()(ExpertKey k) const noexcept {
  uint64_t x=(uint64_t(k.layer)<<32)|k.expert;
  x=(x^ (x>>30))*0xbf58476d1ce4e5b9ULL;
  x=(x^(x>>27))*0x94d049bb133111ebULL;
  return size_t(x^(x>>31));
 }
};
enum class AdmissionStatus { Hit, Admitted, TooLarge, NoEvictableSpace, InvalidSize };
struct Admission { AdmissionStatus status; std::vector<ExpertKey> evictions; };
class ExpertResidencyPlanner {
 struct Entry { uint64_t bytes, age; bool pinned; };
 uint64_t capacity_, used_=0, clock_=0;
 std::unordered_map<ExpertKey,Entry,ExpertKeyHash> entries_;
public:
 explicit ExpertResidencyPlanner(uint64_t capacity):capacity_(capacity){}
 uint64_t capacity() const noexcept {return capacity_;}
 uint64_t used() const noexcept {return used_;}
 size_t size() const noexcept {return entries_.size();}
 bool contains(ExpertKey k) const {return entries_.find(k)!=entries_.end();}
 bool pin(ExpertKey k,bool value) {
  auto it=entries_.find(k); if(it==entries_.end()) return false;
  it->second.pinned=value; return true;
 }
 bool touch(ExpertKey k) {
  auto it=entries_.find(k); if(it==entries_.end()) return false;
  it->second.age=++clock_; return true;
 }
 Admission admit(ExpertKey k,uint64_t bytes,bool pinned=false) {
  if(!bytes) return {AdmissionStatus::InvalidSize,{}};
  auto existing=entries_.find(k);
  if(existing!=entries_.end()) {
   if(existing->second.bytes!=bytes) return {AdmissionStatus::InvalidSize,{}};
   existing->second.age=++clock_;
   existing->second.pinned|=pinned;
   return {AdmissionStatus::Hit,{}};
  }
  if(bytes>capacity_) return {AdmissionStatus::TooLarge,{}};
  uint64_t free=capacity_-used_;
  std::vector<ExpertKey> victims;
  while(free<bytes) {
   const Entry* oldest=nullptr; ExpertKey victim{};
   for(const auto& [candidate,entry]:entries_) {
    if(entry.pinned) continue;
    bool chosen=false;
    for(const auto& v:victims) if(v==candidate){chosen=true;break;}
    if(chosen) continue;
    if(!oldest || entry.age<oldest->age ||
       (entry.age==oldest->age &&
       (candidate.layer<victim.layer ||
       (candidate.layer==victim.layer && candidate.expert<victim.expert)))) {
     oldest=&entry; victim=candidate;
    }
   }
   if(!oldest) return {AdmissionStatus::NoEvictableSpace,{}};
   free+=oldest->bytes; victims.push_back(victim);
  }
  for(auto victim:victims) {
   auto it=entries_.find(victim);
   used_-=it->second.bytes; entries_.erase(it);
  }
  entries_.emplace(k,Entry{bytes,++clock_,pinned});
  used_+=bytes;
  return {AdmissionStatus::Admitted,victims};
 }
 bool erase(ExpertKey k) {
  auto it=entries_.find(k);
  if(it==entries_.end()||it->second.pinned) return false;
  used_-=it->second.bytes; entries_.erase(it); return true;
 }
};
}
