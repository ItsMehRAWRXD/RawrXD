#pragma once
// Transactional metadata-only expert batch planning. No buffer ownership or IO.
#include "ExpertResidencyPlanner.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>
namespace rawrxd::deep2 {
struct ExpertRequest { ExpertKey key; uint64_t bytes; float score; };
struct BatchPlan { std::vector<ExpertKey> hits, loads, evictions; bool accepted=false; };
inline BatchPlan planExpertBatch(ExpertResidencyPlanner& live, std::vector<ExpertRequest> requests) {
 BatchPlan result;
 for(const auto& r:requests)
  if(r.bytes==0 || !std::isfinite(r.score) || r.score<0) return result;
 std::sort(requests.begin(),requests.end(),[](const auto& a,const auto& b) {
  if(a.score!=b.score) return a.score>b.score;
  if(a.key.layer!=b.key.layer) return a.key.layer<b.key.layer;
  return a.key.expert<b.key.expert;
 });
 auto candidate=live;
 for(const auto& r:requests) {
  const bool hit=candidate.contains(r.key);
  const auto admission=candidate.admit(r.key,r.bytes);
  if(hit) {
   if(admission.status!=AdmissionStatus::Hit) return BatchPlan{};
   result.hits.push_back(r.key);
  } else {
   if(admission.status!=AdmissionStatus::Admitted) return BatchPlan{};
   result.loads.push_back(r.key);
   result.evictions.insert(result.evictions.end(),admission.evictions.begin(),admission.evictions.end());
  }
 }
 live=std::move(candidate);
 result.accepted=true;
 return result;
}
}
