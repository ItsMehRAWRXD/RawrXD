#include "dual_gpu_bridge.hpp"
#include <algorithm>
#include <chrono>
#include <limits>
#include <unordered_set>
#include <utility>

namespace deep2 {
Plan make_contiguous_plan(uint32_t layers, const std::vector<uint64_t>& weights,
                          const std::vector<DeviceMemory>& devices, uint64_t safety) {
  if (layers == 0 || weights.size() != layers || devices.size() != 2)
    throw std::invalid_argument("two devices and one weight size per layer required");
  if (devices[0].device == devices[1].device) throw std::invalid_argument("duplicate device");
  uint64_t available[2]{};
  for (int i=0;i<2;++i) {
    if (devices[i].capacity_bytes < devices[i].reserved_bytes ||
        devices[i].capacity_bytes-devices[i].reserved_bytes < safety)
      throw std::runtime_error("insufficient device budget");
    available[i]=devices[i].capacity_bytes-devices[i].reserved_bytes-safety;
  }
  std::vector<uint64_t> prefix(layers+1,0);
  for (uint32_t i=0;i<layers;++i) {
    if (weights[i] > std::numeric_limits<uint64_t>::max()-prefix[i])
      throw std::overflow_error("weight byte sum overflow");
    prefix[i+1]=prefix[i]+weights[i];
  }
  // Require both devices to participate; select split minimizing maximum capacity fraction.
  bool found=false; uint32_t best=0; long double score=std::numeric_limits<long double>::infinity();
  for (uint32_t s=1;s<layers;++s) {
    uint64_t a=prefix[s], b=prefix[layers]-a;
    if (a>available[0] || b>available[1]) continue;
    long double candidate=std::max((long double)a/available[0], (long double)b/available[1]);
    if (!found || candidate<score) { found=true; score=candidate; best=s; }
  }
  if (!found) throw std::runtime_error("no valid resident two-GPU layer split");
  Plan p{{{0,best,devices[0].device},{best,layers,devices[1].device}},layers};
  validate_plan(p,devices); return p;
}
void validate_plan(const Plan& p, const std::vector<DeviceMemory>& devices) {
  if (p.layer_count==0 || p.stages.empty()) throw std::invalid_argument("empty plan");
  std::unordered_set<DeviceId> valid;
  for (const auto& d:devices) valid.insert(d.device);
  uint32_t cursor=0;
  for (const auto& s:p.stages) {
    if (s.first!=cursor || s.end<=s.first || s.end>p.layer_count || !valid.count(s.device))
      throw std::invalid_argument("invalid layer assignment");
    cursor=s.end;
  }
  if (cursor!=p.layer_count) throw std::invalid_argument("incomplete layer coverage");
}
DualGpuBridge::DualGpuBridge(Plan p, Backend b):plan_(std::move(p)),backend_(std::move(b)) {
  if (!backend_.run_layers || !backend_.synchronize || !backend_.transfer_hidden || !backend_.activate_state_owner)
    throw std::invalid_argument("missing required native backend callback");
  if (plan_.stages.empty() || plan_.layer_count==0) throw std::invalid_argument("empty execution plan");
  uint32_t cursor=0;
  for (const auto& s:plan_.stages) {
    if (s.first!=cursor || s.end<=s.first || s.end>plan_.layer_count)
      throw std::invalid_argument("invalid execution plan");
    cursor=s.end;
  }
  if (cursor!=plan_.layer_count) throw std::invalid_argument("incomplete execution plan");
}
void DualGpuBridge::forward() {
  // Serial boundary is intentional: correctness-first across independent VkDevices.
  // transfer_hidden must synchronously complete a real staged transfer before returning.
  for (size_t i=0;i<plan_.stages.size();++i) {
    const auto& s=plan_.stages[i];
    if (i) {
      const auto& prev=plan_.stages[i-1];
      if (prev.device!=s.device) {
        backend_.synchronize(prev.device);
        auto t0=std::chrono::steady_clock::now();
        backend_.transfer_hidden(prev.device,s.device,s.first);
        auto t1=std::chrono::steady_clock::now();
        stats_.transfers++;
        stats_.wall_ms+=std::chrono::duration<double,std::milli>(t1-t0).count();
      }
    }
    backend_.activate_state_owner(s.device,s.first);
    backend_.run_layers(s.device,s.first,s.end);
  }
  backend_.synchronize(plan_.stages.back().device);
}
}
