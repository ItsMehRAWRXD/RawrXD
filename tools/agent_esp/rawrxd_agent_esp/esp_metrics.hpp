#pragma once
// RawrXD ESP metrics. C++20 standard library only. SPDX-License-Identifier: MIT
#include "agent_esp.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace rawrxd::esp {
class Metrics {
public:
 using Clock=std::chrono::steady_clock;
 enum class Phase { Idle, Load, Prefill, Decode, Tool, Build, Test, Done, Error };
 struct Snapshot {
  uint64_t request_id=0, agent_id=0, generated=0, prefill_tokens=0, context_tokens=0;
  uint64_t gpu_dispatches=0, cpu_fallbacks=0, tool_calls=0, failures=0;
  double rolling_tps=0, decode_tps=0, prefill_tps=0, task_tps=0;
  double ttft_ms=0, prefill_ms=0, decode_ms=0, task_ms=0, idle_ms=0;
   double last_progress_ms=0;
   bool ttft_valid=false, stalled=false;
   // RAWRXD_DEEP2_STALL_STATES_001: distinguishing states. `active` means real
   // dispatched work advanced recently; `slow` means an op is in flight but
   // nothing completed yet; only `stalled` (no dispatches at all) means trouble.
   bool active=false, slow=false;
   Phase phase=Phase::Idle;
 };
 explicit Metrics(uint64_t request=0,uint64_t agent=0,
                  std::chrono::milliseconds window=std::chrono::milliseconds(5000),
                  std::chrono::milliseconds stall=std::chrono::milliseconds(30000))
  :request_(request),agent_(agent),window_(window),stall_(stall){}
 void task_start(Clock::time_point now=Clock::now()) {
  std::lock_guard lk(mu_);reset_locked(now);phase_=Phase::Load;
 }
 void begin_prefill(uint64_t input_tokens,Clock::time_point now=Clock::now()) {
  std::lock_guard lk(mu_);transition_locked(Phase::Prefill,now);
  prefill_pending_=input_tokens;prefill_start_=now;
 }
 void end_prefill(Clock::time_point now=Clock::now()) {
  std::lock_guard lk(mu_);
  if(phase_!=Phase::Prefill || !prefill_start_)return;
  prefill_elapsed_+=std::chrono::duration<double>(now-*prefill_start_).count();
  prefill_tokens_+=prefill_pending_;prefill_pending_=0;prefill_start_.reset();
  progress_=now;
 }
 void begin_decode(Clock::time_point now=Clock::now()) {
  std::lock_guard lk(mu_);transition_locked(Phase::Decode,now);
  if(!decode_segment_)decode_segment_=now;
 }
 void token(uint64_t token_id=0,Clock::time_point now=Clock::now()) {
  (void)token_id;
  std::lock_guard lk(mu_);
  if(!started_)reset_locked(now);
  if(phase_!=Phase::Decode){transition_locked(Phase::Decode,now);decode_segment_=now;}
  if(!first_token_)first_token_=now;
  ++generated_;recent_.push_back(now);progress_=now;
  prune_locked(now);
 }
 void tool_start(Clock::time_point now=Clock::now()) { std::lock_guard lk(mu_);++tool_calls_;transition_locked(Phase::Tool,now); }
 void build_start(Clock::time_point now=Clock::now()) { std::lock_guard lk(mu_);transition_locked(Phase::Build,now); }
 void test_start(Clock::time_point now=Clock::now()) { std::lock_guard lk(mu_);transition_locked(Phase::Test,now); }
  void gpu_dispatch() { std::lock_guard lk(mu_);++gpu_dispatches_; }
  void cpu_fallback() { std::lock_guard lk(mu_);++cpu_fallbacks_; }
  // Batch variants used by sync_kernel_counters(): each engine receipt is a
  // completed kernel dispatch, not an event that may be counted twice.
  void gpu_dispatch_batch(uint64_t n) { std::lock_guard lk(mu_);gpu_dispatches_+=n;last_dispatch_=Clock::now();progress_=Clock::now(); }
  void cpu_fallback_batch(uint64_t n) { std::lock_guard lk(mu_);cpu_fallbacks_+=n;last_dispatch_=Clock::now(); }
 void failure(Clock::time_point now=Clock::now()) { std::lock_guard lk(mu_);++failures_;progress_=now; }
 void set_context(uint64_t tokens) { std::lock_guard lk(mu_);context_=tokens; }
 void finish(bool success,Clock::time_point now=Clock::now()) {
  std::lock_guard lk(mu_);transition_locked(success?Phase::Done:Phase::Error,now);finished_=now;
 }
 Snapshot snapshot(Clock::time_point now=Clock::now()) {
  std::lock_guard lk(mu_);prune_locked(now);
  Snapshot s;s.request_id=request_;s.agent_id=agent_;s.generated=generated_;
  s.prefill_tokens=prefill_tokens_;s.context_tokens=context_;s.phase=phase_;
  s.gpu_dispatches=gpu_dispatches_;s.cpu_fallbacks=cpu_fallbacks_;
  s.tool_calls=tool_calls_;s.failures=failures_;
  if(!started_)return s;
  auto end=finished_.value_or(now);
  s.task_ms=ms(end-*started_);
  s.task_tps=s.task_ms>0?generated_/(s.task_ms/1000.0):0;
  s.prefill_ms=1000*prefill_elapsed_;
  if(phase_==Phase::Prefill && prefill_start_)s.prefill_ms+=ms(now-*prefill_start_);
  s.prefill_tps=s.prefill_ms>0?prefill_tokens_/(s.prefill_ms/1000.0):0;
  s.decode_ms=1000*decode_elapsed_;
  if(phase_==Phase::Decode && decode_segment_)s.decode_ms+=ms(now-*decode_segment_);
   s.decode_tps=s.decode_ms>0?generated_/(s.decode_ms/1000.0):0;
   if(first_token_){s.ttft_valid=true;s.ttft_ms=ms(*first_token_-*started_);}
   s.last_progress_ms=ms(now-progress_);
   // RAWRXD_DEEP2_STALL_STATES_001: three states instead of a boolean.
   // `stalled` alone conflated a long-but-healthy operation with a deadlock,
   // which is exactly what made a 138s prefill look like a hang.
   //   active: dispatched work (gpu/cpu) advanced recently
   //   slow:   no completed work recently, but a verified op is still in flight
   //   stalled: no progress across ALL relevant counters past the deadline
   s.active = (gpu_dispatches_+cpu_fallbacks_) > 0 &&
              (last_dispatch_ && now-*last_dispatch_<=stall_);
   s.slow = !s.active && (phase_==Phase::Load || phase_==Phase::Prefill || phase_==Phase::Decode) &&
            now-progress_>=stall_;
   s.stalled = s.slow && (gpu_dispatches_+cpu_fallbacks_)==0;
   if(phase_==Phase::Decode && decode_segment_){
    double elapsed=ms(now-*decode_segment_)/1000.0;
    double interval=std::min(elapsed,window_.count()/1000.0);
    if(interval>0)s.rolling_tps=recent_.size()/interval;
   }
   return s;
  }
 static const char* phase_name(Phase p) noexcept {
  switch(p){case Phase::Idle:return "idle";case Phase::Load:return "load";
  case Phase::Prefill:return "prefill";case Phase::Decode:return "decode";
  case Phase::Tool:return "tool";case Phase::Build:return "build";
  case Phase::Test:return "test";case Phase::Done:return "done";
  case Phase::Error:return "error";}return "unknown";
 }
private:
 static double ms(Clock::duration d){return std::chrono::duration<double,std::milli>(d).count();}
 void reset_locked(Clock::time_point now){
   started_=now;finished_.reset();first_token_.reset();prefill_start_.reset();decode_segment_.reset();last_dispatch_.reset();
  phase_=Phase::Idle;progress_=now;phase_since_=now;recent_.clear();generated_=prefill_tokens_=0;
  context_=gpu_dispatches_=cpu_fallbacks_=tool_calls_=failures_=prefill_pending_=0;
  prefill_elapsed_=decode_elapsed_=0;
 }
 void transition_locked(Phase next,Clock::time_point now){
  if(!started_)reset_locked(now);
  if(phase_==Phase::Decode && decode_segment_){decode_elapsed_+=std::chrono::duration<double>(now-*decode_segment_).count();decode_segment_.reset();recent_.clear();}
  if(phase_==Phase::Prefill && prefill_start_){prefill_elapsed_+=std::chrono::duration<double>(now-*prefill_start_).count();prefill_tokens_+=prefill_pending_;prefill_pending_=0;prefill_start_.reset();}
  phase_=next;phase_since_=now;progress_=now;
  if(next==Phase::Decode)decode_segment_=now;
 }
 void prune_locked(Clock::time_point now){while(!recent_.empty() && now-recent_.front()>window_)recent_.pop_front();}
  std::mutex mu_;uint64_t request_,agent_,generated_=0,prefill_tokens_=0,prefill_pending_=0,context_=0;
  uint64_t gpu_dispatches_=0,cpu_fallbacks_=0,tool_calls_=0,failures_=0;
  std::chrono::milliseconds window_,stall_;
  Phase phase_=Phase::Idle;Clock::time_point progress_{},phase_since_{};
  std::optional<Clock::time_point> started_,finished_,first_token_,prefill_start_,decode_segment_,last_dispatch_;
 double prefill_elapsed_=0,decode_elapsed_=0;
 std::deque<Clock::time_point> recent_;
};
inline std::string snapshot_json(const Metrics::Snapshot& s){
 std::ostringstream o;o<<std::fixed<<std::setprecision(3);
 o<<"{\"request\":"<<s.request_id<<",\"agent\":"<<s.agent_id
  <<",\"phase\":\""<<Metrics::phase_name(s.phase)<<"\",\"generated\":"<<s.generated
  <<",\"prefill_tokens\":"<<s.prefill_tokens<<",\"context\":"<<s.context_tokens
  <<",\"rolling_tps\":"<<s.rolling_tps<<",\"decode_tps\":"<<s.decode_tps
  <<",\"prefill_tps\":"<<s.prefill_tps<<",\"task_tps\":"<<s.task_tps
  <<",\"ttft_ms\":"<<(s.ttft_valid?s.ttft_ms:-1.0)
  <<",\"prefill_ms\":"<<s.prefill_ms<<",\"decode_ms\":"<<s.decode_ms
  <<",\"task_ms\":"<<s.task_ms<<",\"gpu_dispatches\":"<<s.gpu_dispatches
  <<",\"cpu_fallbacks\":"<<s.cpu_fallbacks<<",\"tool_calls\":"<<s.tool_calls
   <<",\"failures\":"<<s.failures<<",\"stalled\":"<<(s.stalled?"true":"false")
   <<",\"active\":"<<(s.active?"true":"false")<<",\"slow\":"<<(s.slow?"true":"false")<<"}";
 return o.str();
}
// Publish a metrics snapshot as a Heartbeat event. Message is JSON object text;
// JSONL event serialization escapes it as a string for backwards compatibility.
inline bool publish_metrics(Bus& bus,Metrics& metrics,uint64_t request,uint64_t agent){
 return bus.publish(Kind::Heartbeat,snapshot_json(metrics.snapshot()),request,agent);
}
} // namespace rawrxd::esp
