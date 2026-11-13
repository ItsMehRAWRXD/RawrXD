#pragma once
// Integration-friendly RAII telemetry facade. No inference dependencies.
#include "esp_metrics.hpp"
#include <chrono>
#include <string>
#include <string_view>
namespace rawrxd::esp {
class RuntimeESP {
public:
 RuntimeESP(Bus& bus,uint64_t request,uint64_t agent=0):bus_(bus),request_(request),agent_(agent),metrics_(request,agent){}
 Metrics& metrics(){return metrics_;}
 void model_load(std::string_view model){metrics_.task_start();bus_.publish(Kind::ModelLoad,model,request_,agent_);}
 void tokenizer(bool ok){bus_.publish(Kind::TokenizerCheck,ok?"PASS":"FAIL",request_,agent_);if(!ok)metrics_.failure();}
 void prefill_start(uint64_t tokens,uint64_t context){metrics_.set_context(context);metrics_.begin_prefill(tokens);bus_.publish(Kind::PrefillStart,"tokens="+std::to_string(tokens)+" ctx="+std::to_string(context),request_,agent_);}
 void prefill_end(){metrics_.end_prefill();auto s=metrics_.snapshot();bus_.publish(Kind::PrefillEnd,"elapsed_ms="+std::to_string(s.prefill_ms),request_,agent_,static_cast<int64_t>(s.prefill_ms));}
 void decode_start(){metrics_.begin_decode();}
 void token(int64_t token_id,std::string_view safe_fragment={}){metrics_.token(static_cast<uint64_t>(token_id));bus_.publish(Kind::TokenGenerated,safe_fragment,request_,agent_,token_id);}
 void snap(std::string_view reason){bus_.publish(Kind::SnapStop,reason,request_,agent_);}
 void tool_start(std::string_view command){metrics_.tool_start();bus_.publish(Kind::ToolStart,command,request_,agent_);}
  void tool_result(std::string_view summary,int exit_code){bus_.publish(Kind::ToolResult,summary,request_,agent_,exit_code);if(exit_code!=0)metrics_.failure();}
  // RAWRXD_DEEP2_FAILURE_TRUTH_001: count model-output failures explicitly. The
  // heartbeat's `failures` field used to stay at zero for an entire failed run
  // because only build/test exit codes incremented it, which made a FAIL verdict
  // look like a run with no failures at all.
  void model_output_failure(){metrics_.failure();bus_.publish(Kind::Error,"model_output_invalid",request_,agent_);}
 void build_start(std::string_view command){metrics_.build_start();bus_.publish(Kind::AgentStep,command,request_,agent_);}
 void build_result(int exit_code){bus_.publish(Kind::BuildResult,exit_code==0?"PASS":"FAIL",request_,agent_,exit_code);if(exit_code)metrics_.failure();}
 void test_start(std::string_view command){metrics_.test_start();bus_.publish(Kind::AgentStep,command,request_,agent_);}
 void test_result(int exit_code){bus_.publish(Kind::TestResult,exit_code==0?"PASS":"FAIL",request_,agent_,exit_code);if(exit_code)metrics_.failure();}
   void gpu_dispatch(){metrics_.gpu_dispatch();}
   void cpu_fallback(){metrics_.cpu_fallback();}
   // RAWRXD_DEEP2_CONTEXT_TRUTH_001: set the committed context length from the
   // host's authoritative counter. A rendered-prompt length is NOT the same
   // number: BOS handling and appended turns make the two drift, and every TPS
   // denominator derived from the wrong one is meaningless. This is called with
   // `fed.size()` - the count of tokens actually executed - not with a render.
   void set_context(uint64_t context){metrics_.set_context(context);}
  // RAWRXD_DEEP2_GPU_TELEMETRY_001: publish the engine's own kernel receipts
  // instead of a counter nothing ever increments. The executor reports
  // cumulative gpu_calls/cpu_calls; ESP keeps cumulative counters too, so the
  // delta since the last sync is added. This is what makes gpu_dispatches and
  // cpu_fallbacks mean something: they come from real dispatch decisions.
  void sync_kernel_counters(uint64_t gpu_calls,uint64_t cpu_calls){
    if(gpu_calls>last_gpu_){metrics_.gpu_dispatch_batch(gpu_calls-last_gpu_);last_gpu_=gpu_calls;}
    if(cpu_calls>last_cpu_){metrics_.cpu_fallback_batch(cpu_calls-last_cpu_);last_cpu_=cpu_calls;}
  }
  uint64_t last_gpu_calls() const {return last_gpu_;}
  uint64_t last_cpu_calls() const {return last_cpu_;}
 void tick(){publish_metrics(bus_,metrics_,request_,agent_);}
 void finish(bool ok){metrics_.finish(ok);tick();bus_.publish(Kind::Finished,ok?"PASS":"FAIL",request_,agent_,ok?0:1);}
 private:Bus& bus_;uint64_t request_,agent_;Metrics metrics_;
  uint64_t last_gpu_=0,last_cpu_=0;
};
} // namespace rawrxd::esp
