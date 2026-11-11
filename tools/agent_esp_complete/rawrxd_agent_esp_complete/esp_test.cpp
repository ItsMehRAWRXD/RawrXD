#include "esp_runtime.hpp"
#include <cassert>
#include <chrono>
#include <cmath>
#include <iostream>
using namespace std::chrono_literals;
int main(){
 using M=rawrxd::esp::Metrics;using C=M::Clock;
 auto t=C::now();M m(42,7,5000ms,30000ms);
 m.task_start(t);m.begin_prefill(100,t+100ms);m.end_prefill(t+1100ms);
 m.begin_decode(t+1100ms);
 for(int i=1;i<=10;++i)m.token(i,t+1100ms+i*100ms);
 auto s=m.snapshot(t+2100ms);
 assert(s.generated==10 && s.prefill_tokens==100);
 assert(std::abs(s.prefill_tps-100.0)<.01);
 assert(std::abs(s.decode_tps-10.0)<.01);
 assert(std::abs(s.rolling_tps-10.0)<.01);
 assert(s.ttft_valid && std::abs(s.ttft_ms-1200.0)<.01);
 assert(!s.stalled);
 m.tool_start(t+2100ms);s=m.snapshot(t+5100ms);
 assert(s.phase==M::Phase::Tool && s.rolling_tps==0 && !s.stalled);
 assert(std::abs(s.decode_tps-10.0)<.01);
 m.begin_prefill(50,t+5100ms);s=m.snapshot(t+36100ms);assert(s.stalled);
 m.end_prefill(t+36100ms);m.finish(true,t+36100ms);
 s=m.snapshot(t+46100ms);assert(!s.stalled && s.phase==M::Phase::Done);
 assert(s.prefill_tokens==150);
 assert(rawrxd::esp::snapshot_json(s).find("\"decode_tps\"")!=std::string::npos);
 rawrxd::esp::Bus bus(8);rawrxd::esp::RuntimeESP r(bus,2);
 r.model_load("model.gguf");r.tokenizer(true);r.prefill_start(2,3);r.prefill_end();r.decode_start();r.token(42,"x");r.tick();r.finish(true);
 rawrxd::esp::Event e;int count=0;while(bus.try_pop(e))++count;assert(count==8);
 std::cout<<"ESP_METRICS_TESTS_PASS\n";
}
