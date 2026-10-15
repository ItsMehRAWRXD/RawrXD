#pragma once
// CLI consumer: use as Recorder callback; one line per meaningful event.
#include "agent_esp.hpp"
#include "esp_metrics.hpp"
#include <cstdio>
#include <mutex>
namespace rawrxd::esp {
class ConsoleView {
 std::mutex mu_;
public:
 void operator()(const Event& e){
  std::lock_guard lk(mu_);
  if(e.kind==Kind::TokenGenerated)return; // high-volume tokens belong in --esp=verbose
  std::fprintf(stderr,"[ESP] seq=%llu req=%llu agent=%llu %-17s %s value=%lld\n",
    static_cast<unsigned long long>(e.sequence),
    static_cast<unsigned long long>(e.request_id),
    static_cast<unsigned long long>(e.agent_id),kind_name(e.kind),e.message.c_str(),
    static_cast<long long>(e.value));
  std::fflush(stderr);
 }
};
} // namespace rawrxd::esp
