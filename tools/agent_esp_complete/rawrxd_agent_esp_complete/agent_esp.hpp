#pragma once
// RawrXD Agent ESP: dependency-free C++20 event telemetry, bounded asynchronous JSONL.
// SPDX-License-Identifier: MIT
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace rawrxd::esp {
enum class Kind : uint8_t {
 ModelLoad, TokenizerCheck, PrefillStart, PrefillEnd, TokenGenerated,
 GPUDispatch, CPUFallback, SnapStop, AgentStep, ToolStart, ToolResult,
 FileChanged, BuildResult, TestResult, Error, Finished, Heartbeat
};
inline const char* kind_name(Kind k) noexcept {
 switch(k) {
 case Kind::ModelLoad:return "model_load"; case Kind::TokenizerCheck:return "tokenizer_check";
 case Kind::PrefillStart:return "prefill_start";case Kind::PrefillEnd:return "prefill_end";
 case Kind::TokenGenerated:return "token_generated";case Kind::GPUDispatch:return "gpu_dispatch";
 case Kind::CPUFallback:return "cpu_fallback";case Kind::SnapStop:return "snap_stop";
 case Kind::AgentStep:return "agent_step";case Kind::ToolStart:return "tool_start";
 case Kind::ToolResult:return "tool_result";case Kind::FileChanged:return "file_changed";
 case Kind::BuildResult:return "build_result";case Kind::TestResult:return "test_result";
 case Kind::Error:return "error";case Kind::Finished:return "finished";
 case Kind::Heartbeat:return "heartbeat";
 } return "unknown";
}
inline uint64_t now_ns() noexcept {
 return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
   std::chrono::system_clock::now().time_since_epoch()).count());
}
inline std::string escape_json(std::string_view s) {
 std::string out; out.reserve(s.size()+16);
 static constexpr char hex[]="0123456789abcdef";
 for(unsigned char c:s) {
  switch(c) {
   case '"':out+="\\\"";break;case '\\':out+="\\\\";break;
   case '\n':out+="\\n";break;case '\r':out+="\\r";break;case '\t':out+="\\t";break;
   default: if(c<0x20) {out+="\\u00";out+=hex[c>>4];out+=hex[c&15];} else out+=static_cast<char>(c);
  }
 }
 return out;
}
struct Event {
 Kind kind{Kind::Heartbeat};
 uint64_t timestamp_ns{0}, sequence{0}, request_id{0}, agent_id{0};
 std::string message; // Caller MUST redact secrets/private content before publishing.
 int64_t value{0}; // token ID, elapsed microseconds, exit code, etc.
};
inline std::string jsonl(const Event& e) {
 std::ostringstream o;
 o << "{\"ts_ns\":" << e.timestamp_ns << ",\"seq\":" << e.sequence
   << ",\"request\":" << e.request_id << ",\"agent\":" << e.agent_id
   << ",\"kind\":\"" << kind_name(e.kind) << "\",\"value\":" << e.value
   << ",\"message\":\"" << escape_json(e.message) << "\"}";
 return o.str();
}
// Thread-safe MPSC queue. Producer path does not do disk I/O or invoke callbacks.
// Bounded queue drops events when full; dropped counter is observable.
class Bus {
public:
 explicit Bus(size_t capacity=8192, size_t max_message_bytes=4096)
  : capacity_(capacity?capacity:1), max_message_(max_message_bytes) {}
 bool publish(Kind kind, std::string_view message={}, uint64_t request=0,
              uint64_t agent=0, int64_t value=0) {
  Event e; e.kind=kind;e.timestamp_ns=now_ns();e.request_id=request;e.agent_id=agent;e.value=value;
  e.message.assign(message.substr(0,max_message_));
  {
   std::lock_guard<std::mutex> lock(mu_);
   if(queue_.size()>=capacity_) {dropped_.fetch_add(1,std::memory_order_relaxed);return false;}
   e.sequence=next_sequence_++;
   queue_.push_back(std::move(e));
  }
  cv_.notify_one();return true;
 }
 bool try_pop(Event& e) {
  std::lock_guard<std::mutex> lock(mu_);
  if(queue_.empty()) return false;
  e=std::move(queue_.front());queue_.pop_front();return true;
 }
 // Blocks until event or stop flag; caller owns consumer thread.
 bool wait_pop(Event& e, const std::atomic<bool>& stop) {
  std::unique_lock<std::mutex> lock(mu_);
  cv_.wait_for(lock,std::chrono::milliseconds(100),[&]{return !queue_.empty()||stop.load();});
  if(queue_.empty())return false;
  e=std::move(queue_.front());queue_.pop_front();return true;
 }
 void wake() noexcept {cv_.notify_all();}
 uint64_t dropped() const noexcept {return dropped_.load(std::memory_order_relaxed);}
private:
 size_t capacity_,max_message_;
 mutable std::mutex mu_;
 std::condition_variable cv_;
 std::deque<Event> queue_;
 uint64_t next_sequence_{1};
 std::atomic<uint64_t> dropped_{0};
};
// One consumer: JSONL and optional callback (e.g. PostMessage to Win32 UI).
class Recorder {
public:
 using Callback=std::function<void(const Event&)>;
 Recorder(Bus& bus, std::string path, Callback callback={})
  : bus_(bus), path_(std::move(path)), callback_(std::move(callback)) {}
 ~Recorder(){stop();}
 Recorder(const Recorder&)=delete;Recorder& operator=(const Recorder&)=delete;
 bool start() {
  if(worker_.joinable())return false;
  stream_.open(path_,std::ios::out|std::ios::app|std::ios::binary);
  if(!stream_)return false;
  stop_.store(false);
  worker_=std::thread([this]{run();});return true;
 }
 void stop() {
  stop_.store(true);bus_.wake();
  if(worker_.joinable())worker_.join();
  if(stream_.is_open())stream_.close();
 }
private:
 void run() {
  Event e;
  for (;;) {
   if (bus_.wait_pop(e,stop_)) {write(e);continue;}
   if (stop_.load()) {
    while(bus_.try_pop(e))write(e);
    break;
   }
  }
  stream_.flush();
 }
 void write(const Event& e) {
  stream_ << jsonl(e) << '\n';stream_.flush();
  if(callback_)callback_(e); // callback must not access UI controls from worker thread
 }
 Bus& bus_;std::string path_;Callback callback_;
 std::ofstream stream_;std::atomic<bool> stop_{false};std::thread worker_;
};
} // namespace rawrxd::esp
