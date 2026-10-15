#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace rawrxd::deep2 {
using Clock = std::chrono::steady_clock;
inline double elapsed_ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b-a).count();
}
struct Counters {
    uint64_t gpu_dispatches=0, cpu_ops=0, cpu_fallbacks=0;
    uint64_t gpu_syncs=0, weight_upload_bytes=0, kv_reused=0, kv_appended=0;
    uint64_t prefill_tokens=0, decode_tokens=0;
    double prefill_ms=0, decode_ms=0;
};
struct Snapshot { Counters counters; double prefill_tps=0, decode_tps=0; };
class Telemetry {
    mutable std::mutex mutex_;
    Counters c_{};
public:
    void gpu_dispatch(uint64_t n=1){std::lock_guard<std::mutex> g(mutex_);c_.gpu_dispatches+=n;}
    void cpu_op(bool fallback){std::lock_guard<std::mutex> g(mutex_);++c_.cpu_ops;if(fallback)++c_.cpu_fallbacks;}
    void gpu_sync(){std::lock_guard<std::mutex> g(mutex_);++c_.gpu_syncs;}
    void upload(uint64_t n){std::lock_guard<std::mutex> g(mutex_);c_.weight_upload_bytes+=n;}
    void kv(uint64_t reused,uint64_t appended){std::lock_guard<std::mutex> g(mutex_);c_.kv_reused+=reused;c_.kv_appended+=appended;}
    void prefill(uint64_t n,double ms){std::lock_guard<std::mutex> g(mutex_);c_.prefill_tokens+=n;c_.prefill_ms+=ms;}
    void decode(uint64_t n,double ms){std::lock_guard<std::mutex> g(mutex_);c_.decode_tokens+=n;c_.decode_ms+=ms;}
    Snapshot snapshot() const {
        std::lock_guard<std::mutex> g(mutex_);
        Snapshot s{};s.counters=c_;
        if(c_.prefill_ms>0)s.prefill_tps=1000.0*c_.prefill_tokens/c_.prefill_ms;
        if(c_.decode_ms>0)s.decode_tps=1000.0*c_.decode_tokens/c_.decode_ms;
        return s;
    }
};
// This only tracks a prefix. Reuse is permitted after the engine confirms
// its KV cache represents exactly the same model, tokenizer and token prefix.
class PrefixTracker {
    std::vector<int32_t> committed_;
    std::string model_fingerprint_;
public:
    void reset(){committed_.clear();model_fingerprint_.clear();}
    size_t reusable(const std::string& fingerprint,const std::vector<int32_t>& prompt) const {
        if(fingerprint!=model_fingerprint_)return 0;
        size_t n=std::min(committed_.size(),prompt.size());
        size_t i=0;while(i<n && committed_[i]==prompt[i])++i;
        return i;
    }
    // Call only after successful KV append/commit; do not call on failed execution.
    void commit(std::string fingerprint,std::vector<int32_t> actual_kv_tokens){
        model_fingerprint_=std::move(fingerprint);
        committed_=std::move(actual_kv_tokens);
    }
};
// Serializes owned model residency in one process. Does not measure or free GPU memory.
class ResidencyGate {
    std::mutex mutex_;
    bool occupied_=false;
public:
    class Lease {
        ResidencyGate* owner_=nullptr;
    public:
        explicit Lease(ResidencyGate* p):owner_(p){}
        Lease(const Lease&)=delete;Lease& operator=(const Lease&)=delete;
        Lease(Lease&& other) noexcept:owner_(other.owner_){other.owner_=nullptr;}
        Lease& operator=(Lease&&)=delete;
        ~Lease(){if(owner_){std::lock_guard<std::mutex> g(owner_->mutex_);owner_->occupied_=false;}}
    };
    Lease acquire(){
        std::lock_guard<std::mutex> g(mutex_);
        if(occupied_)throw std::runtime_error("MODEL_RESIDENCY_CONFLICT");
        occupied_=true;return Lease(this);
    }
};
struct Policy {
    bool require_gpu=false;
    bool reject_cpu_fallback=false;
    double min_prefill_tps=0;
};
inline std::string evaluate(const Snapshot& s,const Policy& p){
    if(p.require_gpu && s.counters.gpu_dispatches==0)return "FAIL: NO_RECORDED_GPU_DISPATCH";
    if(p.reject_cpu_fallback && s.counters.cpu_fallbacks)return "FAIL: CPU_FALLBACK";
    if(p.min_prefill_tps>0 && s.counters.prefill_tokens && s.prefill_tps<p.min_prefill_tps)
        return "FAIL: PREFILL_BELOW_TARGET";
    return "PASS";
}
} // namespace rawrxd::deep2
