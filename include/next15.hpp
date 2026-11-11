#pragma once
// RawrXD Next15: dependency-free C++20 instrumentation and guarded integration layer.
// Does not claim to implement GPU kernels or engine-specific hooks absent from this drop.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd::next15 {
using Clock=std::chrono::steady_clock;
struct Result { bool pass{}; std::string message; static Result ok(std::string m="PASS"){return {true,std::move(m)};} static Result fail(std::string m){return {false,std::move(m)};} };
struct RunConfig {std::string model, model_hash, git_revision, quant, backend; std::uint32_t context{}, gpu_index{}; bool greedy{true};};
struct Counters {std::atomic<std::uint64_t> pipeline_creates{0}, gpu_submits{0}, gpu_gemv{0}, gpu_gemm{0}, gpu_layers{0}, cpu_fallbacks{0}, strict_violations{0}, host_upload_bytes{0}, residency_hits{0}, residency_misses{0}, generated_tokens{0};};
struct CounterView {std::uint64_t pipeline_creates{},gpu_submits{},gpu_gemv{},gpu_gemm{},gpu_layers{},cpu_fallbacks{},strict_violations{},host_upload_bytes{},residency_hits{},residency_misses{},generated_tokens{};};
CounterView read(const Counters& c);
Result certify_gpu(const CounterView& before,const CounterView& after,bool numeric_ok);
struct Stage {std::uint64_t calls{},nanoseconds{},bytes{};};
class Profiler {
 std::mutex mu_; std::map<std::string,Stage> stages_;
 public: void record(std::string_view stage,std::uint64_t ns,std::uint64_t bytes=0); std::map<std::string,Stage> snapshot();
};
class Scope {Profiler* p_; const char* stage_; Clock::time_point start_; std::uint64_t bytes_;
 public: Scope(Profiler& p,const char* stage,std::uint64_t bytes=0):p_(&p),stage_(stage),start_(Clock::now()),bytes_(bytes){} ~Scope(); Scope(const Scope&)=delete; Scope& operator=(const Scope&)=delete;};
struct FiniteFailure {std::size_t index{}; float value{};};
std::optional<FiniteFailure> first_nonfinite(std::span<const float> values);
Result compare(std::span<const float> reference,std::span<const float> actual,float atol=1e-4f,float rtol=1e-3f);
// Q8_0 layout: 2-byte IEEE754 half scale, 32 signed 8-bit values. GGUF block size 34.
float half_to_float(std::uint16_t bits);
Result q8_0_dot(std::span<const std::byte> packed,std::span<const float> rhs,float& out);
struct FenceTrace {std::uint64_t submit_id{},wait_ns{},waited_for_submit{},gpu_index{}; bool dependency_confirmed{};};
Result audit_fences(std::span<const FenceTrace> trace,std::vector<std::uint64_t>& candidate_wait_ids);
struct ResidencyBudget {std::uint64_t capacity{},reserved{}; bool try_reserve(std::uint64_t n); void release(std::uint64_t n);};
struct Placement {std::uint32_t gpu{}; std::uint64_t bytes{}; double estimated_work{};};
Result validate_placement(std::span<const Placement> placements,std::span<const std::uint64_t> budgets);
struct ExpertHit {std::uint32_t expert{}; std::uint64_t count{};};
std::vector<ExpertHit> top_experts(std::span<const std::uint32_t> ids,std::size_t top_k);
// Greedy verification only: propose one draft token; accepting it is exact if target greedy argmax matches.
struct GreedyDraft {std::uint32_t token{}; bool accepted{};};
GreedyDraft verify_greedy(std::span<const float> target_logits,std::uint32_t proposed);
struct ContextBudget {std::uint64_t weights_bytes{},kv_bytes_per_token{},other_bytes{},memory_budget{};};
std::uint64_t max_context(const ContextBudget& b);
struct PerformanceSample {double prefill_tps{},decode_tps{},p95_ms{}; std::uint64_t peak_bytes{}; bool correct{},fallback{};};
struct PromotionRule {double minimum_gain_pct{3.0}; double maximum_latency_regression_pct{5.0}; std::uint64_t maximum_peak_bytes{};};
Result promote(std::span<const PerformanceSample> baseline,std::span<const PerformanceSample> candidate,const PromotionRule& rule);
struct Profile {std::string model_hash,device_id,quant,kernel; double measured_tps{}; bool certified{};};
std::optional<Profile> choose_profile(std::span<const Profile> profiles,std::string_view model_hash,std::string_view device_id,std::string_view quant);
struct GatewayProbe {bool health{},models{},chat{},stream{},cancel{},agent{},snapshots{},ollama{},deep2{},coexist{},ide{},ghost{};};
Result certify_gateway(const GatewayProbe& p);
std::string json_escape(std::string_view s);
Result write_receipt(const std::filesystem::path& path,const RunConfig& cfg,const CounterView& c,const std::map<std::string,Stage>& stages,const std::map<std::string,Result>& gates);
// Production integration surface: callers attach ONLY to actual executed operations.
void on_gpu_submit(Counters& c,std::uint64_t upload_bytes=0);
void on_gpu_kernel(Counters& c,bool gemm);
void on_gpu_layer_complete(Counters& c);
void on_cpu_fallback(Counters& c);
}
#define RAWRXD_N15_CONCAT_IMPL(a,b) a##b
#define RAWRXD_N15_CONCAT(a,b) RAWRXD_N15_CONCAT_IMPL(a,b)
#define RAWRXD_N15_SCOPE(prof,stage) ::rawrxd::next15::Scope RAWRXD_N15_CONCAT(_rawr_n15_scope_,__LINE__)((prof),(stage))
