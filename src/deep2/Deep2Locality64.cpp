#include "Deep2Locality64.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace Deep2 {

Locality64Collector::Locality64Collector() { reset(); }

void Locality64Collector::reset() {
    armed_.store(false, std::memory_order_relaxed);
    overflow_.store(false, std::memory_order_relaxed);
    sequence_error_.store(false, std::memory_order_relaxed);
    for (auto& v : demand_) v.store(0, std::memory_order_relaxed);
    for (auto& v : local_) v.store(0, std::memory_order_relaxed);
    h2d_.store(0, std::memory_order_relaxed);
    critical_host_.store(0, std::memory_order_relaxed);
    inter_gpu_.store(0, std::memory_order_relaxed);
    for (auto& v : gpu_fwd_) v.store(0, std::memory_order_relaxed);
    std::lock_guard<std::mutex> g(mu_);
    token_begin_.fill(0);
    token_ns_.fill(0);
    for (auto& t : spans_) for (auto& s : t) s = {};
    measured_tokens_ = 0;
    window_begin_ns_ = 0;
    window_end_ns_ = 0;
}

void Locality64Collector::setArmed(bool v) { armed_.store(v, std::memory_order_release); }
bool Locality64Collector::armed() const { return armed_.load(std::memory_order_acquire); }

bool Locality64Collector::addSat(std::atomic<uint64_t>& dst, uint64_t add,
                                 std::atomic<bool>& overflow) {
    uint64_t old = dst.load(std::memory_order_relaxed);
    for (;;) {
        if (add > std::numeric_limits<uint64_t>::max() - old) {
            dst.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
            overflow.store(true, std::memory_order_relaxed);
            return false;
        }
        if (dst.compare_exchange_weak(old, old + add,
                                      std::memory_order_relaxed,
                                      std::memory_order_relaxed)) return true;
    }
}

void Locality64Collector::beginWindow(uint64_t now_ns) {
    if (!armed()) { sequence_error_.store(true); return; }
    std::lock_guard<std::mutex> g(mu_);
    if (window_begin_ns_ != 0 || now_ns == 0) { sequence_error_.store(true); return; }
    window_begin_ns_ = now_ns;
}

bool Locality64Collector::beginToken(uint64_t ordinal, uint64_t now_ns) {
    if (!armed() || ordinal >= kTargetTokens || now_ns == 0) {
        sequence_error_.store(true); return false;
    }
    std::lock_guard<std::mutex> g(mu_);
    if (!window_begin_ns_ || token_begin_[ordinal] != 0 || token_ns_[ordinal] != 0) {
        sequence_error_.store(true); return false;
    }
    token_begin_[ordinal] = now_ns;
    return true;
}

bool Locality64Collector::endToken(uint64_t ordinal, uint64_t now_ns) {
    if (!armed() || ordinal >= kTargetTokens || now_ns == 0) {
        sequence_error_.store(true); return false;
    }
    std::lock_guard<std::mutex> g(mu_);
    const uint64_t b = token_begin_[ordinal];
    if (!b || now_ns <= b || token_ns_[ordinal] != 0) {
        sequence_error_.store(true); return false;
    }
    token_ns_[ordinal] = now_ns - b;
    ++measured_tokens_;
    return true;
}

void Locality64Collector::endWindow(uint64_t now_ns) {
    std::lock_guard<std::mutex> g(mu_);
    if (!window_begin_ns_ || now_ns <= window_begin_ns_ || window_end_ns_ != 0)
        sequence_error_.store(true);
    else
        window_end_ns_ = now_ns;
}

void Locality64Collector::noteDemand(LocalityKind kind, uint64_t bytes, bool already_local) {
    if (!armed() || bytes == 0) return;
    const auto i = static_cast<size_t>(kind);
    if (i >= demand_.size()) { sequence_error_.store(true); return; }
    addSat(demand_[i], bytes, overflow_);
    if (already_local) addSat(local_[i], bytes, overflow_);
}

void Locality64Collector::noteHostToDevice(uint64_t bytes, bool critical) {
    if (!armed() || !bytes) return;
    addSat(h2d_, bytes, overflow_);
    if (critical) addSat(critical_host_, bytes, overflow_);
}

void Locality64Collector::noteInterGpu(uint64_t bytes) {
    if (!armed() || !bytes) return;
    addSat(inter_gpu_, bytes, overflow_);
}

void Locality64Collector::noteGpuForwardSpan(unsigned gpu_slot, uint64_t token_ordinal,
                                              uint64_t start_ns, uint64_t end_ns) {
    if (!armed()) return;
    if (gpu_slot >= 2 || token_ordinal >= kTargetTokens || !start_ns || end_ns <= start_ns) {
        sequence_error_.store(true); return;
    }
    addSat(gpu_fwd_[gpu_slot], 1, overflow_);
    std::lock_guard<std::mutex> g(mu_);
    Span& s = spans_[token_ordinal][gpu_slot];
    if (!s.valid) { s = {start_ns, end_ns, true}; return; }
    if (start_ns < s.start) s.start = start_ns;
    if (end_ns > s.end) s.end = end_ns;
}

uint64_t Locality64Collector::percentile(std::array<uint64_t, kTargetTokens> a,
                                         uint64_t n, unsigned pct) {
    if (!n || n > kTargetTokens) return 0;
    std::sort(a.begin(), a.begin() + static_cast<std::ptrdiff_t>(n));
    const uint64_t rank = ((n * pct) + 99u) / 100u; // nearest-rank, 1-based
    const uint64_t idx = rank ? rank - 1 : 0;
    return a[static_cast<size_t>(idx < n ? idx : n - 1)];
}

Locality64Snapshot Locality64Collector::snapshot() const {
    Locality64Snapshot s{};
    uint64_t demand_total = 0, local_total = 0;
    for (size_t i = 0; i < demand_.size(); ++i) {
        const uint64_t d = demand_[i].load(std::memory_order_relaxed);
        const uint64_t l = local_[i].load(std::memory_order_relaxed);
        if (l > d) s.sequence_error = true;
        if (demand_total > UINT64_MAX - d || local_total > UINT64_MAX - l) s.accounting_overflow = true;
        else { demand_total += d; local_total += l; }
    }
    s.demand_bytes_total = demand_total;
    s.already_local_bytes_total = local_total;
    if (local_total <= demand_total) s.bytes_not_already_local_total = demand_total - local_total;
    else s.sequence_error = true;

    const size_t w = static_cast<size_t>(LocalityKind::Weight);
    const size_t k = static_cast<size_t>(LocalityKind::KV);
    s.weight_bytes_requested_total = demand_[w].load(std::memory_order_relaxed);
    s.weight_bytes_already_local = local_[w].load(std::memory_order_relaxed);
    s.kv_bytes_requested_total = demand_[k].load(std::memory_order_relaxed);
    s.kv_bytes_already_local = local_[k].load(std::memory_order_relaxed);
    s.host_to_device_bytes = h2d_.load(std::memory_order_relaxed);
    s.critical_path_host_bytes = critical_host_.load(std::memory_order_relaxed);
    s.inter_gpu_bytes = inter_gpu_.load(std::memory_order_relaxed);
    s.gpu0_forward_count = gpu_fwd_[0].load(std::memory_order_relaxed);
    s.gpu1_forward_count = gpu_fwd_[1].load(std::memory_order_relaxed);
    s.accounting_overflow = s.accounting_overflow || overflow_.load(std::memory_order_relaxed);
    s.sequence_error = s.sequence_error || sequence_error_.load(std::memory_order_relaxed);

    std::lock_guard<std::mutex> g(mu_);
    s.measured_tokens = measured_tokens_;
    if (window_begin_ns_ && window_end_ns_ > window_begin_ns_)
        s.generation_wall_ns = window_end_ns_ - window_begin_ns_;

    uint64_t maxv = 0, overlap = 0;
    for (uint64_t i = 0; i < measured_tokens_ && i < kTargetTokens; ++i) {
        if (token_ns_[i] > maxv) maxv = token_ns_[i];
        const Span& a = spans_[i][0];
        const Span& b = spans_[i][1];
        if (a.valid && b.valid && a.start < b.end && b.start < a.end) ++overlap;
    }
    s.same_token_overlap_count = overlap;
    s.token_ns_p50 = percentile(token_ns_, measured_tokens_, 50);
    s.token_ns_p95 = percentile(token_ns_, measured_tokens_, 95);
    s.token_ns_max = maxv;
    if (s.generation_wall_ns && s.measured_tokens)
        s.tps_milli = (s.measured_tokens * 1000000000000ull) / s.generation_wall_ns;
    return s;
}

Locality64Verdict Locality64Collector::evaluate(const Locality64ParentSeal& p,
                                                 const Locality64Policy& policy) const {
    Locality64Verdict v{};
    v.s = snapshot();
    v.exact_64 = (v.s.measured_tokens == kTargetTokens);
    v.parents_sealed = p.bind16_sealed && p.persistent_decode_sealed && p.residency_sealed;
    v.residency_still_zero_delta =
        p.weight_upload_delta == 0 && p.device_create_delta == 0 &&
        p.model_load_delta == 0 && p.reload_bytes_delta == 0 && p.pin_evict_delta == 0;
    v.accounting_valid = !v.s.accounting_overflow && !v.s.sequence_error &&
                         v.s.demand_bytes_total > 0 &&
                         v.s.already_local_bytes_total <= v.s.demand_bytes_total;
    v.timing_valid = v.s.generation_wall_ns > 0 && v.s.token_ns_p50 > 0 &&
                     v.s.token_ns_p95 > 0 && v.s.token_ns_max > 0;
    v.threshold_configured = policy.max_nonlocal_bytes_per_token > 0;

    const uint64_t denom = v.s.measured_tokens ? v.s.measured_tokens : 1;
    const uint64_t nonlocal_bpt = v.s.bytes_not_already_local_total / denom;
    const uint64_t critical_bpt = v.s.critical_path_host_bytes / denom;
    const uint64_t inter_bpt = v.s.inter_gpu_bytes / denom;

    v.locality_limit_ok = v.threshold_configured &&
                          nonlocal_bpt <= policy.max_nonlocal_bytes_per_token;
    v.critical_host_limit_ok =
        policy.max_critical_path_host_bytes_per_token == UINT64_MAX ||
        critical_bpt <= policy.max_critical_path_host_bytes_per_token;
    v.inter_gpu_limit_ok =
        policy.max_inter_gpu_bytes_per_token == UINT64_MAX ||
        inter_bpt <= policy.max_inter_gpu_bytes_per_token;
    v.dual_gpu_ok = !policy.require_dual_gpu ||
                    (v.s.gpu0_forward_count > 0 && v.s.gpu1_forward_count > 0);
    v.overlap_ok = !policy.require_same_token_overlap || v.s.same_token_overlap_count > 0;

    v.conjunction = v.exact_64 && v.parents_sealed && v.residency_still_zero_delta &&
                    v.accounting_valid && v.timing_valid && v.threshold_configured &&
                    v.locality_limit_ok && v.critical_host_limit_ok &&
                    v.inter_gpu_limit_ok && v.dual_gpu_ok && v.overlap_ok;
    return v;
}

int Locality64Collector::writeReceipt(const char* path,
                                      const Locality64ParentSeal& p,
                                      const Locality64Policy& policy,
                                      const Locality64Verdict& v,
                                      uint64_t raw_generated_tokens) {
    if (!path) return 1;
    FILE* f = std::fopen(path, "wb");
    if (!f) return 1;
    const uint64_t n = v.s.measured_tokens ? v.s.measured_tokens : 1;
    const uint64_t nonlocal_bpt = v.s.bytes_not_already_local_total / n;
    const uint64_t critical_bpt = v.s.critical_path_host_bytes / n;
    const uint64_t inter_bpt = v.s.inter_gpu_bytes / n;

    std::fprintf(f, "GATE=DEEP2_ROOFLINE_LOCALITY_001\n");
    std::fprintf(f, "STATUS=%s\n", v.conjunction ? "LIVE_PRODUCT_PASS" : "RUNTIME_HOLD");
    std::fprintf(f, "TARGET=64\nGENERATED_TOKENS=%llu\nRAW_GENERATED_TOKENS=%llu\n",
                 (unsigned long long)v.s.measured_tokens,
                 (unsigned long long)raw_generated_tokens);
    std::fprintf(f, "BIND16_SEALED=%d\nPERSISTENT_DECODE_SEALED=%d\nRESIDENCY_SEALED=%d\n",
                 p.bind16_sealed ? 1 : 0, p.persistent_decode_sealed ? 1 : 0,
                 p.residency_sealed ? 1 : 0);
    std::fprintf(f, "wup_d=%llu\nDEVICE_CREATE_DELTA=%llu\nMODEL_LOAD_DELTA=%llu\nRELOAD_B_DELTA=%llu\nPIN_EVICT_DELTA=%llu\n",
                 (unsigned long long)p.weight_upload_delta,
                 (unsigned long long)p.device_create_delta,
                 (unsigned long long)p.model_load_delta,
                 (unsigned long long)p.reload_bytes_delta,
                 (unsigned long long)p.pin_evict_delta);
    std::fprintf(f, "WEIGHT_BYTES_REQUESTED_TOTAL=%llu\nWEIGHT_BYTES_ALREADY_LOCAL=%llu\n",
                 (unsigned long long)v.s.weight_bytes_requested_total,
                 (unsigned long long)v.s.weight_bytes_already_local);
    std::fprintf(f, "KV_BYTES_REQUESTED_TOTAL=%llu\nKV_BYTES_ALREADY_LOCAL=%llu\n",
                 (unsigned long long)v.s.kv_bytes_requested_total,
                 (unsigned long long)v.s.kv_bytes_already_local);
    std::fprintf(f, "BYTES_NOT_ALREADY_LOCAL_TOTAL=%llu\nBYTES_NOT_ALREADY_LOCAL_PER_TOKEN=%llu\n",
                 (unsigned long long)v.s.bytes_not_already_local_total,
                 (unsigned long long)nonlocal_bpt);
    std::fprintf(f, "HOST_TO_DEVICE_BYTES=%llu\nINTER_GPU_BYTES=%llu\nCRITICAL_PATH_HOST_BYTES=%llu\n",
                 (unsigned long long)v.s.host_to_device_bytes,
                 (unsigned long long)v.s.inter_gpu_bytes,
                 (unsigned long long)v.s.critical_path_host_bytes);
    std::fprintf(f, "CRITICAL_PATH_HOST_BYTES_PER_TOKEN=%llu\nINTER_GPU_BYTES_PER_TOKEN=%llu\n",
                 (unsigned long long)critical_bpt, (unsigned long long)inter_bpt);
    std::fprintf(f, "GPU0_FORWARD_COUNT=%llu\nGPU1_FORWARD_COUNT=%llu\nSAME_TOKEN_OVERLAP_COUNT=%llu\n",
                 (unsigned long long)v.s.gpu0_forward_count,
                 (unsigned long long)v.s.gpu1_forward_count,
                 (unsigned long long)v.s.same_token_overlap_count);
    std::fprintf(f, "GENERATION_WALL_NS=%llu\nTOKEN_NS_P50=%llu\nTOKEN_NS_P95=%llu\nTOKEN_NS_MAX=%llu\nTPS_MEASURED_MILLI=%llu\n",
                 (unsigned long long)v.s.generation_wall_ns,
                 (unsigned long long)v.s.token_ns_p50,
                 (unsigned long long)v.s.token_ns_p95,
                 (unsigned long long)v.s.token_ns_max,
                 (unsigned long long)v.s.tps_milli);
    std::fprintf(f, "MAX_NONLOCAL_BYTES_PER_TOKEN=%llu\nMAX_CRITICAL_PATH_HOST_BYTES_PER_TOKEN=%llu\nMAX_INTER_GPU_BYTES_PER_TOKEN=%llu\n",
                 (unsigned long long)policy.max_nonlocal_bytes_per_token,
                 (unsigned long long)policy.max_critical_path_host_bytes_per_token,
                 (unsigned long long)policy.max_inter_gpu_bytes_per_token);
    std::fprintf(f, "CONJ_OPS exact64=%d parents=%d residency_zero_delta=%d accounting=%d timing=%d threshold=%d locality=%d critical_host=%d inter_gpu=%d dual=%d overlap=%d\n",
                 v.exact_64, v.parents_sealed, v.residency_still_zero_delta,
                 v.accounting_valid, v.timing_valid, v.threshold_configured,
                 v.locality_limit_ok, v.critical_host_limit_ok,
                 v.inter_gpu_limit_ok, v.dual_gpu_ok, v.overlap_ok);
    std::fprintf(f, "ROOFLINE_LOCALITY=%s\nCERT_EXIT=%d\nPROMOTE=0\nTIP_CLIMB=HOLD\n",
                 v.conjunction ? "PASS" : "FAIL", v.conjunction ? 0 : 2);
    std::fprintf(f, "NEXT=%s\nNOT_RUN!=PASS\n",
                 v.conjunction ? "ROOFLINE_LOCALITY_64_SEALED_NEXT_GATE" :
                                 "DEEP2_ROOFLINE_LOCALITY_001");
    std::fclose(f);
    return 0;
}

Locality64Collector& Locality64_Global() {
    static Locality64Collector g;
    return g;
}

} // namespace Deep2
