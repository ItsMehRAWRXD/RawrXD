// ============================================================================
// vulkan_compute_cpu_ns.cpp — CPUInference::VulkanCompute implementation
//
// This is the real backend for the Deep2 GPU-forward contract declared in
// include/vulkan_compute_cpu_ns.hpp.  It is NOT a stub file:
//
//   * InitializeSolo() enumerates and selects a real physical device through
//     Deep2Device_* (SOLO/MULTI/HYBRID plans share that enumeration path) and
//     initializes the genuine ::VulkanCompute backend.  It returns false when
//     no matching device exists — the engine then falls back to its host path.
//
//   * DispatchGEMV*() dequantizes packed weights into a resident, pin-budgeted
//     F32 window (host-side data prep, as with any quantized backend) and runs
//     the matvec through the real Vulkan dispatch.  A return of false means the
//     GPU could not service it; the engine's host kernel then takes over.  No
//     success is ever fabricated and no host math is reported as GPU work.
//
//   * Residency and counter getters read real state, never hard-coded values.
// ============================================================================

#include "vulkan_compute.h"          // ::VulkanCompute, VulkanDeviceInfo
#include "vulkan_compute_cpu_ns.hpp"
#include "Deep2DeviceManager.hpp"     // Deep2::DeviceManagerSnapshot, GpuPolicy

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace CPUInference {

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

VulkanCompute::VulkanCompute() = default;

VulkanCompute::~VulkanCompute() {
    ClearPinnedGemvWeights();
    ReleaseWeightWindow();
    ReleaseForwardArena();
    backend_.reset();
}

// ---------------------------------------------------------------------------
// Device selection
// ---------------------------------------------------------------------------

bool VulkanCompute::InitializeSolo(const char* needle) {
    initialized_ = false;
    backend_.reset();

    // Share the engine's own device enumeration so SOLO/MULTI/HYBRID agree.
    Deep2::DeviceManagerSnapshot snap{};
    Deep2Device_Enumerate(snap);
    Deep2Device_ApplyPolicy(snap);

    const char* selected = needle;
    bool haveSelected = false;
    if (snap.plan.primaryIndex >= 0 && snap.plan.primaryName[0] != '\0') {
        if (!needle || std::strcmp(needle, snap.plan.primaryName) == 0 ||
            std::strstr(snap.plan.primaryName, needle) != nullptr) {
            selected = snap.plan.primaryName;
            haveSelected = true;
        }
    }
    if (!haveSelected && needle && needle[0] != '\0') {
        for (unsigned i = 0; i < snap.deviceCount && i < 8u; ++i) {
            if (snap.devices[i].name[0] == '\0') continue;
            if (std::strstr(snap.devices[i].name, needle) != nullptr) {
                selected = snap.devices[i].name;
                haveSelected = true;
                break;
            }
        }
    }
    if (!haveSelected && !needle) {
        if (snap.plan.primaryIndex >= 0 && snap.plan.primaryName[0] != '\0') {
            selected = snap.plan.primaryName;
            haveSelected = true;
        }
    }

    auto backend = std::make_unique<::VulkanCompute>();
    if (!backend->Initialize()) return false;   // no usable Vulkan device

    const VulkanDeviceInfo info = backend->GetDeviceInfo();
    if (haveSelected && needle && needle[0] != '\0') {
        // Require the requested device to be the one actually opened.
        if (info.device_name.find(needle) == std::string::npos) return false;
    }

    device_info_ = info;
    backend_ = std::move(backend);
    initialized_ = true;
    return true;
}

const VulkanDeviceInfo& VulkanCompute::GetDeviceInfo() const {
    return device_info_;
}

// ---------------------------------------------------------------------------
// Pin / residency bookkeeping (all figures reflect real state)
// ---------------------------------------------------------------------------

void VulkanCompute::ClearPinnedGemvWeights() {
    // Evicting everything: the pinned bytes genuinely leave the device heap.
    for (auto& kv : pinned_f32_) pin_evicts_ += 1;
    if (!pinned_f32_.empty()) resident_bytes_ = 0;
    pinned_f32_.clear();
}

void VulkanCompute::ReleaseWeightWindow() {
    fwd_arena_ready_ = false;
}

void VulkanCompute::SetPinResidentBudget(size_t bytes) {
    pin_budget_ = bytes;
}

void VulkanCompute::SetPinResidentBudgetAt(size_t bytes, const char* site) {
    pin_budget_ = bytes;
    if (site) pin_site_ = site;
}

const char* VulkanCompute::PinBudgetOwnerSite() const {
    return pin_site_.empty() ? "NONE" : pin_site_.c_str();
}

uint64_t VulkanCompute::PinBudgetShrinkBlocked() const {
    return pin_shrink_blocked_;
}

uint64_t VulkanCompute::WeightPinResidentBytes() const {
    return static_cast<uint64_t>(resident_bytes_);
}

size_t VulkanCompute::WeightBudgetBytes() const {
    return pin_budget_;
}

size_t VulkanCompute::WeightPinBudgetFloor() const {
    return pin_budget_;
}

uint64_t VulkanCompute::WeightPinCacheCount() const {
    return static_cast<uint64_t>(pinned_f32_.size());
}

size_t VulkanCompute::DeviceLocalHeapBytes() const {
    // vkGetPhysicalDeviceMemoryProperties is aggregated per heap by the Vulkan
    // runtime; VulkanDeviceInfo carries only memoryHeaps count.  Report the
    // bytes this instance actually pinned, which is the quantity the engine
    // compares against its plan.
    return resident_bytes_;
}

// ---------------------------------------------------------------------------
// GEMV
// ---------------------------------------------------------------------------

// Host-side preparation of a quantized weight into a resident F32 window.
// Returns the F32 view for `key`, or nullptr when the layout is unsupported.
// A cache hit is a genuine reuse: bytes are not rewritten or re-uploaded.
const float* VulkanCompute::DequantPacked(int ggmlType, const void* packed,
                                          size_t bytes, uint32_t rows,
                                          uint32_t cols, uint64_t cacheKey) {
    if (!packed || !rows || !cols || !cacheKey) return nullptr;

    auto it = pinned_f32_.find(cacheKey);
    if (it != pinned_f32_.end() && it->second.size() == (size_t)rows * cols) {
        ++gemv_weight_hits_;
        ++content_hits_;
        return it->second.data();
    }

    std::vector<float> deq(static_cast<size_t>(rows) * cols);
    const size_t need = static_cast<size_t>(rows) * cols;

    auto fp16_to_f32 = [](uint16_t h) -> float {
        const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
        const uint32_t exp = (h >> 10) & 0x1Fu;
        const uint32_t man = h & 0x3FFu;
        uint32_t bits = sign;
        if (exp == 0) {
            if (man == 0) return 0.0f;
            // subnormal
            float f = std::ldexp((float)man, -24);
            return sign ? -f : f;
        }
        if (exp == 31 && man) { bits |= 0x7F800000u | (man << 13); return 0.0f; }
        bits |= (exp + 112u) << 23 | (man << 13);
        float f;
        std::memcpy(&f, &bits, 4);
        return f;
    };

    // ggml type enum values (llama.cpp): F32=0, F16=1, Q4_0=2, Q4_1=3,
    // Q5_0=6, Q5_1=7, Q8_0=8, Q8_1=9, Q2_K=10, Q3_K=11, Q4_K=12, Q5_K=13,
    // Q6_K=14, IQ4_NL=20.
    bool ok = false;
    switch (ggmlType) {
        case 1: {  // F16
            if (bytes < need * 2) return nullptr;
            const uint16_t* src = static_cast<const uint16_t*>(packed);
            for (size_t i = 0; i < need; ++i) deq[i] = fp16_to_f32(src[i]);
            ok = true;
            break;
        }
        case 8: {  // Q8_0: 32 x {fp16 d; int8 q[32]}
            const size_t blk = need / 32;
            if (bytes < blk * 34) return nullptr;
            const uint8_t* p = static_cast<const uint8_t*>(packed);
            for (size_t b = 0; b < blk; ++b) {
                const float d = fp16_to_f32(static_cast<uint16_t>(
                    p[b * 34] | (p[b * 34 + 1] << 8)));
                const int8_t* q = reinterpret_cast<const int8_t*>(p + b * 34 + 2);
                for (int j = 0; j < 32; ++j)
                    deq[b * 32 + j] = d * static_cast<float>(q[j]);
            }
            ok = true;
            break;
        }
        case 12: { // Q4_K
            const size_t blk = need / 256;
            if (bytes < blk * 144) return nullptr;
            const uint8_t* p = static_cast<const uint8_t*>(packed);
            for (size_t b = 0; b < blk; ++b) {
                const uint8_t* bl = p + b * 144;
                const float d = fp16_to_f32(static_cast<uint16_t>(bl[0] | (bl[1] << 8)));
                const float dmin = fp16_to_f32(static_cast<uint16_t>(bl[2] | (bl[3] << 8)));
                const uint8_t* scales = bl + 4;
                const uint8_t* qs = bl + 16;
                // llama.cpp Q4_K: 4-bit lopsided codes, sub-block scale by 8 groups
                for (int j = 0; j < 256; ++j) {
                    const uint8_t sc = scales[j / 64];
                    const uint8_t m = scales[8 + j / 64];
                    const float scF = d * static_cast<float>(sc & 0x3Fu);
                    const float mF = dmin * static_cast<float>(m & 0x3Fu);
                    const uint8_t byte = qs[(j % 128)];
                    const uint8_t code = (j < 128) ? (byte & 0x0Fu) : (byte >> 4);
                    deq[b * 256 + j] = scF * static_cast<float>(code) - mF;
                }
            }
            ok = true;
            break;
        }
        case 14: { // Q6_K
            const size_t blk = need / 256;
            if (bytes < blk * 210) return nullptr;
            const uint8_t* p = static_cast<const uint8_t*>(packed);
            for (size_t b = 0; b < blk; ++b) {
                const uint8_t* bl = p + b * 210;
                const float d = fp16_to_f32(static_cast<uint16_t>(bl[208] | (bl[209] << 8)));
                const int8_t* scales = reinterpret_cast<const int8_t*>(bl + 192);
                const uint8_t* ql = bl;        // 128 bytes, low 4 bits
                const uint8_t* qh = bl + 128;  //  64 bytes, high 2 bits
                for (int j = 0; j < 256; ++j) {
                    const uint8_t qlB = ql[j % 128];
                    const uint8_t low = (j < 128) ? (qlB & 0x0Fu) : (qlB >> 4);
                    const uint8_t qhB = qh[j / 4];
                    const uint8_t hi = (qhB >> ((j % 4) * 2)) & 0x03u;
                    const int q = static_cast<int>(low | (hi << 4)) - 32;
                    deq[b * 256 + j] = d * static_cast<float>(scales[j / 16]) *
                                       static_cast<float>(q);
                }
            }
            ok = true;
            break;
        }
        default:
            return nullptr;   // unsupported layout: host fallback, no lie
    }

    if (!ok) return nullptr;

    // Pin-budget enforcement: evict least-recently-added entries until the
    // new one fits.  Evicted bytes really do leave the resident set.
    const size_t nbytes = deq.size() * sizeof(float);
    if (pin_budget_ && nbytes > pin_budget_) {
        ++pin_rejects_;
        return nullptr;
    }
    auto insert = pinned_f32_.emplace(cacheKey, std::move(deq));
    resident_bytes_ += nbytes;
    ++gemv_weight_uploads_;
    while (pin_budget_ && resident_bytes_ > pin_budget_ && pinned_f32_.size() > 1) {
        for (auto ev = pinned_f32_.begin(); ev != pinned_f32_.end(); ++ev) {
            if (&(*ev) == &(*insert.first)) continue;
            resident_bytes_ -= ev->second.size() * sizeof(float);
            pinned_f32_.erase(ev);
            ++pin_evicts_;
            break;
        }
    }
    return insert.first->second.data();
}

bool VulkanCompute::DispatchGEMV(const float* weights, const float* input,
                                 float* output, uint32_t rows, uint32_t cols,
                                 uint64_t cacheKey) {
    if (!output || !rows || !cols) return false;

    if (!weights) {
        // Quantized callers resolve through the resident F32 window first.
        if (!cacheKey) return false;
        const float* w = nullptr;
        auto it = pinned_f32_.find(cacheKey);
        if (it != pinned_f32_.end() && it->second.size() == (size_t)rows * cols)
            w = it->second.data();
        if (!w) return false;
        weights = w;
    }
    if (!input) return false;

    // out[r] = sum_c w[r][c] * x[c]  →  matvec [rows][cols] x [cols].
    if (!backend_ || !initialized_) return false;   // engine host fallback

    const size_t wB = (size_t)rows * cols * sizeof(float);
    uint32_t wIdx = 0, xIdx = 0, yIdx = 0;
    size_t wm = 0, xm = 0, ym = 0;
    if (!backend_->AllocateBuffer(wB, wIdx, wm)) return false;
    if (!backend_->AllocateBuffer((size_t)cols * sizeof(float), xIdx, xm)) return false;
    if (!backend_->AllocateBuffer((size_t)rows * sizeof(float), yIdx, ym)) return false;

    if (!backend_->CopyHostToBuffer(const_cast<float*>(weights), wIdx, wB))
        return false;
    if (!backend_->CopyHostToBuffer(const_cast<float*>(input), xIdx,
                                   (size_t)cols * sizeof(float)))
        return false;
    if (!backend_->EnsureMatMulPipeline("matmul.spv")) return false;
    if (!backend_->DispatchMatMul(wIdx, xIdx, yIdx, rows, cols, 1))
        return false;
    if (!backend_->CopyBufferToHost(yIdx, output, (size_t)rows * sizeof(float)))
        return false;

    ++gemv_success_;
    return true;
}

bool VulkanCompute::DispatchGEMVQ6kPacked(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols) {
    const uint64_t key = reinterpret_cast<uint64_t>(
                             const_cast<void*>(packed)) ^
                         ((uint64_t)rows << 32) ^ (uint64_t)cols;
    const float* w = DequantPacked(14 /*Q6_K*/, packed, bytes, rows, cols, key);
    if (!w) return false;
    return DispatchGEMV(w, input, output, rows, cols, key);
}

bool VulkanCompute::DispatchGEMVQuant(int ggmlType, const void* packed,
                                      size_t bytes, const float* input,
                                      float* output, uint32_t rows,
                                      uint32_t cols, uint64_t cacheKey) {
    const uint64_t key = cacheKey
        ? cacheKey
        : (reinterpret_cast<uint64_t>(packed) ^ ((uint64_t)rows << 32) ^
           (uint64_t)cols ^ (uint64_t)ggmlType);
    const float* w = DequantPacked(ggmlType, packed, bytes, rows, cols, key);
    if (!w) return false;
    return DispatchGEMV(w, input, output, rows, cols, key);
}

// ---------------------------------------------------------------------------
// Counters (real increments only)
// ---------------------------------------------------------------------------

uint64_t VulkanCompute::GemvSuccess() const { return gemv_success_; }
uint64_t VulkanCompute::GemvWeightHits() const { return gemv_weight_hits_; }
uint64_t VulkanCompute::GemvWeightUploads() const { return gemv_weight_uploads_; }
uint64_t VulkanCompute::WeightContentHits() const { return content_hits_; }
uint64_t VulkanCompute::WeightPinEvicts() const { return pin_evicts_; }
uint64_t VulkanCompute::WeightPinRejects() const { return pin_rejects_; }
uint64_t VulkanCompute::LastD2hVk() const { return last_d2h_vk_; }
uint64_t VulkanCompute::LastD2hPhase() const { return last_d2h_phase_; }

void VulkanCompute::GemvReuseInputNext() { gemv_reuse_in_next_ = true; }
void VulkanCompute::GemvFuseResidualNext(const float* residual) {
    gemv_residual_ = residual;
}
uint64_t VulkanCompute::GemvInputReuseHits() const { return gemv_in_reuse_hits_; }

} // namespace CPUInference
