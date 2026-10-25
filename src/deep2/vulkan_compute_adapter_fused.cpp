// ============================================================================
// vulkan_compute_adapter_fused.cpp -- the rest of CPUInference::VulkanCompute
// ============================================================================
// include/vulkan_compute_cpu_ns.hpp declares the full engine-facing GPU
// contract, but only a handful of its members were ever defined (see
// vulkan_compute_engine_adapter.cpp: InitializeSolo, DispatchGEMV,
// DispatchGEMVQuant, the Gemv* counters, GetDeviceInfo, SetPinResidentBudget).
// The other 23 are called from the live MLA path (K2MLA_GpuGemv.cpp,
// K2MLA_FusedQ4KT.cpp, K2MLA_QPathDevice.cpp, K2QbGemvDirectHost.hpp,
// K2GpuStreamCopy.cpp) and were unresolved.
//
// RULE FOLLOWED HERE: forward real capability, fail closed where it is absent.
// Deep2::VulkanCompute is the real implementation. Where it has an entry point
// this file calls it, so the work happens on the device. Where it does not --
// there is no pinned-F32 map, no pin-evict/reject counters, no ensure-host-io,
// no stream-to-slot, and recordCopy() needs a full command buffer that a raw
// VkBuffer pair cannot supply -- the member returns false and the caller's
// documented hand-off to the host path runs. No member reports success for a
// dispatch that did not happen.
//
//   BeginFusedLayer / EndFusedLayer   backend BeginFusedLayer/EndFusedLayer
//   EnsureForwardArena                backend EnsureForwardArena
//   DispatchRmsNorm                   backend DispatchRmsNorm
//   DispatchGEMVFusedQ4KT             backend DispatchGemvQ4KBatch (Q4_K=12)
//   DispatchGEMVQ6kPacked             backend DispatchGemvQuant (Q6_K=14)
//   EnsureGemvActDevice/GemvAct*      backend arena + Upload/DownloadVector
//   WeightBudgetBytes                 the adapter's own pin budget
// ============================================================================
#include "vulkan_compute_cpu_ns.hpp"
#include "vulkan_compute.h"

#include <cstring>

namespace {

// GGML type codes as used throughout this tree (GGUFLoader.hpp).
constexpr int GGML_TYPE_Q4_K = 12;
constexpr int GGML_TYPE_Q6_K = 14;

// Translate the contract's DeviceBuf into the implementation's. Both are plain
// VkBuffer/VkDeviceMemory/size triples; the contract field is `bytes`, the
// implementation's is `size`. memoryFlags is not carried across because the
// implementation infers locality from its own allocation bookkeeping.
Deep2::VulkanCompute::DeviceBuf ToBackend(const CPUInference::VulkanCompute::DeviceBuf& b) {
    Deep2::VulkanCompute::DeviceBuf o{};
    o.buffer = b.buffer;
    o.memory = b.memory;
    o.size = static_cast<VkDeviceSize>(b.bytes);
    return o;
}

CPUInference::VulkanCompute::DeviceBuf FromBackend(const Deep2::VulkanCompute::DeviceBuf& b) {
    CPUInference::VulkanCompute::DeviceBuf o{};
    o.buffer = b.buffer;
    o.memory = b.memory;
    o.bytes = static_cast<size_t>(b.size);
    return o;
}

bool HostVisible(const Deep2::VulkanCompute::DeviceBuf& b) {
    return (b.memoryFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) != 0;
}

} // namespace

namespace CPUInference {

// ----------------------------------------------------------------------------
// Forward arena / host activation and the weight prefetch window
//
// These forward to the implementation's own arena and weight-window API, so a
// prefetch, an upload, a wait and a flush all run on the real device.
// ----------------------------------------------------------------------------
VulkanCompute::DeviceBuf& VulkanCompute::ArenaHidden() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaHidden());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaNormed() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaNormed());
    return mirror;
}

bool VulkanCompute::UploadHidden(const float* src, uint32_t count) {
    if (backend_ == nullptr || src == nullptr) return false;
    if (count == 0) return false;
    return backend_->UploadHidden(src, count);
}

bool VulkanCompute::PrefetchWeight(const void* packed, size_t bytes,
                                   uint32_t& slot) {
    if (backend_ == nullptr || packed == nullptr) return false;
    if (bytes == 0) return false;
    return backend_->PrefetchWeight(packed, bytes, slot);
}

bool VulkanCompute::SubmitGemvPrefetch(uint32_t slot, DeviceBuf& in,
                                       DeviceBuf& out, uint32_t rows,
                                       uint32_t cols, size_t bytes,
                                       int ggmlType) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(in);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->SubmitGemvPrefetch(slot, bi, bo, rows, cols, bytes, ggmlType)) {
        return false;
    }
    in = FromBackend(bi);
    out = FromBackend(bo);
    return true;
}

bool VulkanCompute::WaitWeightUpload(uint32_t slot) {
    if (backend_ == nullptr) return false;
    // The implementation names this WaitWeightCompute; it is the wait that
    // pairs with SubmitGemvPrefetch.
    return backend_->WaitWeightCompute(slot);
}

bool VulkanCompute::FlushWeightComputes() {
    if (backend_ == nullptr) return false;
    return backend_->FlushWeightComputes();
}

// ----------------------------------------------------------------------------
// Fused layer lifecycle
// ----------------------------------------------------------------------------
bool VulkanCompute::BeginFusedLayer() {
    if (backend_ == nullptr) return false;
    return backend_->BeginFusedLayer();
}

bool VulkanCompute::EndFusedLayer() {
    if (backend_ == nullptr) return false;
    return backend_->EndFusedLayer();
}

// ----------------------------------------------------------------------------
// Forward arena
//
// Contract   (hidden, inter, nHeads, qCols, kvDim, maxSeq, nLayers)
// Impl       (hidden, intermediate, heads, kvHeads, headDim, maxSeq, layers,
//             kvLayers=0)
// Mapping: qCols -> headDim (query columns per head), kvDim -> kvHeads
// (per-head KV width). The contract exposes no separate kvHeads value, so this
// is the only reading its seven parameters support; kvLayers stays 0, which is
// the implementation's default.
// ----------------------------------------------------------------------------
bool VulkanCompute::EnsureForwardArena(uint32_t hidden, uint32_t inter,
                                       uint32_t nHeads, uint32_t qCols,
                                       uint32_t kvDim, uint32_t maxSeq,
                                       uint32_t nLayers) {
    if (backend_ == nullptr) return false;
    if (hidden == 0 || inter == 0 || nLayers == 0) return false;
    if (qCols == 0 || kvDim == 0 || maxSeq == 0) return false;
    const bool ok = backend_->EnsureForwardArena(hidden, inter, nHeads, kvDim,
                                                 qCols, maxSeq, nLayers, 0);
    if (ok) {
        fwd_arena_ready_ = true;
        gemv_act_in_ = FromBackend(backend_->ArenaNormed());
        gemv_act_out_ = FromBackend(backend_->ArenaResidual());
    }
    return ok;
}

// ----------------------------------------------------------------------------
// Fused kernel dispatch -- RMS norm
// ----------------------------------------------------------------------------
bool VulkanCompute::DispatchRmsNorm(DeviceBuf& in, DeviceBuf& w, DeviceBuf& out,
                                    uint32_t n, float epsilon) {
    if (backend_ == nullptr) return false;
    if (n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(in);
    Deep2::VulkanCompute::DeviceBuf bw = ToBackend(w);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchRmsNorm(bi, bw, bo, n, epsilon)) return false;
    in = FromBackend(bi);
    w = FromBackend(bw);
    out = FromBackend(bo);
    return true;
}

// ----------------------------------------------------------------------------
// GEMV staging -- the activation window the packed dispatches read/write
// ----------------------------------------------------------------------------
bool VulkanCompute::EnsureGemvActDevice(size_t inBytes, size_t outBytes) {
    if (backend_ == nullptr) return false;
    if (inBytes == 0 || outBytes == 0) return false;

    Deep2::VulkanCompute::DeviceBuf& in = backend_->ArenaNormed();
    Deep2::VulkanCompute::DeviceBuf& out = backend_->ArenaResidual();
    if (in.size < inBytes || out.size < outBytes) {
        // Size the arena from the byte counts the caller actually asked for.
        const uint32_t hidden = inBytes / sizeof(float);
        const uint32_t rows = outBytes / sizeof(float);
        if (hidden == 0 || rows == 0) return false;
        if (!backend_->EnsureForwardArena(hidden, hidden, 1, 1, 1, 1, 1)) return false;
        if (backend_->ArenaNormed().size < inBytes ||
            backend_->ArenaResidual().size < outBytes) {
            return false;
        }
    }
    gemv_act_in_ = FromBackend(backend_->ArenaNormed());
    gemv_act_out_ = FromBackend(backend_->ArenaResidual());
    return gemv_act_in_.buffer != VK_NULL_HANDLE &&
           gemv_act_out_.buffer != VK_NULL_HANDLE;
}

VulkanCompute::DeviceBuf& VulkanCompute::GemvActIn() { return gemv_act_in_; }
VulkanCompute::DeviceBuf& VulkanCompute::GemvActOut() { return gemv_act_out_; }

VkBuffer VulkanCompute::GemvHostInBuffer() {
    if (backend_ == nullptr) return VK_NULL_HANDLE;
    const Deep2::VulkanCompute::DeviceBuf& a = backend_->ArenaNormed();
    // Only hand back a host-writable handle when the arena buffer really is
    // host-visible; a device-local buffer returned here would let a caller
    // write into memory the device owns.
    return HostVisible(a) ? a.buffer : VK_NULL_HANDLE;
}

VkBuffer VulkanCompute::GemvHostOutBuffer() {
    if (backend_ == nullptr) return VK_NULL_HANDLE;
    const Deep2::VulkanCompute::DeviceBuf& a = backend_->ArenaResidual();
    return HostVisible(a) ? a.buffer : VK_NULL_HANDLE;
}

bool VulkanCompute::GemvHostWriteIn(const float* src, size_t bytes) {
    if (backend_ == nullptr || src == nullptr) return false;
    if (bytes == 0 || (bytes % sizeof(float)) != 0) return false;
    if (gemv_reuse_in_next_) {
        gemv_reuse_in_next_ = false;
        if (backend_->ArenaNormed().size < bytes) return false;
        ++gemv_in_reuse_hits_;
        return true;
    }
    return backend_->UploadVector(backend_->ArenaNormed(), src, bytes / sizeof(float));
}

bool VulkanCompute::GemvHostReadOut(float* dst, size_t bytes) {
    if (backend_ == nullptr || dst == nullptr) return false;
    if (bytes == 0 || (bytes % sizeof(float)) != 0) return false;
    return backend_->DownloadVector(backend_->ArenaResidual(), dst, bytes / sizeof(float));
}

// ----------------------------------------------------------------------------
// Fused decode kernels
// ----------------------------------------------------------------------------

// Q4_K fused GEMV. The implementation owns a real Q4_K kernel
// (DispatchGemvQ4KBatch, batch=1 for a single token), so this dispatches on the
// device after staging the host activation.
bool VulkanCompute::DispatchGEMVFusedQ4KT(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols,
                                          uint64_t cacheKey) {
    if (backend_ == nullptr) return false;
    if (packed == nullptr || input == nullptr || output == nullptr) return false;
    if (rows == 0 || cols == 0 || bytes == 0) return false;

    Deep2::VulkanCompute::DeviceBuf& in = backend_->ArenaNormed();
    Deep2::VulkanCompute::DeviceBuf& out = backend_->ArenaResidual();
    if (in.size < static_cast<size_t>(cols) * sizeof(float) ||
        out.size < static_cast<size_t>(rows) * sizeof(float)) {
        if (!backend_->EnsureForwardArena(cols, cols, 1, 1, 1, 1, 1)) return false;
    }
    if (!backend_->UploadVector(in, input, cols)) return false;
    if (!backend_->DispatchGemvQ4KBatch(packed, bytes, in, out, rows, cols, 1)) {
        return false;
    }
    if (!backend_->DownloadVector(out, output, rows)) return false;

    gemv_success_ = static_cast<uint64_t>(backend_->GemvSuccessCount());
    gemv_weight_uploads_ = static_cast<uint64_t>(backend_->WeightUploadCount());
    gemv_weight_hits_ = static_cast<uint64_t>(backend_->WeightHitCount());
    return true;
}

// Q6_K logits path: dedicated buffer, never truncated by the weight window.
// The generic quant dispatch implements this kernel, so the host activation is
// staged into the arena and the caller's output buffer is written by the
// device.
bool VulkanCompute::DispatchGEMVQ6kPacked(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols) {
    if (backend_ == nullptr) return false;
    if (packed == nullptr || input == nullptr || output == nullptr) return false;
    if (rows == 0 || cols == 0 || bytes == 0) return false;

    Deep2::VulkanCompute::DeviceBuf& in = backend_->ArenaNormed();
    if (in.size < static_cast<size_t>(cols) * sizeof(float)) {
        if (!backend_->EnsureForwardArena(cols, cols, 1, 1, 1, 1, 1)) return false;
    }
    if (!backend_->UploadVector(in, input, cols)) return false;

    // The contract's signature is host-pointer based; stage the result back out
    // through the arena, which is what keeps the output off the host while the
    // kernel runs.
    Deep2::VulkanCompute::DeviceBuf& out = backend_->ArenaResidual();
    if (out.size < static_cast<size_t>(rows) * sizeof(float)) {
        if (!backend_->EnsureForwardArena(rows, rows, 1, 1, 1, 1, 1)) return false;
    }
    if (!backend_->DispatchGemvQuant(GGML_TYPE_Q6_K, packed, bytes, in, out, rows, cols)) {
        return false;
    }
    if (!backend_->DownloadVector(out, output, rows)) return false;

    gemv_success_ = static_cast<uint64_t>(backend_->GemvSuccessCount());
    gemv_weight_uploads_ = static_cast<uint64_t>(backend_->WeightUploadCount());
    gemv_weight_hits_ = static_cast<uint64_t>(backend_->WeightHitCount());
    return true;
}

// The two device-operand / Q8-KVA forms below have no counterpart in the
// implementation and no honest way to construct one from the arguments given.
// Each fails closed so the caller's host path runs.

bool VulkanCompute::DispatchGemvPacked(const void* packed, size_t bytes,
                                       DeviceBuf& in, DeviceBuf& out,
                                       uint32_t rows, uint32_t cols,
                                       uint64_t cacheKey) {
    (void)packed; (void)bytes; (void)in; (void)out;
    (void)rows; (void)cols; (void)cacheKey;
    // The implementation's quant dispatch is keyed by an explicit GGML type
    // code; this signature carries none, so selecting a kernel would be a guess
    // that could silently run the wrong kernel.
    return false;
}

bool VulkanCompute::DispatchGEMVPacked(const void* packed, size_t bytes,
                                       const float* input, float* output,
                                       uint32_t rows, uint32_t cols,
                                       uint64_t cacheKey) {
    (void)packed; (void)bytes; (void)input; (void)output;
    (void)rows; (void)cols; (void)cacheKey;
    // Same reason as DispatchGemvPacked: no GGML type reaches this entry point,
    // so the kernel cannot be selected honestly.
    return false;
}

bool VulkanCompute::DispatchGEMVFusedQ8Kva(const void* packed, size_t bytes,
                                           const float* input, float* output,
                                           uint32_t rows, uint32_t cols,
                                           uint64_t cacheKey) {
    (void)packed; (void)bytes; (void)input; (void)output;
    (void)rows; (void)cols; (void)cacheKey;
    // The implementation ships no Q8_VA key/value fused kernel, and its generic
    // quant dispatch is keyed by a GGML type code that this call does not carry.
    // There is no device work to dispatch, so the host path keeps the token.
    return false;
}

// ----------------------------------------------------------------------------
// Host IO capability
//
// The backend does not expose a persistent host-visible activation buffer.
// UploadVector/DownloadVector allocate and submit their real Vulkan staging
// transfers internally.  This adapter therefore validates that the forward
// arena has enough device storage for both directions; it does not claim that
// a host-visible buffer exists.
// ----------------------------------------------------------------------------
bool VulkanCompute::EnsureHostIo(size_t actIn, size_t actOut) {
    if (backend_ == nullptr || actIn == 0 || actOut == 0)
        return false;
    const Deep2::VulkanCompute::DeviceBuf& in = backend_->ArenaNormed();
    const Deep2::VulkanCompute::DeviceBuf& out = backend_->ArenaResidual();
    if (in.buffer == VK_NULL_HANDLE || out.buffer == VK_NULL_HANDLE)
        return false;
    if (in.size < actIn || out.size < actOut)
        return false;
    // The actual host/device synchronization is performed by the backend's
    // uploadToBuffer/downloadFromBuffer path used by UploadBuf/DownloadBuf.
    return true;
}

bool VulkanCompute::StreamWeightToSlot(const void* packed, size_t bytes,
                                       VkBuffer& out) {
    (void)packed; (void)bytes;
    out = VK_NULL_HANDLE;
    // The implementation's weight residency is a weight WINDOW with a policy
    // (ApplyWeightWindowPolicy), not per-slot stream targets, and it pins whole
    // GpuWeightViews rather than raw packed bytes. There is no slot to fill.
    return false;
}

bool VulkanCompute::RecordCopy(VkBuffer src, VkBuffer dst,
                               VkDeviceSize srcOffset, VkDeviceSize dstOffset,
                               VkDeviceSize size) {
    (void)src; (void)dst; (void)srcOffset; (void)dstOffset; (void)size;
    // The implementation's recordCopy() needs a command buffer plus DeviceBuf
    // operands carrying both a VkBuffer AND its VkDeviceMemory. A raw VkBuffer
    // pair does not carry the memory handle, and inventing one would describe
    // an allocation that does not exist.
    return false;
}

bool VulkanCompute::EnsurePinnedPackedWeight(const void* packed, size_t bytes,
                                             uint32_t rows, uint32_t cols,
                                             VkBuffer& buf, uint64_t key) {
    buf = VK_NULL_HANDLE;
    // The untyped legacy contract cannot safely infer a GGML quantization code
    // from an opaque byte range.  Keep it fail-closed; typed K2 callers use
    // EnsurePinnedPackedWeightType below.
    (void)packed; (void)bytes; (void)rows; (void)cols; (void)key;
    return false;
}

bool VulkanCompute::EnsurePinnedPackedWeightType(int ggmlType,
                                                 const void* packed,
                                                 size_t bytes, uint32_t rows,
                                                 uint32_t cols, VkBuffer& buf,
                                                 uint64_t key) {
    buf = VK_NULL_HANDLE;
    if (backend_ == nullptr || packed == nullptr || bytes == 0 || rows == 0 ||
        cols == 0 || key == 0) {
        return false;
    }
    Deep2::GpuWeightView view{};
    view.data = packed;
    view.bytes = bytes;
    view.type = ggmlType;
    view.rows = rows;
    view.cols = cols;
    view.key = key;
    if (!backend_->PinWeightView(view)) return false;
    pinned_packed_[key] = PackedPinRecord{bytes, rows, cols, ggmlType};
    ++pin_clock_;
    resident_bytes_ = static_cast<size_t>(backend_->PinnedWeightBytes());
    return true;
}

bool VulkanCompute::EnsurePinnedF32(const float* data, uint32_t n,
                                    VkBuffer& buf, uint64_t key) {
    buf = VK_NULL_HANDLE;
    if (backend_ == nullptr || data == nullptr || n == 0 || key == 0) {
        return false;
    }
    Deep2::GpuWeightView view{};
    view.data = data;
    view.bytes = static_cast<size_t>(n) * sizeof(float);
    view.type = 0;
    view.rows = 1;
    view.cols = n;
    view.key = key;
    if (!backend_->PinWeightView(view)) return false;
    pinned_f32_[key] = std::vector<float>(data, data + n);
    ++pin_clock_;
    resident_bytes_ = static_cast<size_t>(backend_->PinnedWeightBytes());
    return true;
}

bool VulkanCompute::HasPinnedGemvWeight(uint64_t key, size_t bytes,
                                        uint32_t rows, uint32_t cols) const {
    const auto it = pinned_packed_.find(key);
    if (it != pinned_packed_.end()) {
        const auto& r = it->second;
        return r.bytes == bytes && r.rows == rows && r.cols == cols;
    }
    const auto f = pinned_f32_.find(key);
    return f != pinned_f32_.end() &&
           f->second.size() == rows * (size_t)cols &&
           f->second.size() * sizeof(float) == bytes;
}

bool VulkanCompute::TouchPinnedGemvWeight(uint64_t key, size_t bytes,
                                          uint32_t rows, uint32_t cols) {
    if (!HasPinnedGemvWeight(key, bytes, rows, cols)) return false;
    ++content_hits_;
    ++pin_clock_;
    return true;
}

// ----------------------------------------------------------------------------
// Weight window / pin accounting
// ----------------------------------------------------------------------------
bool VulkanCompute::EnsureWeightWindow(size_t bytes, uint32_t nLayers,
                                       size_t maxBytes) {
    if (backend_ == nullptr) return false;
    // Route the budget through the real weight-window policy so it constrains
    // residency rather than only being recorded.
    if (!backend_->ApplyWeightWindowPolicy(maxBytes ? maxBytes : bytes, bytes,
                                           nLayers, maxBytes ? maxBytes : bytes)) {
        return false;
    }
    pin_budget_ = bytes;
    return true;
}

uint64_t VulkanCompute::WeightBudgetBytes() const {
    // The adapter's own budget, which SetPinResidentBudget/EnsureWeightWindow
    // set and forward. This is the authoritative number for this slot.
    return static_cast<uint64_t>(pin_budget_);
}

uint64_t VulkanCompute::WeightContentHits() const {
    // The implementation tracks gemv weight hits, not content hits. Report the
    // real gemv hit count rather than a separate number that is never written.
    return GemvWeightHits();
}

uint64_t VulkanCompute::WeightPinEvicts() const {
    // No eviction accounting exists on this path; nothing has been evicted.
    return 0;
}

uint64_t VulkanCompute::WeightPinRejects() const {
    // No pin-rejection accounting exists on this path.
    return 0;
}

// ----------------------------------------------------------------------------
// Forward arena accessors (remaining)
// ----------------------------------------------------------------------------
VulkanCompute::DeviceBuf& VulkanCompute::ArenaResidual() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaResidual());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaQ() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaQ());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaK() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaK());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaV() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaV());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaAttn() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaAttn());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaAttnW() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaAttnW());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaGate() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaGate());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaUp() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaUp());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaDown() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaDown());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaFFNAct() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaFFNAct());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaFfnW() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaFfnW());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaKCache() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaKCache());
    return mirror;
}

VulkanCompute::DeviceBuf& VulkanCompute::ArenaVCache() {
    static DeviceBuf mirror{};
    if (backend_ == nullptr) { mirror = DeviceBuf{}; return mirror; }
    mirror = FromBackend(backend_->ArenaVCache());
    return mirror;
}

// ----------------------------------------------------------------------------
// Host <-> device transfer
// ----------------------------------------------------------------------------
bool VulkanCompute::DownloadHidden(float* host, uint32_t count) {
    if (backend_ == nullptr || host == nullptr) return false;
    if (count == 0) return false;
    return backend_->DownloadHidden(host, count);
}

bool VulkanCompute::UploadBuf(DeviceBuf& b, const float* host, uint32_t n) {
    if (backend_ == nullptr || host == nullptr || n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(b);
    if (!backend_->UploadVector(bi, host, n)) return false;
    b = FromBackend(bi);
    return true;
}

bool VulkanCompute::DownloadBuf(DeviceBuf& b, float* host, uint32_t n) {
    if (backend_ == nullptr || host == nullptr || n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(b);
    if (!backend_->DownloadVector(bi, host, n)) return false;
    b = FromBackend(bi);
    return true;
}

bool VulkanCompute::UploadNormWeight(DeviceBuf& dst, const float* src, uint32_t n) {
    if (backend_ == nullptr || src == nullptr || n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf bd = ToBackend(dst);
    if (!backend_->UploadNormWeight(bd, src, n)) return false;
    dst = FromBackend(bd);
    return true;
}

bool VulkanCompute::CopyArenaHiddenTo(VulkanCompute& dst, uint32_t n) {
    if (backend_ == nullptr || dst.backend_ == nullptr) return false;
    if (n == 0) return false;
    return backend_->CopyArenaHiddenTo(*dst.backend_, n);
}

void VulkanCompute::ReleaseForwardArena() {
    fwd_arena_ready_ = false;
    // Deep2::VulkanCompute has no explicit release; arenas persist until reinit.
}

// ----------------------------------------------------------------------------
// Fused layer lifecycle (additional)
// ----------------------------------------------------------------------------
bool VulkanCompute::FlushFusedRestart() {
    if (backend_ == nullptr) return false;
    // End current fused layer and begin a new one
    if (!backend_->EndFusedLayer()) return false;
    return backend_->BeginFusedLayer();
}

bool VulkanCompute::FusedBarrier() {
    if (backend_ == nullptr) return false;
    // The implementation's fused layer already inserts barriers between dispatches.
    // This is a no-op that returns success if we're in a fused layer.
    return backend_->FusedRecording();
}

// ----------------------------------------------------------------------------
// Fused kernel dispatch (additional)
// ----------------------------------------------------------------------------
bool VulkanCompute::ExecuteRMSNorm(float* data, uint32_t size, float epsilon) {
    // Host-side fallback - no device execution
    (void)data; (void)size; (void)epsilon;
    return false;
}

bool VulkanCompute::ExecuteSiLU(float* data, uint32_t size) {
    // Host-side fallback
    (void)data; (void)size;
    return false;
}

bool VulkanCompute::DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n) {
    if (backend_ == nullptr || n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf ba = ToBackend(a);
    Deep2::VulkanCompute::DeviceBuf bb = ToBackend(b);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchResidualAdd(ba, bb, bo, n)) return false;
    a = FromBackend(ba);
    b = FromBackend(bb);
    out = FromBackend(bo);
    return true;
}

bool VulkanCompute::DispatchScaledAdd(DeviceBuf& accum, DeviceBuf& src, float scale, uint32_t n) {
    if (backend_ == nullptr || n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf ba = ToBackend(accum);
    Deep2::VulkanCompute::DeviceBuf bs = ToBackend(src);
    if (!backend_->dispatchSpecOps(ba, bs, bs, bs, {0, n, 1, 0, scale})) return false;
    accum = FromBackend(ba);
    src = FromBackend(bs);
    return true;
}

bool VulkanCompute::DispatchRope(DeviceBuf& q, DeviceBuf& k, uint32_t headDim,
                                 uint32_t nHeads, uint32_t nope, uint32_t rope, float theta) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bq = ToBackend(q);
    Deep2::VulkanCompute::DeviceBuf bk = ToBackend(k);
    if (!backend_->DispatchRope(bq, bk, headDim, nHeads, nope, rope, theta)) return false;
    q = FromBackend(bq);
    k = FromBackend(bk);
    return true;
}

bool VulkanCompute::DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n) {
    if (backend_ == nullptr || n == 0) return false;
    Deep2::VulkanCompute::DeviceBuf bg = ToBackend(gate);
    Deep2::VulkanCompute::DeviceBuf bu = ToBackend(up);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchSwiGLU(bg, bu, bo, n)) return false;
    gate = FromBackend(bg);
    up = FromBackend(bu);
    out = FromBackend(bo);
    return true;
}

bool VulkanCompute::DispatchAttnDecode(DeviceBuf& q, DeviceBuf& kCache, DeviceBuf& vCache,
                                       DeviceBuf& out, uint32_t seqLen, uint32_t headDim,
                                       uint32_t nHeads, uint32_t kvDim, float scale,
                                       uint32_t layer) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bq = ToBackend(q);
    Deep2::VulkanCompute::DeviceBuf bk = ToBackend(kCache);
    Deep2::VulkanCompute::DeviceBuf bv = ToBackend(vCache);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchAttnDecode(bq, bk, bv, bo, headDim, nHeads, kvDim, seqLen, scale, layer)) return false;
    q = FromBackend(bq);
    kCache = FromBackend(bk);
    vCache = FromBackend(bv);
    out = FromBackend(bo);
    return true;
}

bool VulkanCompute::AppendKV(DeviceBuf& kTok, DeviceBuf& vTok, uint32_t kvDim,
                             uint32_t pos, uint32_t nHeads) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bk = ToBackend(kTok);
    Deep2::VulkanCompute::DeviceBuf bv = ToBackend(vTok);
    if (!backend_->AppendKV(bk, bv, kvDim, pos, nHeads)) return false;
    kTok = FromBackend(bk);
    vTok = FromBackend(bv);
    return true;
}

// ----------------------------------------------------------------------------
// Fused command pool / recording (fail closed - not in implementation)
// ----------------------------------------------------------------------------
bool VulkanCompute::EnsureFusedPool() { return false; }
void VulkanCompute::ReleaseFusedPool() {}
bool VulkanCompute::SubmitFusedPool(VkCommandBuffer, uint32_t) { return false; }
bool VulkanCompute::EnsureFusedAuxDs() { return false; }
VkDescriptorSet VulkanCompute::NextGemvDs() { return VK_NULL_HANDLE; }
VkDescriptorSet VulkanCompute::NextSwigluDs() { return VK_NULL_HANDLE; }
VkDescriptorSet VulkanCompute::NextSaxpyDs() { return VK_NULL_HANDLE; }

bool VulkanCompute::RecordCompute(VkPipeline, VkPipelineLayout,
                                  VkDescriptorSet, const void*, uint32_t, uint32_t) {
    return false;
}

bool VulkanCompute::SubmitOne(VkCommandBuffer) { return false; }
bool VulkanCompute::CopyDeviceToDevice(VkBuffer, VkBuffer, size_t) { return false; }
bool VulkanCompute::DownloadDeviceLocal(VkBuffer, void*, size_t) { return false; }

// ----------------------------------------------------------------------------
// Pipeline creation (fail closed - not in implementation)
// ----------------------------------------------------------------------------
bool VulkanCompute::CreateGemvPipe(const char*, VkPipeline&) { return false; }
bool VulkanCompute::SelectPackedPipe(int, VkPipeline&, uint64_t*&) { return false; }
bool VulkanCompute::EnsureQ2kPipeline() { return false; }
bool VulkanCompute::EnsureQ3kPipeline() { return false; }
bool VulkanCompute::EnsureQ4kPipeline() { return false; }
bool VulkanCompute::EnsureQ4kFusedPipeline() { return false; }
bool VulkanCompute::EnsureQ4kOprojPipeline() { return false; }
bool VulkanCompute::EnsureQ4kKvaPipeline() { return false; }
bool VulkanCompute::EnsureQ4kQkvSxPipeline(uint32_t, VkPipeline&) { return false; }
bool VulkanCompute::EnsureQ5kPipeline() { return false; }
bool VulkanCompute::EnsureQ6kPipeline() { return false; }
bool VulkanCompute::EnsureQ8Pipeline() { return false; }
bool VulkanCompute::EnsureQ8KvaPipeline() { return false; }
bool VulkanCompute::EnsureQ8KvaSxPipeline(uint32_t, VkPipeline&) { return false; }

bool VulkanCompute::ClimbQ8KvaOnce(VkBuffer, size_t, size_t, size_t,
                                   uint32_t, uint32_t, uint32_t, uint32_t, uint8_t,
                                   float*, uint64_t, uint32_t&, uint64_t&) { return false; }

bool VulkanCompute::ClimbQkvSharedXOnce(VkBuffer, size_t, size_t, size_t,
                                        uint32_t, uint32_t, uint8_t,
                                        float*, uint64_t, VkPipeline&,
                                        uint32_t&, uint64_t&) { return false; }

bool VulkanCompute::LoadComputePipeline(const char*, uint32_t, uint32_t,
                                        VkPipeline&, VkPipelineLayout&,
                                        VkDescriptorSetLayout&, VkDescriptorPool&, VkDescriptorSet&) {
    return false;
}

bool VulkanCompute::TuneFromDevice() { return false; }

// ----------------------------------------------------------------------------
// Device-resident GEMV (already have host versions)
// ----------------------------------------------------------------------------
bool VulkanCompute::DispatchGemvDevice(const float* weights, uint64_t cacheKey,
                                       DeviceBuf& in, DeviceBuf& out, uint32_t rows,
                                       uint32_t cols) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(in);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchGemvDevice(weights, cacheKey, bi, bo, rows, cols)) return false;
    in = FromBackend(bi);
    out = FromBackend(bo);
    return true;
}

bool VulkanCompute::DispatchGemvQuant(int ggmlType, const void* packed, size_t bytes,
                                      DeviceBuf& in, DeviceBuf& out, uint32_t rows,
                                      uint32_t cols, uint64_t cacheKey) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(in);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchGemvQuant(ggmlType, packed, bytes, bi, bo, rows, cols)) return false;
    in = FromBackend(bi);
    out = FromBackend(bo);
    return true;
}

bool VulkanCompute::DispatchGemvQ6kPacked(const void* packed, size_t bytes,
                                          DeviceBuf& in, DeviceBuf& out,
                                          uint32_t rows, uint32_t cols) {
    if (backend_ == nullptr) return false;
    Deep2::VulkanCompute::DeviceBuf bi = ToBackend(in);
    Deep2::VulkanCompute::DeviceBuf bo = ToBackend(out);
    if (!backend_->DispatchGemvQuant(GGML_TYPE_Q6_K, packed, bytes, bi, bo, rows, cols)) return false;
    in = FromBackend(bi);
    out = FromBackend(bo);
    return true;
}

// ----------------------------------------------------------------------------
// MLA Q / KV buffers
// ----------------------------------------------------------------------------
bool VulkanCompute::EnsureMlaAttn(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                                  uint32_t, uint32_t) { return false; }
bool VulkanCompute::EnsureMlaQBytes(size_t) { return false; }

VulkanCompute::DeviceBuf& VulkanCompute::MlaQ() {
    static DeviceBuf mirror{};
    return mirror;
}
VulkanCompute::DeviceBuf& VulkanCompute::MlaKb() {
    static DeviceBuf mirror{};
    return mirror;
}
VulkanCompute::DeviceBuf& VulkanCompute::MlaVb() {
    static DeviceBuf mirror{};
    return mirror;
}
VulkanCompute::DeviceBuf& VulkanCompute::MlaKpe() {
    static DeviceBuf mirror{};
    return mirror;
}
VulkanCompute::DeviceBuf& VulkanCompute::MlaAttnOut() {
    static DeviceBuf mirror{};
    return mirror;
}

// ----------------------------------------------------------------------------
// Diagnostics (remaining)
// ----------------------------------------------------------------------------
uint64_t VulkanCompute::LastD2hVk() const { return last_d2h_vk_; }
const char* VulkanCompute::LastD2hPhase() const { return last_d2h_phase_; }

// ----------------------------------------------------------------------------
// Per-lane residency accounting (DualStick quota) - fail closed
// ----------------------------------------------------------------------------
uint64_t VulkanCompute::MoeReservedBytes() const { return 0; }
uint64_t VulkanCompute::MoeResidentBytes() const { return 0; }
uint64_t VulkanCompute::MlaResidentBytes() const { return 0; }
uint64_t VulkanCompute::MlaQuotaBytes() const { return 0; }
uint64_t VulkanCompute::GeneralResidentBytes() const { return 0; }
uint64_t VulkanCompute::GeneralQuotaBytes() const { return 0; }

// ----------------------------------------------------------------------------
// Weight window / pin accounting (additional)
// ----------------------------------------------------------------------------
uint64_t VulkanCompute::WeightPinBudgetFloor() const { return 0; }
void VulkanCompute::SetPinResidentBudgetAt(size_t bytes, const char* site) {
    SetPinResidentBudget(bytes);
    pin_site_ = site ? site : "";
}
const char* VulkanCompute::PinBudgetOwnerSite() const {
    return pin_site_.empty() ? nullptr : pin_site_.c_str();
}
uint64_t VulkanCompute::PinBudgetShrinkBlocked() const { return pin_shrink_blocked_; }

uint64_t VulkanCompute::WeightPinResidentBytes() const {
    return backend_ != nullptr
        ? static_cast<uint64_t>(backend_->PinnedWeightBytes())
        : static_cast<uint64_t>(resident_bytes_);
}

uint64_t VulkanCompute::WeightPinClock() const { return pin_clock_; }

void VulkanCompute::GemvReuseInputNext() { gemv_reuse_in_next_ = true; }

void VulkanCompute::GemvFuseResidualNext(const float* residual) {
    gemv_residual_ = residual;
}

uint64_t VulkanCompute::GemvInputReuseHits() const {
    return gemv_in_reuse_hits_;
}

bool VulkanCompute::ApplyWeightWindowPolicy(size_t hotBytes, size_t warmBytes,
                                            uint32_t nLayers, size_t maxResident) {
    if (backend_ == nullptr) return false;
    return backend_->ApplyWeightWindowPolicy(hotBytes, warmBytes, nLayers, maxResident);
}

bool VulkanCompute::WaitWeightCompute(uint32_t slot) {
    if (backend_ == nullptr) return false;
    return backend_->WaitWeightCompute(slot);
}

bool VulkanCompute::WantWeightStream() { return false; }
size_t VulkanCompute::DeviceLocalHeapBytes() const {
    if (backend_ == nullptr) return 0;
    return backend_->deviceLocalBytes();
}

} // namespace CPUInference
