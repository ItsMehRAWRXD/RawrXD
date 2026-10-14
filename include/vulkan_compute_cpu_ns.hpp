// ============================================================================
// vulkan_compute_cpu_ns.hpp — AUTHORITATIVE CPUInference::VulkanCompute contract
// ----------------------------------------------------------------------------
// ROOT CAUSE OF THE C2888 / "forward-declared but never defined" FAMILY:
//
//   The production Deep2 engine types its GPU backend as
//   CPUInference::VulkanCompute (Deep2Engine.h:436/437/720/721,
//   getVulkanComputeSlot(), vulkanDevices_).
//
//   That class was only ever FORWARD-DECARED:
//       src/deep2/K2GpuStreamCopy.hpp:8
//       src/deep2/MoEWeightProxy.hpp:17
//       src/deep2/NUGemv.hpp:7
//       src/deep2/NULiveConsumer.hpp:7
//       src/deep2/lavapath/DualStickStreamWindow.hpp:59
//       src/agentic_iterative_reasoning.h:9
//       src/gguf_loader_fixed.h:11
//       ... (namespace CPUInference { class VulkanCompute; })
//
//   No complete declaration ever existed, yet ~30 translation units define
//   its members (src/vulkan_fwd_*.cpp, src/vulkan_weight_*.cpp,
//   src/deep2/K2MLA_*.cpp, src/deep2/K2NativeMoEFfn_*.cpp, ...) and the engine
//   + every deep2_*_cert.cpp call them.
//
//   NOTE: the global ::VulkanCompute in THIS header's parent
//   (include/vulkan_compute.h) is a DIFFERENT C++ class with a different and
//   smaller method set (Initialize/DispatchMatMul/KV-cache/CPU scalar execs).
//   It is NOT interchangeable and must NOT be used to satisfy this contract.
//
// This header is the single authoritative declaration. Every declaration and
// out-of-class definition in the tree must match it exactly.
// ============================================================================

#pragma once

#include "vulkan_compute.h"    // Vk* types, VulkanDeviceInfo, ::VulkanCompute (device level)
// The GPU compute implementation that CPUInference::VulkanCompute adapts.
// Path-qualified so it cannot collide with the device-level vulkan_compute.h
// included on the line above -- an unqualified "vulkan_compute.h" here would
// bind to whichever comes first on the include path, which is the exact class
// identity bug this whole integration exists to remove.
#include "deep2/vulkan_compute.h"

#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace CPUInference {

class VulkanCompute {
public:
    // ---- Forward-arena device buffer ---------------------------------------
    // A device-local (or device-visible host) allocation used by the fused
    // forward arena, the pin cache and the MLA Q/KB/VB/KPE/OUT paths.
    struct DeviceBuf {
        VkBuffer       buffer = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        size_t         bytes  = 0;
    };

    VulkanCompute();
    ~VulkanCompute();

    VulkanCompute(const VulkanCompute&)            = delete;
    VulkanCompute& operator=(const VulkanCompute&) = delete;
    VulkanCompute(VulkanCompute&&)                 = delete;
    VulkanCompute& operator=(VulkanCompute&&)      = delete;

    // ---- Device lifecycle ---------------------------------------------------
    // Select one physical device by name substring ("Radeon RX 7800 XT", ...).
    // Returns false when no matching device or initialization fails; the engine
    // then treats the slot as absent and its host path takes over.
    bool InitializeSolo(const char* needle);

    // ---- GEMV dispatch -----------------------------------------------------
    // F32 window: output[r] = dot(weights[r][0..cols), input[0..cols).
    bool DispatchGEMV(const float* weights, const float* input, float* output,
                      uint32_t rows, uint32_t cols, uint64_t cacheKey);

    // Host-parameterized packed dispatch (identical math to DispatchGEMVPacked
    // but staging through the host activation buffers).
    bool DispatchGEMVPacked(const void* packed, size_t bytes,
                            const float* input, float* output,
                            uint32_t rows, uint32_t cols, uint64_t cacheKey);

    // Q6_K logits path: dedicated buffer; never truncated by the weight window.
    bool DispatchGEMVQ6kPacked(const void* packed, size_t bytes,
                              const float* input, float* output,
                              uint32_t rows, uint32_t cols);

    // Generic packed-quant dispatch. `type` is the GGML type enum value.
    // cacheKey identifies the caller's weight window so a dequantized copy can
    // stay resident across calls; pass 0 for a one-shot dispatch.
    bool DispatchGEMVQuant(int ggmlType, const void* packed, size_t bytes,
                           const float* input, float* output,
                           uint32_t rows, uint32_t cols, uint64_t cacheKey);

    // Fused decode kernels.
    bool DispatchGEMVFusedQ4KT(const void* packed, size_t bytes,
                               const float* input, float* output,
                               uint32_t rows, uint32_t cols, uint64_t cacheKey);
    bool DispatchGEMVFusedQ8Kva(const void* packed, size_t bytes,
                               const float* input, float* output,
                               uint32_t rows, uint32_t cols, uint64_t cacheKey);

    // ---- Forward arena / fused batch ---------------------------------------
    bool EnsureForwardArena(uint32_t hidden, uint32_t inter, uint32_t nHeads,
                            uint32_t qCols, uint32_t kvDim, uint32_t maxSeq,
                            uint32_t nLayers);
    void ReleaseForwardArena();
    DeviceBuf& ArenaHidden();
    DeviceBuf& ArenaResidual();
    DeviceBuf& ArenaNormed();
    DeviceBuf& ArenaQ();
    DeviceBuf& ArenaK();
    DeviceBuf& ArenaV();
    DeviceBuf& ArenaAttn();
    DeviceBuf& ArenaAttnW();
    DeviceBuf& ArenaGate();
    DeviceBuf& ArenaUp();
    DeviceBuf& ArenaDown();
    DeviceBuf& ArenaFFNAct();
    DeviceBuf& ArenaFfnW();
    DeviceBuf& ArenaKCache();
    DeviceBuf& ArenaVCache();

    // ---- Host <-> device transfer -------------------------------------------
    bool UploadHidden(const float* host, uint32_t n);
    bool DownloadHidden(float* host, uint32_t n);
    bool UploadBuf(DeviceBuf& b, const float* host, uint32_t n);
    bool DownloadBuf(DeviceBuf& b, float* host, uint32_t n);
    bool UploadNormWeight(DeviceBuf& dst, const float* src, uint32_t n);
    bool CopyArenaHiddenTo(VulkanCompute& dst, uint32_t n);
    bool EnsureHostIo(size_t actIn, size_t actOut);

    // ---- Fused layer lifecycle ---------------------------------------------
    bool BeginFusedLayer();
    bool EndFusedLayer();
    bool FlushFusedRestart();
    bool FusedBarrier();

    // ---- Fused kernel dispatch ---------------------------------------------
    bool DispatchRmsNorm(DeviceBuf& in, DeviceBuf& w, DeviceBuf& out,
                         uint32_t n, float epsilon);
    bool ExecuteRMSNorm(float* data, uint32_t size, float epsilon);
    bool ExecuteSiLU(float* data, uint32_t size);
    bool DispatchResidualAdd(DeviceBuf& a, DeviceBuf& b, DeviceBuf& out,
                             uint32_t n);
    bool DispatchScaledAdd(DeviceBuf& accum, DeviceBuf& src, float scale,
                           uint32_t n);
    bool DispatchRope(DeviceBuf& q, DeviceBuf& k, uint32_t headDim,
                      uint32_t nHeads, uint32_t nope, uint32_t rope, float theta);
    bool DispatchSwiGLU(DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out,
                        uint32_t n);
    bool DispatchAttnDecode(DeviceBuf& q, DeviceBuf& kCache, DeviceBuf& vCache,
                            DeviceBuf& out, uint32_t seqLen, uint32_t headDim,
                            uint32_t nHeads, uint32_t kvDim, float scale,
                            uint32_t layer);
    bool AppendKV(DeviceBuf& kTok, DeviceBuf& vTok, uint32_t kvDim,
                  uint32_t pos, uint32_t nHeads);

    // ---- Fused command pool -------------------------------------------------
    bool EnsureFusedPool();
    void ReleaseFusedPool();
    bool SubmitFusedPool(VkCommandBuffer cmd, uint32_t idx);
    bool EnsureFusedAuxDs();
    VkDescriptorSet NextGemvDs();
    VkDescriptorSet NextSwigluDs();
    VkDescriptorSet NextSaxpyDs();
    bool RecordCompute(VkPipeline pipe, VkPipelineLayout layout,
                       VkDescriptorSet ds, const void* pc, uint32_t groupX,
                       uint32_t groupY);
    bool RecordCopy(VkBuffer src, VkBuffer dst, VkDeviceSize srcOff,
                    VkDeviceSize dstOff, VkDeviceSize size);
    bool SubmitOne(VkCommandBuffer cmd);
    bool CopyDeviceToDevice(VkBuffer src, VkBuffer dst, size_t size);
    bool DownloadDeviceLocal(VkBuffer src, void* dst, size_t size);

    // ---- Pipeline creation --------------------------------------------------
    bool CreateGemvPipe(const char* spvName, VkPipeline& pipe);
    bool SelectPackedPipe(int ggmlType, VkPipeline& pipe, uint64_t*& ops);
    bool EnsureQ2kPipeline();
    bool EnsureQ3kPipeline();
    bool EnsureQ4kPipeline();
    bool EnsureQ4kFusedPipeline();
    bool EnsureQ4kOprojPipeline();
    bool EnsureQ4kKvaPipeline();
    bool EnsureQ4kQkvSxPipeline(uint32_t rows, VkPipeline& out);
    bool EnsureQ5kPipeline();
    bool EnsureQ6kPipeline();
    bool EnsureQ8Pipeline();
    bool EnsureQ8KvaPipeline();
    bool EnsureQ8KvaSxPipeline(uint32_t rows, VkPipeline& out);
    bool ClimbQ8KvaOnce(VkBuffer wbuf, size_t bytes, size_t inB, size_t outB,
                        uint32_t rows, uint32_t cols, uint32_t nBlk,
                        uint32_t colsX, uint8_t mode, float* out,
                        uint64_t key, uint32_t& ops, uint64_t& done);
    bool ClimbQkvSharedXOnce(VkBuffer wbuf, size_t bytes, size_t inB,
                             size_t outB, uint32_t rows, uint32_t cols,
                             uint8_t mode, float* out, uint64_t key,
                             VkPipeline& pipe, uint32_t& ops, uint64_t& done);
    bool LoadComputePipeline(const char* spvName, uint32_t nBind,
                             uint32_t pcBytes, VkPipeline& pipe,
                             VkPipelineLayout& layout,
                             VkDescriptorSetLayout& dsLayout,
                             VkDescriptorPool& pool, VkDescriptorSet& ds);
    bool TuneFromDevice();

    // ---- GEMV device staging ------------------------------------------------
    bool EnsureGemvActDevice(size_t inBytes, size_t outBytes);
    DeviceBuf& GemvActIn();
    DeviceBuf& GemvActOut();
    VkBuffer   GemvHostInBuffer();
    VkBuffer   GemvHostOutBuffer();
    bool GemvHostWriteIn(const float* src, size_t bytes);
    bool GemvHostReadOut(float* dst, size_t bytes);
    void GemvReuseInputNext();
    void GemvFuseResidualNext(const float* residual);
    uint64_t GemvInputReuseHits() const;

    bool BindGemvStorage(VkBuffer wbuf, size_t wbytes, VkBuffer inb,
                         size_t inBytes, VkBuffer outb, size_t outBytes,
                         VkPipeline pipe, uint32_t nBlk, uint32_t rows,
                         uint32_t cols);
    bool BindGemvStoragePc(VkBuffer wbuf, size_t wbytes, VkBuffer inb,
                           size_t inBytes, VkBuffer outb, size_t outBytes,
                           VkPipeline pipe, const uint32_t* pc, uint32_t nBlk,
                           uint32_t rows);

    // Device-resident GEMV (arena operands).
    bool DispatchGemvDevice(const float* weights, uint64_t cacheKey,
                            DeviceBuf& in, DeviceBuf& out, uint32_t rows,
                            uint32_t cols);
    bool DispatchGemvPacked(const void* packed, size_t bytes, DeviceBuf& in,
                            DeviceBuf& out, uint32_t rows, uint32_t cols,
                            uint64_t cacheKey);
    bool DispatchGemvQuant(int ggmlType, const void* packed, size_t bytes,
                           DeviceBuf& in, DeviceBuf& out, uint32_t rows,
                           uint32_t cols, uint64_t cacheKey);
    bool DispatchGemvQ6kPacked(const void* packed, size_t bytes, DeviceBuf& in,
                               DeviceBuf& out, uint32_t rows, uint32_t cols);

    // ---- Weight pin residency ----------------------------------------------
    bool EnsurePinnedPackedWeight(const void* packed, size_t bytes,
                                  uint32_t rows, uint32_t cols, VkBuffer& buf,
                                  uint64_t key);
    bool EnsurePinnedF32(const float* data, uint32_t n, VkBuffer& buf,
                         uint64_t key);
    bool HasPinnedGemvWeight(uint64_t key, size_t bytes, uint32_t rows,
                             uint32_t cols) const;
    bool TouchPinnedGemvWeight(uint64_t key, size_t bytes, uint32_t rows,
                               uint32_t cols);
    void ReleaseWeightWindow();
    void ClearPinnedGemvWeights();
    void ResetWeightWindowLayerCursor();
    size_t WeightBudgetBytes() const;
    size_t WeightPinBudgetFloor() const;
    void SetPinResidentBudget(size_t bytes);
    void SetPinResidentBudgetAt(size_t bytes, const char* site);
    const char* PinBudgetOwnerSite() const;
    uint64_t PinBudgetShrinkBlocked() const;
    uint64_t WeightPinCacheCount() const;
    uint64_t WeightPinResidentBytes() const;
    uint64_t WeightPinClock() const;

    bool EnsureWeightWindow(size_t bytes, uint32_t nLayers, size_t maxBytes);
    bool ApplyWeightWindowPolicy(size_t hotBytes, size_t warmBytes,
                                 uint32_t nLayers, size_t maxResident);
    bool PrefetchWeight(const void* packed, size_t bytes, uint32_t& slot);
    bool WaitWeightUpload(uint32_t slot);
    bool WaitWeightCompute(uint32_t slot);
    bool FlushWeightComputes();
    bool SubmitGemvPrefetch(uint32_t slot, DeviceBuf& in, DeviceBuf& out,
                            uint32_t rows, uint32_t cols, size_t bytes,
                            int ggmlType);
    bool StreamWeightToSlot(const void* packed, size_t bytes, VkBuffer& buf);
    bool WantWeightStream();
    bool WeightPrefetchActive();
    bool WeightStreamActive();
    size_t DeviceLocalHeapBytes() const;

    // ---- Per-lane residency accounting (DualStick quota) --------------------
    uint64_t MoeReservedBytes() const;
    uint64_t MoeResidentBytes() const;
    uint64_t MlaResidentBytes() const;
    uint64_t MlaQuotaBytes() const;
    uint64_t GeneralResidentBytes() const;
    uint64_t GeneralQuotaBytes() const;

    // ---- Diagnostics telemetry ---------------------------------------------
    uint64_t GemvSuccess() const;
    uint64_t GemvWeightHits() const;
    uint64_t GemvWeightUploads() const;
    uint64_t WeightContentHits() const;
    uint64_t WeightPinEvicts() const;
    uint64_t WeightPinRejects() const;
    uint64_t LastD2hVk() const;
    uint64_t LastD2hPhase() const;

    // ---- MLA Q / KV buffers -------------------------------------------------
    bool EnsureMlaAttn(uint32_t nHeads, uint32_t qkDim, uint32_t vDim,
                       uint32_t nope, uint32_t rope, uint32_t maxSeq,
                       uint32_t nLayers);
    bool EnsureMlaQBytes(size_t need);
    bool DispatchAttnDecodeMLA(DeviceBuf& q, DeviceBuf& kb, DeviceBuf& vb,
                               DeviceBuf& kpe, DeviceBuf& out, uint32_t qkDim,
                               uint32_t vDim, uint32_t nope, uint32_t rope,
                               uint32_t nHeads, uint32_t pos, float theta,
                               float scale, float ropeScale, uint32_t layer);
    DeviceBuf& MlaQ();
    DeviceBuf& MlaKb();
    DeviceBuf& MlaVb();
    DeviceBuf& MlaKpe();
    DeviceBuf& MlaAttnOut();

    // ---- Device info --------------------------------------------------------
    const VulkanDeviceInfo& GetDeviceInfo() const;

private:
    // Host-side preparation of a quantized weight into a resident F32 window.
    // Returns nullptr when the layout is unsupported or the pin budget rejects
    // the entry — callers then return false so the engine uses its host path.
    const float* DequantPacked(int ggmlType, const void* packed, size_t bytes,
                               uint32_t rows, uint32_t cols, uint64_t cacheKey);

    // ---- Real backend -------------------------------------------------------
    // The genuine GPU compute implementation created by InitializeSolo().
    //
    // This is Deep2::VulkanCompute (src/deep2/vulkan_compute.h), NOT the
    // device-level ::VulkanCompute from include/vulkan_compute.h. That other
    // class's ExecuteMatMul is documented CPU fallback ("Naive CPU fallback
    // (O(m*k*n)) for benchmarking correctness") and its only real kernel is
    // ExecuteQuantDot, so a GEMV built on it performs no device work and
    // reports gpu_calls=0 -- which is exactly the "zero GPU calls /
    // PARITY_VERDICT=NOT_RUN" symptom in the parity probe. The Deep2
    // implementation ships the deep2_qgemv* / deep2_argmax / deep2_spec_* shader
    // family and the quantised dispatch, so it is the one that actually runs.
    std::unique_ptr<Deep2::VulkanCompute> backend_;
    bool initialized_ = false;
    VulkanDeviceInfo device_info_{};

    // ---- Pinned F32 weight windows (dequantized, resident) -------------------
    // Keyed by the caller's cacheKey (usually derived from the source pointer,
    // rows and cols) so the same logical weight resolves to one resident copy.
    std::unordered_map<uint64_t, std::vector<float>> pinned_f32_;
    size_t pin_budget_ = 0;
    std::string pin_site_;
    size_t resident_bytes_ = 0;
    uint64_t pin_evicts_ = 0;
    uint64_t pin_rejects_ = 0;
    uint64_t pin_shrink_blocked_ = 0;
    uint64_t content_hits_ = 0;

    // ---- GEMV accounting (real counters) ------------------------------------
    uint64_t gemv_success_ = 0;
    uint64_t gemv_weight_hits_ = 0;
    uint64_t gemv_weight_uploads_ = 0;
    uint64_t gemv_in_reuse_hits_ = 0;
    bool     gemv_reuse_in_next_ = false;
    const float* gemv_residual_ = nullptr;

    // ---- Transfer diagnostics -------------------------------------------------
    uint64_t last_d2h_vk_ = 0;
    uint64_t last_d2h_phase_ = 0;
    bool     fwd_arena_ready_ = false;

    // ---- GEMV staging mirrors (ENGINE_RECOVERY) -------------------------------
    // GemvActIn()/GemvActOut() must return DeviceBuf&, but the device buffers
    // they alias live inside Deep2::VulkanCompute (whose DeviceBuf is a
    // different nested type). These two members hold the translated mirror so
    // the returned reference is stable and refers to this instance. They are
    // populated by EnsureGemvActDevice().
    DeviceBuf gemv_act_in_{};
    DeviceBuf gemv_act_out_{};
};

} // namespace CPUInference
