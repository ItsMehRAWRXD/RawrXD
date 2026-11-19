#pragma once
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
#include <vulkan/vulkan.h>

// GPU compute optional - CPU inference always works
// Vulkan is enabled if system supports it, otherwise CPU fallback

struct VulkanDeviceInfo {
    std::string device_name;
    VkPhysicalDeviceProperties properties{};
    VkPhysicalDeviceMemoryProperties memory_props{};
    uint32_t vendor_id;
    uint32_t device_id;
    bool supports_compute;
    uint32_t compute_queue_family;
};

struct ComputeShader {
    std::string name;
    std::vector<uint32_t> spirv_code;
    VkShaderModule module = nullptr;
    VkPipelineLayout layout = nullptr;
    VkPipeline pipeline = nullptr;
};

struct VulkanTensor {
    std::string name;
    size_t size_bytes{0};
    std::vector<float> host_data;  // Scalar data stored in CPU memory
    VkBuffer device_buffer = nullptr;
    VkDeviceMemory device_memory = nullptr;
};

// Async command buffer pool for high-performance batching
struct CommandBufferPool {
    VkCommandBuffer buffer = nullptr;
    VkFence fence = nullptr;
    bool is_available = true;
};

// RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY: backend instrumentation.
// Distinguishes time spent EXECUTING kernels from time spent FEEDING them
// (submission overhead, host waits, upload/download traffic) and accounts
// every allocation so resource churn is measurable rather than anecdotal.
struct GpuCounters {
    uint64_t buffer_allocations = 0;    // vkCreateBuffer + vkAllocateMemory calls
    uint64_t descriptor_allocations = 0; // sets successfully allocated
    uint64_t descriptor_reuses = 0;      // descriptor updates on existing sets
    uint64_t descriptor_alloc_attempts = 0;  // vkAllocateDescriptorSets calls
    uint64_t descriptor_alloc_failures = 0;  // attempts that failed (any reason)
    uint64_t descriptor_pool_creates = 0;    // pools created
    uint64_t descriptor_pool_resets = 0;     // pools reset via vkResetDescriptorPool
    uint64_t descriptor_sets_in_flight = 0;  // allocated sets not yet GPU-complete
    uint64_t descriptor_sets_peak = 0;       // high-water mark of in-flight sets
    uint64_t submits = 0;               // vkQueueSubmit calls
    uint64_t waits = 0;                 // vkWaitForFences calls
    uint64_t upload_bytes = 0;          // host -> device bytes transferred
    uint64_t download_bytes = 0;        // device -> host bytes transferred
    uint64_t weight_cache_hits = 0;     // re-dispatched an already-resident weight
    uint64_t weight_cache_misses = 0;  // first upload of a weight tensor
    uint64_t weight_cache_evictions = 0; // LRU/hotness budget evictions (RAWRXD_STRATA_S01)
    uint64_t weight_prefetches = 0;    // explicit prefetch submissions (STRATA_S03)
    uint64_t weight_prefetch_hits = 0; // prefetch found the weight already resident
    uint64_t device_bytes_live = 0;    // device-local bytes currently allocated
    uint64_t device_bytes_peak = 0;    // high-water mark of device_bytes_live
    // Legacy compatibility counter. The implementation records the host
    // fence-wait span here, so it intentionally aliases wait_ms; it is not a
    // device execution timer. Use gpu_ms for Vulkan timestamp time.
    double kernel_ms = 0;
    double submit_ms = 0;             // host time recording + submitting
    double wait_ms = 0;               // host time blocked in vkWaitForFences
    double gpu_ms = 0;                // TRUE device-side shader time (timestamp query)
};

class VulkanCompute {
public:
    VulkanCompute();
    ~VulkanCompute();

    bool Initialize();
    bool LoadShader(const std::string& name, const std::string& spirv_path);
    bool CreateComputePipeline(const std::string& shader_name);
    VulkanTensor TransferGGUFTensor(const std::string& tensor_name,
                                    const void* data_ptr,
                                    size_t size_bytes,
                                    uint32_t usage = 0);
    void ReleaseTensors();
    bool EnsureMatMulPipeline(const std::string& spirv_path);
    bool EnsureRoPEPipeline(const std::string& spirv_path);
    bool EnsureQuantDotPipeline(const std::string& spirv_path);

// RAWRXD_DEEP2_SPEC_FUSED_LMHEAD_001: public scratch buffer type for
    // fused LM-head batch dispatch.
    struct QuantScratch {
        VkBuffer buffer = nullptr;
        VkDeviceMemory memory = nullptr;
        size_t capacity = 0;
        bool in_use = false;
        explicit operator bool() const noexcept {
            return buffer != nullptr && memory != nullptr && capacity != 0;
        }
    };
    // Scratch-buffer pool access (the pool itself lives in the private fast
    // path). A caller acquires a buffer of at least `bytes`, writes or reads
    // through it, then releases it back to the pool.
    QuantScratch* AcquireQuantScratch(size_t bytes);
    void ReleaseQuantScratch(QuantScratch* s);
    // Raw buffer copy through the persistent staging buffers. Used by the
    // fused LM-head path to stage the concatenated activations in and the
    // concatenated logits out.
    bool UploadBuffer(VkBuffer dst, const void* src, size_t bytes);
    bool DownloadBuffer(VkBuffer src, void* dst, size_t bytes);
    // Creates (idempotently) the fused multi-row Q4_K/Q6_K GEMV pipeline used by
    // DispatchGemvQ4KBatch. The loader searches packaged and source-tree paths.
    bool EnsureQ4KBatchGemvPipeline();
    bool DispatchGemvQ4KBatch(
        const void* weights, size_t weightBytes,
        VkBuffer inputBatch, VkBuffer outputBatch,
        uint32_t rows, uint32_t cols, uint32_t batch,
        uint32_t kind = 12); // 12=Q4_K, 14=Q6_K

    // Native quantised dot product: one output row per invocation.
    //   kind 0 = Q4_K x Q8_K, kind 1 = Q6_K x Q8_K
    //   packed        : weight bytes, u32-aligned
    //   q8_interleaved: per block [d, qs(256), bsums(16)] as floats = 273 floats
    // Returns false on any failure; never silently falls back to the CPU.
    bool ExecuteQuantDot(const void* packed, size_t packed_bytes,
                         const void* q8_interleaved, size_t q8_bytes,
                         void* out, size_t out_bytes,
                         size_t n_out, size_t n_in, size_t n_blocks, int kind);

    // Batched variant (RAWRXD_DEEP2_LEGACY_QUANT_GPU_001): Begin/Queue/End
    // records N independent quant-dot dispatches into ONE command buffer with
    // ONE fence, so a MoE block's 2*selected dots cost two submits instead of
    // 2*selected. Queue only dots whose outputs are read AFTER End: the batch
    // is not a dependency resolver. Any failure reports false and the batch is
    // discarded (no partial state), so the caller falls back to single calls.
    bool BeginQuantDotBatch();
    bool QueueQuantDot(const void* packed, size_t packed_bytes, const void* q8_interleaved,
                       size_t q8_bytes, void* out, size_t out_bytes,
                       size_t n_out, size_t n_in, int kind);
    bool EndQuantDotBatch();

    // DEEP2_VULKAN_SUBMIT_OPT_001: RuntimeGraph command-buffer lifecycle
    // (names match deep2 BeginFusedLayer/EndFusedLayer). Marks a fuse window
    // for SUBMIT_TRACE / submit accounting; ForceHostSync is the true
    // host-data dependency barrier. GPU-resident attn is still required to
    // collapse ~4 host syncs/layer toward <=10 submits/forward.
    bool BeginFusedLayer();
    bool EndFusedLayer();
    bool ForceHostSync();
    bool FusedRecording() const { return quant_fuse_active_; }

    // DEEP2_VULKAN_SUBMIT_OPT_001: GQA decode attention on QuantDot device.
    // Uploads Q + K/V cache slices, runs quant_attn_decode.spv, downloads out.
    // MLA / mismatched head widths fail closed (return false → CPU OpAttention).
    bool EnsureAttnDecodePipeline();
    bool ExecuteAttnDecodeGqa(
        const float* q, size_t q_floats,
        const float* k_cache, size_t k_floats,
        const float* v_cache, size_t v_floats,
        float* out, size_t out_floats,
        uint32_t head_dim, uint32_t heads, uint32_t kv_heads,
        uint32_t seq_len, float scale);

    // RAWRXD_STRATA_S01/S02/S03/S08: residency queries the Strata expert
    // layer uses to observe and steer the device-local weight cache without
    // changing dispatch semantics. All are read-only or cache-insertion
    // primitives; a stale entry is never served (fingerprint + pointer
    // identity still guard every lookup), so a prefetch can never feed a
    // dispatch stale bytes.
    bool IsQuantWeightResident(const void* packed, size_t bytes, int kind) const;
    bool PrefetchQuantWeight(const void* packed, size_t bytes, int kind);
    // RAWRXD_G04 generation lease. Holds a residency reference to one weight so
    // the residency budget cannot evict it (and cannot defer-destroy its buffer)
    // while the lease is outstanding. The weight is uploaded if it is not yet
    // resident, so a lease taken before the dependent dispatch also removes the
    // first-token upload stall. Returns a non-zero lease id, or 0 on failure.
    // Every lease must be released with ReleaseWeightLease (leases are
    // generation-scoped: the id is unique for the process lifetime of this
    // device, so a stale id is rejected rather than mis-applied).
    uint64_t AcquireWeightLease(const void* packed, size_t bytes, int kind);
    void ReleaseWeightLease(uint64_t lease_id);
    // RAWRXD_G04: force the residency budget (bytes). 0 restores the derived
    // default. Must be set before the first dispatch; the budget is otherwise
    // resolved once from the device heap / RR_WEIGHT_CACHE_MAX_BYTES. Lets a
    // gate force eviction pressure deterministically instead of depending on
    // how much VRAM the host happens to have.
    void SetQuantWeightBudgetBytes(size_t bytes) { quant_weight_budget_bytes_ = bytes; }
    size_t QuantWeightBudgetBytes() const { return quant_weight_budget_bytes_; }
    // RAWRXD_G04 observability: the residency-safety invariants a gate can
    // assert without trusting any counter's intent.
    size_t OutstandingWeightLeases() const;   // leases not yet released
    size_t PinnedWeightCount() const;         // cache entries with pin_count > 0
    size_t RetiredWeightCount() const;        // evicted, destruction still deferred
    uint64_t RetiredWeightsReaped() const;    // deferred destructions completed
    uint64_t WeightResidencyEpoch() const;    // submissions issued so far
    uint64_t CompletedWeightEpoch() const;    // submissions whose fence has signalled
    uint64_t BudgetOverrides() const;         // evictions deferred (all pinned)
    size_t TrimUnpinnedQuantWeights();
    // 0 = LRU (default, the historical policy), 1 = hotness (STRATA_S08).
    void SetWeightCachePolicy(int policy) { weight_cache_policy_ = policy; }
    int WeightCachePolicy() const { return weight_cache_policy_; }
    // D1: the batch descriptor-ring capacity (kQuantBatchMaxSets).
    static constexpr uint32_t QuantDotBatchCapacity() { return kQuantBatchMaxSets; }

    // FP16-weight dot (RAWRXD_DEEP2_F16_QUANT_DOT_CLOSURE): models such as
    // qwen3 carry FP16 projections (blk.N.attn_v.weight) among otherwise
    // quantised weights. Previously those matmuls ran on the CPU, which broke
    // the GPU-only certificate for the whole family. The kernel dots the raw
    // fp16 weights against the raw float activation with no quantisation, so
    // the CPU reference agrees to fp32 rounding.
    bool EnsureF16DotPipeline();
    bool ExecuteF16Dot(const void* packed, size_t packed_bytes,
                       const float* x, size_t n_in,
                       void* out, size_t out_bytes,
                       size_t n_out);
    bool DispatchMatMul(uint32_t input_a_idx,
                        uint32_t input_b_idx,
                        uint32_t output_idx,
                        uint32_t M,
                        uint32_t K,
                        uint32_t N);
    
    // High-performance async variant using command buffer pooling
    bool DispatchMatMulAsync(uint32_t input_a_idx,
                             uint32_t input_b_idx,
                             uint32_t output_idx,
                             uint32_t M,
                             uint32_t K,
                             uint32_t N);
    
    VulkanDeviceInfo GetDeviceInfo() const { return device_info_; }
    bool IsAMDDevice() const { return device_info_.vendor_id == 0x1002; }
    bool IsNvidiaDevice() const { return device_info_.vendor_id == 0x10DE; }

    // Instrumentation counters (kernel/submit/wait time, transfer bytes,
    // allocation and reuse accounting). Never modifies GPU state.
    const GpuCounters& GetGpuCounters() const { return gpu_counters_; }

    // Multi-GPU support. By default SelectPhysicalDevice() auto-picks the
    // highest-scoring device. Call SetPreferredDeviceIndex() before
    // Initialize() to pin this instance to a specific enumerated index, which
    // is what allows more than one GPU to be used in one process.
    struct EnumeratedDevice {
        int32_t index;
        std::string name;
        uint32_t vendor_id;
        uint32_t device_id;
        VkPhysicalDeviceType device_type;
    };
    static std::vector<EnumeratedDevice> EnumerateDevices();

    void SetPreferredDeviceIndex(int32_t idx) { preferred_device_index_ = idx; }
    int32_t GetPreferredDeviceIndex() const { return preferred_device_index_; }
    int32_t GetActiveDeviceIndex() const { return active_device_index_; }
    
    bool AllocateBuffer(size_t size, uint32_t& buffer_idx, size_t& memory_size);
    bool AllocateBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory);
    bool CopyBufferToHost(uint32_t buffer_idx, void* host_data, size_t size);
    bool CopyBufferToHost(VkBuffer device_buffer, void* host_data, size_t size);
    bool CopyHostToBuffer(void* host_data, uint32_t buffer_idx, size_t size);
    bool CopyHostToBuffer(void* host_data, VkBuffer device_buffer, size_t size);
    
    // KV Cache management for autoregressive inference
    bool AllocateKVCache(uint32_t num_layers, uint32_t max_seq_len, uint32_t head_dim);
    bool AppendToKVCache(uint32_t layer_idx, const float* k_new, const float* v_new, uint32_t token_pos);
    bool GetKVCacheSlice(uint32_t layer_idx, uint32_t start_pos, uint32_t end_pos, float* k_out, float* v_out);
    void ClearKVCache();
    bool IsKVCacheAllocated() const { return kv_cache_allocated_; }
    
    // Command buffer & synchronization utilities
    bool ExecuteSingleTimeCommands(std::function<void(VkCommandBuffer)> record_func);
    bool ExecuteCommandBuffer(VkCommandBuffer cmd_buffer);
    
    // High-performance async execution
    VkCommandBuffer AcquireAsyncCommandBuffer();
    bool SubmitAsyncCommandBuffer(VkCommandBuffer cmd_buffer);
    bool FlushAsyncCommands();  // Wait for all pending async operations
    bool CheckAsyncCompletion(VkCommandBuffer cmd_buffer);  // Non-blocking check
    
    // Descriptor set management
    bool CreateDescriptorSetLayout(uint32_t binding_count, VkDescriptorSetLayout& layout);
    bool AllocateDescriptorSet(VkDescriptorSetLayout layout, VkDescriptorSet& descriptor_set);
    bool UpdateDescriptorSet(VkDescriptorSet descriptor_set, uint32_t binding, VkBuffer buffer, size_t buffer_size);
    
    // Scalar CPU implementations (no GPU)
    bool ExecuteMatMul(const float* input_a, const float* input_b, 
                       float* output, uint32_t m, uint32_t k, uint32_t n);
    bool ExecuteAttention(const float* queries, const float* keys, const float* values,
                         float* output, uint32_t seq_len, uint32_t head_dim);
    bool ExecuteRoPE(float* embeddings, uint32_t dim, uint32_t seq_pos, uint32_t rotation_dim);
    bool ExecuteRMSNorm(float* data, uint32_t size, float epsilon = 1e-5f);
    bool ExecuteSiLU(float* data, uint32_t size);
    bool ExecuteSoftmax(float* data, uint32_t size);
    bool ExecuteDequantize(const uint8_t* quantized, float* output,
                           uint32_t elements, const std::string& quant_type);
    
    void Cleanup();

private:
    bool CreateInstance();
    bool SelectPhysicalDevice();
    bool CreateLogicalDevice();
    bool CreateCommandPool();
    bool LoadSPIRVCode(const std::string& path, std::vector<uint32_t>& code);
    uint32_t FindMemoryType(uint32_t type_filter, VkMemoryPropertyFlags properties);

    VkInstance instance_ = nullptr;
    VkPhysicalDevice physical_device_ = nullptr;
    VkDevice device_ = nullptr;
    VkQueue compute_queue_ = nullptr;
    VkCommandPool command_pool_ = nullptr;
    VkDescriptorPool descriptor_pool_ = nullptr;

    // Async command buffer pooling for high-performance batching
    std::vector<CommandBufferPool> command_buffer_pool_;
    std::queue<size_t> available_buffer_indices_;

    // Permanent descriptor system for MatMul (avoid per-dispatch allocation overhead)
    VkDescriptorSetLayout matmul_descriptor_set_layout_ = nullptr;
    VkDescriptorPool matmul_descriptor_pool_ = nullptr;

    // Permanent descriptor system for RoPE
    VkDescriptorSetLayout rope_descriptor_set_layout_ = nullptr;
    VkDescriptorPool rope_descriptor_pool_ = nullptr;

    // Permanent descriptor system for the quantised dot product
    VkDescriptorSetLayout quant_descriptor_set_layout_ = nullptr;
    VkDescriptorPool quant_descriptor_pool_ = nullptr;
    // Pool capacity, recorded at creation so allocation failures can report
    // whether the pool is exhausted (lifecycle) or undersized (sizing).
    uint32_t quant_pool_max_sets_ = 0;
    static constexpr const char* kQuantDotShaderPath =
        "F:\\rawrxd\\tools\\shaders\\quant_dot.spv";
    static constexpr const char* kRoPEShaderPath =
        "F:\\rawrxd\\tools\\shaders\\rope_fixed.spv";

    // ---- RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY fast path state ----
    // ExecuteQuantDot previously allocated three fresh device buffers, two
    // staging buffers, a fence, a command buffer and a descriptor set on EVERY
    // dispatch, and re-uploaded the immutable packed weights every time. Weights
    // are now uploaded once and kept device resident; activations and outputs
    // reuse pooled device buffers; one command buffer + one fence carry the
    // upload, dispatch and readback for a call; and descriptor sets are recycled
    // from a small ring. The host still waits for completion before reading the
    // output, so every reuse is race-free.
    struct QuantWeight {
        VkBuffer buffer = nullptr;
        VkDeviceMemory memory = nullptr;
        size_t bytes = 0;
        int kind = -1;
        uint64_t fingerprint = 0;   // first 8 packed bytes, cheap staleness guard
        uint64_t last_used = 0;     // LRU stamp for the residency budget
        uint64_t use_count = 0;     // hotness counter (RAWRXD_STRATA_S08): dispatches served
        // RAWRXD_G04: in-flight references held against this entry. Non-zero
        // means some recorded, queued or leased dispatch may still read the
        // buffer, so the residency budget must never evict it.
        uint64_t pin_count = 0;
    };
    std::unordered_map<const void*, QuantWeight> quant_weight_cache_;;
    // 0 = LRU, 1 = hotness (STRATA_S08). Seeded from RR_WEIGHT_CACHE_POLICY at
    // first use so an existing deployment keeps the historical behaviour
    // unless the operator opts in.
    int weight_cache_policy_ = -1;

    // ---- RAWRXD_G04: concurrent-safe residency --------------------------------
    // The residency cache, the pooled scratch, the descriptor rings, the batch
    // state and the instrumentation counters are shared device state. They are
    // guarded by quant_mu_ (recursive: the public dispatch entry points take it
    // and then call the helpers below, which take it again). Dispatch remains
    // serialised against other dispatch, which is the pre-existing contract;
    // what G04 adds is that OBSERVING and STEERING residency (IsWeightResident,
    // PrefetchWeight, leases) is now safe and never races a concurrent
    // dispatch, and that eviction can no longer free a buffer another thread
    // still has in flight.
    mutable std::recursive_mutex quant_mu_;

    // Fence-safe eviction: an evicted entry's device objects are not destroyed
    // inside the eviction loop. They are moved here tagged with the dispatch
    // epoch that retired them and destroyed only after ReapRetiredWeights()
    // observes that epoch's fence signalled, so no in-flight command buffer can
    // still reference them.
    struct RetiredWeight {
        VkBuffer buffer = nullptr;
        VkDeviceMemory memory = nullptr;
        size_t bytes = 0;
        uint64_t retired_epoch = 0;
    };
    std::vector<RetiredWeight> quant_retired_;
    std::unordered_map<uint64_t, const void*> quant_leases_;  // lease id -> weight key
    uint64_t quant_lease_seq_ = 0;
    uint64_t quant_epoch_ = 0;             // bumped on every submission
    uint64_t quant_completed_epoch_ = 0;   // epoch whose fence has been waited
    uint64_t quant_retired_reaped_ = 0;    // deferred destructions completed
    uint64_t quant_budget_overrides_ = 0;  // eviction deferred: every entry pinned
    void RetireQuantWeight(const QuantWeight& w);
    void ReapRetiredWeights();
    void NoteSubmissionComplete();
    bool PinQuantWeight(const void* packed, size_t bytes, int kind);
    void UnpinQuantWeight(const void* packed);
    // Stable-address pool: entries are heap-allocated so an Acquire never
    // invalidates a pointer the caller already holds for another entry.
    std::vector<std::unique_ptr<QuantScratch>> quant_scratch_pool_;
    static constexpr uint32_t kQuantRingSets = 4;   // recycled descriptor sets
    static constexpr uint32_t kQuantPoolSets = 256;  // pool capacity for the ring
    std::vector<VkDescriptorSet> quant_ds_ring_;
    size_t quant_ds_ring_next_ = 0;
    bool quant_fast_ready_ = false;    // ring + persistent objects created
    VkFence quant_fence_ = nullptr;
    VkCommandBuffer quant_cmd_ = nullptr;
    VkBuffer upload_staging_ = nullptr;     // persistent host-visible staging
    VkDeviceMemory upload_staging_mem_ = nullptr;
    size_t upload_staging_size_ = 0;
    void* upload_staging_mapped_ = nullptr;
    VkBuffer readback_buffer_ = nullptr;   // persistent host-visible readback
    VkDeviceMemory readback_memory_ = nullptr;
    size_t readback_size_ = 0;
    void* readback_mapped_ = nullptr;
    uint64_t quant_lru_seq_ = 0;               // clock for weight cache LRU
    uint64_t quant_weight_budget_bytes_ = 0;   // 0 = derive from the device heap

    // RAWRXD_GATE7_TPS_001: GPU-side execution time from timestamp queries.
    // kernel_ms measures the HOST blocked in vkWaitForFences, which conflates
    // driver/submit latency with real shader execution. gpu_ms is read back
    // from the device timeline so TPS work can tell compute from dispatch
    // overhead. Zero (and ts_supported_ false) when the device has no valid
    // timestamp bits - never estimated.
    VkQueryPool quant_ts_pool_ = nullptr;
    bool quant_ts_pool_attempted_ = false;
    bool ts_supported_ = false;
    double ts_period_ns_ = 0.0;
    bool EnsureQuantTimestampPool();

    // Fast-path helpers. They never silently fall back: any failure is
    // reported so the quant-dot caller can account a CPU run.
    bool EnsureQuantFastPath();
    void ReleaseQuantFastPath();
    bool EnsureHostVisible(size_t bytes, VkBuffer& buf, VkDeviceMemory& mem,
                           size_t& size, void*& mapped);

    QuantWeight* EnsureQuantWeight(const void* packed, size_t bytes, int kind);
    GpuCounters gpu_counters_;

    // Batch state (Begin/Queue/End are public above). One entry per queued dot.
    struct QuantBatchEntry {
        VkBuffer weight = nullptr;
        VkBuffer q8 = nullptr;      // device-side batch buffer (regions per entry)
        VkBuffer out = nullptr;     // ditto
        size_t q8_bytes = 0;
        size_t out_bytes = 0;
        void* out_host = nullptr;   // caller's destination buffer
        VkDescriptorSet ds = nullptr;
        uint32_t n_out = 0, n_in = 0, n_blocks = 0, kind = 0;   // push constants
    };
    static constexpr uint32_t kQuantBatchMaxSets = 32;
    bool quant_batch_active_ = false;
    bool quant_fuse_active_ = false;   // DEEP2_VULKAN_SUBMIT_OPT_001
    uint32_t quant_fuse_submits_ = 0;

    // DEEP2_VULKAN_SUBMIT_OPT_001 AttnDecode scratch (QuantDot device)
    VkDescriptorSetLayout attn_set_layout_ = nullptr;
    VkDescriptorPool attn_desc_pool_ = nullptr;
    VkBuffer attn_q_dev_ = nullptr, attn_k_dev_ = nullptr, attn_v_dev_ = nullptr, attn_o_dev_ = nullptr;
    VkDeviceMemory attn_q_mem_ = nullptr, attn_k_mem_ = nullptr, attn_v_mem_ = nullptr, attn_o_mem_ = nullptr;
    size_t attn_q_cap_ = 0, attn_k_cap_ = 0, attn_v_cap_ = 0, attn_o_cap_ = 0;
    VkBuffer attn_stage_q_ = nullptr, attn_stage_k_ = nullptr, attn_stage_v_ = nullptr, attn_stage_o_ = nullptr;
    VkDeviceMemory attn_stage_q_mem_ = nullptr, attn_stage_k_mem_ = nullptr,
                   attn_stage_v_mem_ = nullptr, attn_stage_o_mem_ = nullptr;
    size_t attn_stage_q_sz_ = 0, attn_stage_k_sz_ = 0, attn_stage_v_sz_ = 0, attn_stage_o_sz_ = 0;
    void* attn_stage_q_map_ = nullptr;
    void* attn_stage_k_map_ = nullptr;
    void* attn_stage_v_map_ = nullptr;
    void* attn_stage_o_map_ = nullptr;
    std::unordered_set<const void*> batch_pinned_;  // G04: weight keys pinned for the open batch (eviction must skip them until End)
    std::vector<QuantBatchEntry> quant_batch_entries_;
    std::vector<VkDescriptorSet> quant_batch_sets_;
    VkBuffer quant_batch_q8_dev_ = nullptr;
    VkDeviceMemory quant_batch_q8_mem_ = nullptr;
    VkBuffer quant_batch_out_dev_ = nullptr;
    VkDeviceMemory quant_batch_out_mem_ = nullptr;
    size_t quant_batch_q8_cap_ = 0, quant_batch_out_cap_ = 0;
    // Host-visible sides of the batch buffers (persistent, grown as needed).
    VkBuffer quant_batch_q8_host_ = nullptr;
    VkDeviceMemory quant_batch_q8_host_mem_ = nullptr;
    size_t quant_batch_q8_host_size_ = 0;
    void* quant_batch_q8_host_mapped_ = nullptr;
    VkBuffer quant_batch_out_host_ = nullptr;
    VkDeviceMemory quant_batch_out_host_mem_ = nullptr;
    size_t quant_batch_out_host_size_ = 0;
    void* quant_batch_out_host_mapped_ = nullptr;
    // Bump cursors into the host batch buffers; reset at BeginQuantDotBatch.
    size_t quant_batch_q8_host_used_ = 0, quant_batch_out_host_used_ = 0;

    // KV Cache for autoregressive inference
    std::vector<std::pair<VkBuffer, VkDeviceMemory>> kv_cache_buffers_; // 2 per layer (K, V)
    uint32_t kv_cache_num_layers_ = 0;
    uint32_t kv_cache_max_seq_len_ = 0;
    uint32_t kv_cache_head_dim_ = 0;
    bool kv_cache_allocated_ = false;
    
    // Persistent staging buffer for optimized host-to-device transfers
    VkBuffer staging_buffer_ = nullptr;
    VkDeviceMemory staging_memory_ = nullptr;
    size_t staging_buffer_size_ = 0;

    VulkanDeviceInfo device_info_;
    int32_t preferred_device_index_ = -1;   // -1 = auto-select
    int32_t active_device_index_ = -1;      // resolved index actually used
    std::unordered_map<std::string, ComputeShader> shaders_;
    std::vector<VulkanTensor> uploaded_tensors_;
    std::vector<std::pair<VkBuffer, VkDeviceMemory>> allocated_buffers_;
    std::unordered_map<std::string, VkDescriptorSetLayout> descriptor_layouts_;
    
    // Helper methods for command buffer pool management
    void InitializeCommandBufferPool(uint32_t pool_size = 4);
    void CleanupCommandBufferPool();
    
    // Helper for offset-based buffer copies (KV cache updates)
    bool CopyHostToBufferOffset(const void* host_data, VkBuffer device_buffer, size_t offset, size_t size);
    bool CopyBufferToHostOffset(VkBuffer device_buffer, size_t offset, void* host_data, size_t size);
    
    // Helper for creating staging buffers (reduces code duplication)
    bool CreateStagingBuffer(size_t size, VkBuffer& buffer, VkDeviceMemory& memory);
};
