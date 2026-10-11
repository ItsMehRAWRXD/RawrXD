#ifndef D2_MATERIAL_OVERLAP_H
#define D2_MATERIAL_OVERLAP_H

/*
  Deep2 material same-token dual-GPU overlap gate.
  Source-only, no Vulkan SDK headers, no third-party libraries.
  Windows/x64 ABI. The product supplies already-created Vulkan handles and
  function pointers so this module never owns model/device initialization.
*/

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
#  define D2_CALL __stdcall
#  define D2_EXPORT __declspec(dllexport)
#else
#  define D2_CALL
#  define D2_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque Vulkan-compatible handles for x64. */
typedef void*    D2VkDevice;
typedef void*    D2VkQueue;
typedef void*    D2VkCommandBuffer;
typedef uint64_t D2VkQueryPool;
typedef uint64_t D2VkFence;

typedef int32_t  D2VkResult;
typedef uint32_t D2VkFlags;
typedef uint32_t D2VkBool32;
typedef uint32_t D2VkPipelineStageFlags;

enum {
    D2_VK_SUCCESS = 0,
    D2_VK_TRUE = 1,
    D2_VK_QUERY_RESULT_64_BIT = 0x00000001u,
    D2_VK_QUERY_RESULT_WAIT_BIT = 0x00000002u,
    D2_VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT = 0x00000001u,
    D2_VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT = 0x00002000u,
    D2_VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT = 0x00000001u,
    D2_VK_TIME_DOMAIN_DEVICE_EXT = 0,
    D2_VK_TIME_DOMAIN_QUERY_PERFORMANCE_COUNTER_EXT = 3
};

typedef struct D2VkCommandBufferBeginInfo {
    uint32_t sType;
    const void* pNext;
    D2VkFlags flags;
    const void* pInheritanceInfo;
} D2VkCommandBufferBeginInfo;

typedef struct D2VkSubmitInfo {
    uint32_t sType;
    const void* pNext;
    uint32_t waitSemaphoreCount;
    const uint64_t* pWaitSemaphores;
    const D2VkPipelineStageFlags* pWaitDstStageMask;
    uint32_t commandBufferCount;
    const D2VkCommandBuffer* pCommandBuffers;
    uint32_t signalSemaphoreCount;
    const uint64_t* pSignalSemaphores;
} D2VkSubmitInfo;

typedef struct D2VkFenceCreateInfo {
    uint32_t sType;
    const void* pNext;
    D2VkFlags flags;
} D2VkFenceCreateInfo;

typedef struct D2VkCalibratedTimestampInfoEXT {
    uint32_t sType;
    const void* pNext;
    uint32_t timeDomain;
} D2VkCalibratedTimestampInfoEXT;

/* Vulkan structure type values from the public Vulkan ABI. */
enum {
    D2_VK_STRUCTURE_TYPE_SUBMIT_INFO = 4,
    D2_VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 8,
    D2_VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO = 42,
    D2_VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT = 1000184000
};

typedef D2VkResult (D2_CALL *D2PFN_vkResetCommandBuffer)(D2VkCommandBuffer, D2VkFlags);
typedef D2VkResult (D2_CALL *D2PFN_vkBeginCommandBuffer)(D2VkCommandBuffer, const D2VkCommandBufferBeginInfo*);
typedef D2VkResult (D2_CALL *D2PFN_vkEndCommandBuffer)(D2VkCommandBuffer);
typedef void       (D2_CALL *D2PFN_vkCmdResetQueryPool)(D2VkCommandBuffer, D2VkQueryPool, uint32_t, uint32_t);
typedef void       (D2_CALL *D2PFN_vkCmdWriteTimestamp)(D2VkCommandBuffer, D2VkPipelineStageFlags, D2VkQueryPool, uint32_t);
typedef D2VkResult (D2_CALL *D2PFN_vkQueueSubmit)(D2VkQueue, uint32_t, const D2VkSubmitInfo*, D2VkFence);
typedef D2VkResult (D2_CALL *D2PFN_vkCreateFence)(D2VkDevice, const D2VkFenceCreateInfo*, const void*, D2VkFence*);
typedef void       (D2_CALL *D2PFN_vkDestroyFence)(D2VkDevice, D2VkFence, const void*);
typedef D2VkResult (D2_CALL *D2PFN_vkWaitForFences)(D2VkDevice, uint32_t, const D2VkFence*, D2VkBool32, uint64_t);
typedef D2VkResult (D2_CALL *D2PFN_vkGetQueryPoolResults)(D2VkDevice, D2VkQueryPool, uint32_t, uint32_t, size_t, void*, uint64_t, D2VkFlags);
typedef D2VkResult (D2_CALL *D2PFN_vkGetCalibratedTimestampsEXT)(D2VkDevice, uint32_t, const D2VkCalibratedTimestampInfoEXT*, uint64_t*, uint64_t*);

typedef struct D2VkFns {
    D2PFN_vkResetCommandBuffer vkResetCommandBuffer;
    D2PFN_vkBeginCommandBuffer vkBeginCommandBuffer;
    D2PFN_vkEndCommandBuffer vkEndCommandBuffer;
    D2PFN_vkCmdResetQueryPool vkCmdResetQueryPool;
    D2PFN_vkCmdWriteTimestamp vkCmdWriteTimestamp;
    D2PFN_vkQueueSubmit vkQueueSubmit;
    D2PFN_vkCreateFence vkCreateFence;
    D2PFN_vkDestroyFence vkDestroyFence;
    D2PFN_vkWaitForFences vkWaitForFences;
    D2PFN_vkGetQueryPoolResults vkGetQueryPoolResults;
    D2PFN_vkGetCalibratedTimestampsEXT vkGetCalibratedTimestampsEXT;
} D2VkFns;

typedef int32_t (D2_CALL *D2RecordPackedFn)(void* user, D2VkCommandBuffer cmd, uint64_t token_id, uint64_t operator_id, uint64_t* packed_bytes_consumed);
typedef int32_t (D2_CALL *D2CompactReduceFn)(void* user, uint64_t token_id, uint64_t operator_id, uint64_t* reduce_bytes, uint32_t* compact_reduce_real);

typedef struct D2Lane {
    D2VkDevice device;
    D2VkQueue queue;
    D2VkCommandBuffer cmd;
    D2VkQueryPool query_pool; /* two query slots: 0=start, 1=end */
    D2VkFns vk;
    D2RecordPackedFn record_packed;
    void* record_user;
    double timestamp_period_ns;
    uint32_t timestamp_valid_bits; /* 0 or >=64 means unmasked 64-bit */
} D2Lane;

typedef struct D2ProductProof {
    uint64_t token_id;
    uint64_t operator_id;
    uint32_t product_linked;
    uint32_t packed_q2k_live;
    uint32_t full_dequant_buffer;
    uint64_t materialized_weight_bytes;
    uint64_t weight_migration_bytes;
    uint32_t synthetic_device_io;
    uint32_t serial_gpu_chain;
    uint32_t critical_path_nvme_reads;
} D2ProductProof;

typedef struct D2OverlapPolicy {
    /* overlap / shorter-lane duration; 700 = 70%. */
    uint32_t min_shorter_overlap_permille;
    /* overlap / whole two-lane critical span; 500 = 50%. */
    uint32_t min_critical_overlap_permille;
    /* Fail if calibration uncertainty from either GPU exceeds this. */
    uint64_t max_calibration_deviation_ns;
    /* Require each lane to consume at least this many packed bytes. */
    uint64_t min_packed_bytes_per_lane;
} D2OverlapPolicy;

typedef struct D2LaneTiming {
    uint64_t packed_bytes;
    uint64_t gpu_start_tick;
    uint64_t gpu_end_tick;
    uint64_t calibrated_device_tick;
    uint64_t calibrated_qpc_tick;
    uint64_t calibration_deviation_ns;
    uint64_t mapped_start_ns;
    uint64_t mapped_end_ns;
    uint64_t duration_ns;
    int32_t record_rc;
    int32_t submit_rc;
    int32_t wait_rc;
    int32_t query_rc;
    int32_t calibrate_rc;
} D2LaneTiming;

typedef struct D2OverlapReceipt {
    D2LaneTiming lane[2];
    uint64_t overlap_ns;
    uint64_t critical_path_ns;
    uint32_t shorter_overlap_permille;
    uint32_t critical_overlap_permille;
    uint64_t aggregate_packed_bytes;
    uint64_t aggregate_effective_bps;
    uint64_t reduce_bytes;
    uint32_t compact_reduce_real;
    uint32_t dual_gpu_real_forwards;
    uint32_t product_linked;
    uint32_t packed_q2k_live;
    uint32_t full_dequant_buffer;
    uint64_t materialized_weight_bytes;
    uint64_t weight_migration_bytes;
    uint32_t synthetic_device_io;
    uint32_t serial_gpu_chain;
    uint32_t critical_path_nvme_reads;
    uint32_t material_same_token_overlap;
    /* Per-token conjunction only; repeated-token authority is window-minted. */
    uint32_t aggregate_bw_candidate;
    uint32_t aggregate_bw_authority;
    uint32_t promote; /* this module never mints promotion */
    int32_t rc;
} D2OverlapReceipt;

/* Pure math/gate helper; useful for tests and repeated-token aggregation. */
D2_EXPORT int32_t D2_CALL d2_overlap_evaluate(
    const D2ProductProof* proof,
    const D2OverlapPolicy* policy,
    D2OverlapReceipt* io_receipt);

typedef struct D2OverlapWindowPolicy {
    uint32_t min_repeated_tokens;       /* e.g. 16 */
    uint32_t min_candidate_pass_permille; /* e.g. 1000 = every token */
} D2OverlapWindowPolicy;

typedef struct D2OverlapWindowReceipt {
    uint32_t token_count;
    uint32_t candidate_pass_count;
    uint32_t candidate_pass_permille;
    uint32_t min_shorter_overlap_permille_seen;
    uint32_t min_critical_overlap_permille_seen;
    uint64_t total_packed_bytes;
    uint64_t total_critical_path_ns;
    uint64_t aggregate_effective_bps;
    uint32_t aggregate_bw_authority;
    uint32_t promote;
    int32_t rc;
} D2OverlapWindowReceipt;

/* Repeated-token authority mint. A single token can only become a candidate. */
D2_EXPORT int32_t D2_CALL d2_overlap_window_evaluate(
    const D2OverlapReceipt* receipts,
    uint32_t receipt_count,
    const D2OverlapWindowPolicy* policy,
    D2OverlapWindowReceipt* out_window);

/*
  Records real product packed work on both command buffers, submits the two
  queues concurrently, maps each device timestamp interval into Windows QPC
  using VK_EXT_calibrated_timestamps, then calls the real compact reducer.
  No calibrated timestamp support => fail closed, not synthetic authority.
*/
D2_EXPORT int32_t D2_CALL d2_material_overlap_run(
    const D2Lane* lane0,
    const D2Lane* lane1,
    const D2ProductProof* proof,
    const D2OverlapPolicy* policy,
    D2CompactReduceFn compact_reduce,
    void* reduce_user,
    D2OverlapReceipt* out_receipt);

#ifdef __cplusplus
}
#endif
#endif
