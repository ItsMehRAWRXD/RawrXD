#ifndef D2_ROOFLINE_H
#define D2_ROOFLINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    D2RF_OK = 0,
    D2RF_EINVAL = -1,
    D2RF_ESTATE = -2,
    D2RF_EAUTH = -3,
    D2RF_EOVERFLOW = -4
};

typedef enum D2RfTier {
    D2RF_TIER_VRAM0 = 0,
    D2RF_TIER_VRAM1 = 1,
    D2RF_TIER_RAM   = 2,
    D2RF_TIER_MMAP  = 3,
    D2RF_TIER_NVME  = 4
} D2RfTier;

typedef struct D2RfQuantForm {
    uint32_t type_id;
    uint32_t block_elems;
    uint32_t block_bytes;
    uint32_t row_align;
} D2RfQuantForm;

typedef struct D2RfLaneCost {
    uint64_t useful_bytes;
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t bytes_per_ns_q20;
    uint64_t fixed_ns_q20;
} D2RfLaneCost;

typedef struct D2RfExpert {
    uint32_t expert_id;
    uint32_t selected;
    uint32_t predicted_next;
    uint32_t reuse_score_q16;
    uint64_t packed_bytes;
    D2RfTier resident_tier;
    uint32_t resident_lane;
} D2RfExpert;

typedef struct D2RfTokenInput {
    uint64_t token_index;

    uint64_t packed_weight_bytes;
    uint64_t kv_bytes;
    uint64_t activation_bytes;
    uint64_t reduction_bytes;

    uint64_t vram0_local_bytes;
    uint64_t vram1_local_bytes;
    uint64_t ram_bytes;
    uint64_t mmap_bytes;
    uint64_t nvme_bytes;

    uint64_t vram0_budget_free;
    uint64_t vram1_budget_free;

    uint64_t gpu0_bw_bytes_per_s;
    uint64_t gpu1_bw_bytes_per_s;
    uint64_t pcie_bytes_per_s;
    uint64_t ram_bytes_per_s;
    uint64_t nvme_bytes_per_s;

    uint64_t gpu0_start_ns;
    uint64_t gpu1_start_ns;

    uint64_t measured_critical_ns;
    uint64_t measured_finish_skew_ns;

    uint32_t selected_experts;
    uint32_t predicted_experts;
    uint32_t command_rebuilds;
    uint32_t kv_host_roundtrips;
    uint32_t critical_path_nvme_reads;
    uint32_t host_materializations;
    uint32_t cpu_f32_expands;
    uint32_t serial_gpu_chain;
    uint32_t weight_migration;
    uint32_t device_lost;
    uint32_t output_parity;
    uint32_t product_linked;
    uint32_t packed_native;
    uint32_t material_overlap;
} D2RfTokenInput;

typedef struct D2RfPlan {
    uint64_t token_index;

    uint64_t active_bytes_total;
    uint64_t bytes_already_local;
    uint64_t bytes_not_local;
    uint64_t critical_remote_bytes;

    uint64_t gpu0_target_bytes;
    uint64_t gpu1_target_bytes;
    uint64_t prefetch_budget_bytes;

    uint64_t predicted_gpu0_end_ns;
    uint64_t predicted_gpu1_end_ns;
    uint64_t predicted_critical_ns;
    uint64_t predicted_finish_skew_ns;

    uint64_t roofline_tps_milli;
    uint64_t sustained_tps_milli;

    uint32_t local_hit_ratio_q16;
    uint32_t remote_penalty_q16;
    uint32_t prefetch_required;
    uint32_t pin_selected_experts;
    uint32_t compact_reduce;
    uint32_t authority_eligible;
} D2RfPlan;

typedef struct D2RfState {
    uint64_t tokens_seen;
    uint64_t authoritative_tokens;

    uint64_t ewma_gpu0_bw_q20;
    uint64_t ewma_gpu1_bw_q20;
    uint64_t ewma_pcie_bw_q20;
    uint64_t ewma_ram_bw_q20;

    uint64_t best_critical_ns;
    uint64_t best_local_hit_q16;

    uint64_t last_gpu0_target_bytes;
    uint64_t last_gpu1_target_bytes;

    uint32_t pin_hysteresis_q16;
    uint32_t prefetch_margin_q16;
    uint32_t rollback_threshold_q16;
    uint32_t initialized;
} D2RfState;

typedef struct D2RfReceipt {
    uint64_t token_index;
    uint64_t active_bytes_total;
    uint64_t bytes_already_local;
    uint64_t bytes_not_local;
    uint64_t critical_remote_bytes;

    uint64_t gpu0_target_bytes;
    uint64_t gpu1_target_bytes;
    uint64_t predicted_critical_ns;
    uint64_t measured_critical_ns;
    uint64_t predicted_finish_skew_ns;
    uint64_t measured_finish_skew_ns;

    uint64_t roofline_tps_milli;
    uint64_t sustained_tps_milli;

    uint32_t local_hit_ratio_q16;
    uint32_t authority_eligible;

    uint32_t command_rebuilds;
    uint32_t kv_host_roundtrips;
    uint32_t critical_path_nvme_reads;
    uint32_t host_materializations;
    uint32_t cpu_f32_expands;
    uint32_t serial_gpu_chain;
    uint32_t weight_migration;
    uint32_t device_lost;
    uint32_t output_parity;
    uint32_t product_linked;
    uint32_t packed_native;
    uint32_t material_overlap;
} D2RfReceipt;

/* Quant density registry. Unknown forms fail closed. */
int d2rf_quant_form(uint32_t type_id, D2RfQuantForm* out);

/* Initialize all fixed-point controls. No heap allocation. */
void d2rf_init(D2RfState* s);

/* Produce one per-token roofline plan. */
int d2rf_plan_token(
    D2RfState* s,
    const D2RfTokenInput* in,
    D2RfPlan* out);

/* Feed measured token timing back into EWMA/best-known state. */
int d2rf_observe(
    D2RfState* s,
    const D2RfTokenInput* in,
    const D2RfPlan* plan);

/* Build an auditable fail-closed receipt. */
int d2rf_receipt(
    const D2RfTokenInput* in,
    const D2RfPlan* plan,
    D2RfReceipt* out);

/* True only when the token is eligible for live product authority. */
int d2rf_receipt_authoritative(const D2RfReceipt* r);

/* Integer helpers exposed for integration tests. */
uint64_t d2rf_muldiv_u64(uint64_t a, uint64_t b, uint64_t d);
uint64_t d2rf_time_ns_for_bytes(uint64_t bytes, uint64_t bytes_per_s);
uint64_t d2rf_tps_milli_from_ns(uint64_t ns);

#ifdef __cplusplus
}
#endif
#endif
