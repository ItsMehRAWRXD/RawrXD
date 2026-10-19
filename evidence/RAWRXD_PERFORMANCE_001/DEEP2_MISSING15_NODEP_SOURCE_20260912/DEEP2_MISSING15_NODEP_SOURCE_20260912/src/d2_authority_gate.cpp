#include "d2_nodep.h"

extern "C" int d2_authority_gate(const D2AuthorityInput* in) {
    if (!in) return 0;
    const D2FabricMetrics& f=in->fabric;
    if (!in->product_linked || !in->runtime_bind_real) return 0;
    if (!in->aggregate_bw_authority_requested) return 0;
    if (!d2_nvme_critical_path_guard(in->critical_path_nvme_reads_per_token)) return 0;
    if (!f.gpu0_real_forwards || !f.gpu1_real_forwards) return 0;
    if (!f.gpu0_local_bytes || !f.gpu1_local_bytes) return 0;
    if (!f.overlap_ns || !f.overlap_ratio_measured) return 0;
    if (f.serial_gpu_chain) return 0;
    if (f.weight_migration_bytes_nonzero || f.inter_gpu_bytes) return 0;
    if (!f.compact_merge_real) return 0;
    if (f.device_lost || f.synthetic_device_io) return 0;
    if (!f.aggregate_effective_bps || !f.critical_path_ns) return 0;
    return 1;
}
