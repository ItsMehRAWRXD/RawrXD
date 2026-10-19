#include "deep2_audit_nodep.h"

extern "C" int d2_q2k_validate_tile(const D2PackedTile* t) {
    if (!t || !t->packed || !t->packed_bytes || !t->x || !t->y || !t->cols || !t->row_count) return 0;
    if (t->materialized_weight_bytes != 0) return 0;
    if (t->scratch_bytes > (64ull << 20)) return 0;
    return 1;
}

extern "C" int d2_q2k_execute_tiled(const D2PackedQ2KOps* ops, const D2PackedTile* base,
                                     uint32_t rows_per_tile, uint32_t total_rows) {
    if (!ops || !ops->ctx || !ops->execute || !base || !rows_per_tile || !total_rows) return 0;
    if (!d2_q2k_validate_tile(base)) return 0;
    if (base->row_begin != 0 || base->row_count != total_rows) return 0;
    uint32_t row=0;
    while (row < total_rows) {
        D2PackedTile t=*base;
        t.row_begin=row;
        t.row_count=(total_rows-row < rows_per_tile) ? (total_rows-row) : rows_per_tile;
        if (!d2_q2k_validate_tile(&t) || !ops->execute(ops->ctx, &t)) return 0;
        row += t.row_count;
    }
    return 1;
}
