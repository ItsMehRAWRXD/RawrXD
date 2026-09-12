#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "deep2_dual_fabric.h"

struct D2Fabric {
    D2FabricConfig cfg;
    D2FabricBackend be;
};

static uint64_t qpc_ns() {
    LARGE_INTEGER f, q;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&q);
    return (uint64_t)((q.QuadPart * 1000000000ull) / (uint64_t)f.QuadPart);
}

struct LaneJob {
    D2Fabric* f;
    const D2FabricSlice* slice;
    const void* activation;
    uint64_t activation_bytes;
    void* output;
    uint64_t output_bytes;
    HANDLE go;
    HANDLE done;
    volatile LONG rc;
    uint64_t start_ns;
    uint64_t end_ns;
};

static DWORD WINAPI lane_thread(LPVOID p) {
    LaneJob* j = (LaneJob*)p;
    WaitForSingleObject(j->go, INFINITE);
    j->start_ns = qpc_ns();
    j->rc = j->f->be.submit(
        j->f->be.user,
        j->slice->owner_gpu,
        j->slice,
        j->activation,
        j->activation_bytes,
        j->output,
        j->output_bytes);
    j->end_ns = qpc_ns();
    SetEvent(j->done);
    return 0;
}

D2Fabric* d2fabric_create(const D2FabricConfig* cfg, const D2FabricBackend* backend) {
    if (!cfg || !backend || !backend->submit || !backend->reduce) return 0;
    if (!cfg->bw0_bytes_per_sec || !cfg->bw1_bytes_per_sec) return 0;
    D2Fabric* f = (D2Fabric*)calloc(1, sizeof(D2Fabric));
    if (!f) return 0;
    f->cfg = *cfg;
    f->be = *backend;
    return f;
}

void d2fabric_destroy(D2Fabric* f) {
    if (f) free(f);
}

static uint32_t weighted_rows(uint32_t rows, uint64_t b0, uint64_t b1) {
    const uint64_t total = b0 + b1;
    if (!rows || !total) return 0;
    uint64_t r0 = ((uint64_t)rows * b0 + total / 2) / total;
    if (r0 == 0) r0 = 1;
    if (r0 >= rows && rows > 1) r0 = rows - 1;
    return (uint32_t)r0;
}

int d2fabric_plan_rows(
    D2Fabric* f,
    uint64_t tensor_id,
    uint64_t source_offset_bytes,
    uint64_t source_bytes,
    uint32_t total_rows,
    uint32_t op_kind,
    uint64_t activation_bytes_each,
    uint64_t reduce_bytes,
    uint32_t requires_sum_reduce,
    D2FabricTokenPlan* out_plan)
{
    if (!f || !out_plan || total_rows < 2 || source_bytes == 0) return -1;
    if (reduce_bytes > f->cfg.max_reduce_bytes) return -2;
    if (activation_bytes_each > f->cfg.max_broadcast_bytes) return -3;

    memset(out_plan, 0, sizeof(*out_plan));
    const uint32_t r0 = weighted_rows(total_rows, f->cfg.bw0_bytes_per_sec, f->cfg.bw1_bytes_per_sec);
    const uint32_t r1 = total_rows - r0;

    /* Approximate byte split by row count. Real binder may round to quant block boundaries. */
    uint64_t bytes0 = (source_bytes * (uint64_t)r0) / (uint64_t)total_rows;
    uint64_t bytes1 = source_bytes - bytes0;

    out_plan->gpu[0].tensor_id = tensor_id;
    out_plan->gpu[0].source_offset_bytes = source_offset_bytes;
    out_plan->gpu[0].source_bytes = bytes0;
    out_plan->gpu[0].row_begin = 0;
    out_plan->gpu[0].row_count = r0;
    out_plan->gpu[0].op_kind = op_kind;
    out_plan->gpu[0].owner_gpu = 0;

    out_plan->gpu[1].tensor_id = tensor_id;
    out_plan->gpu[1].source_offset_bytes = source_offset_bytes + bytes0;
    out_plan->gpu[1].source_bytes = bytes1;
    out_plan->gpu[1].row_begin = r0;
    out_plan->gpu[1].row_count = r1;
    out_plan->gpu[1].op_kind = op_kind;
    out_plan->gpu[1].owner_gpu = 1;

    out_plan->activation_bytes_each = activation_bytes_each;
    out_plan->reduce_bytes = reduce_bytes;
    out_plan->requires_sum_reduce = requires_sum_reduce ? 1u : 0u;
    return 0;
}

int d2fabric_execute(
    D2Fabric* f,
    const D2FabricTokenPlan* plan,
    const void* activation,
    void* out0,
    void* out1,
    void* merged,
    uint64_t output_bytes,
    D2FabricCounters* out_counters)
{
    if (!f || !plan || !out0 || !out1 || !merged || !out_counters) return -1;
    memset(out_counters, 0, sizeof(*out_counters));

    HANDLE go = CreateEventA(0, TRUE, FALSE, 0);
    HANDLE done0 = CreateEventA(0, TRUE, FALSE, 0);
    HANDLE done1 = CreateEventA(0, TRUE, FALSE, 0);
    if (!go || !done0 || !done1) return -2;

    LaneJob j0 = {};
    LaneJob j1 = {};
    j0.f = f; j1.f = f;
    j0.slice = &plan->gpu[0]; j1.slice = &plan->gpu[1];
    j0.activation = activation; j1.activation = activation;
    j0.activation_bytes = plan->activation_bytes_each;
    j1.activation_bytes = plan->activation_bytes_each;
    j0.output = out0; j1.output = out1;
    j0.output_bytes = output_bytes; j1.output_bytes = output_bytes;
    j0.go = go; j1.go = go;
    j0.done = done0; j1.done = done1;

    HANDLE t0 = CreateThread(0, 0, lane_thread, &j0, 0, 0);
    HANDLE t1 = CreateThread(0, 0, lane_thread, &j1, 0, 0);
    if (!t0 || !t1) {
        if (t0) CloseHandle(t0);
        if (t1) CloseHandle(t1);
        CloseHandle(go); CloseHandle(done0); CloseHandle(done1);
        return -3;
    }

    /* One epoch release: both submitters leave together. */
    SetEvent(go);
    HANDLE dones[2] = { done0, done1 };
    WaitForMultipleObjects(2, dones, TRUE, INFINITE);

    out_counters->start_ns[0] = j0.start_ns;
    out_counters->start_ns[1] = j1.start_ns;
    out_counters->end_ns[0] = j0.end_ns;
    out_counters->end_ns[1] = j1.end_ns;
    out_counters->active_ns[0] = j0.end_ns > j0.start_ns ? j0.end_ns - j0.start_ns : 0;
    out_counters->active_ns[1] = j1.end_ns > j1.start_ns ? j1.end_ns - j1.start_ns : 0;
    out_counters->local_weight_bytes[0] = plan->gpu[0].source_bytes;
    out_counters->local_weight_bytes[1] = plan->gpu[1].source_bytes;
    out_counters->broadcast_bytes = plan->activation_bytes_each * 2;
    out_counters->reduce_bytes = plan->reduce_bytes;
    out_counters->weight_migration_bytes = 0;

    const uint64_t latest_start = j0.start_ns > j1.start_ns ? j0.start_ns : j1.start_ns;
    const uint64_t earliest_end = j0.end_ns < j1.end_ns ? j0.end_ns : j1.end_ns;
    out_counters->both_lanes_worked =
        (plan->gpu[0].source_bytes && plan->gpu[1].source_bytes && j0.rc == 0 && j1.rc == 0) ? 1u : 0u;

    /* Serial chain means no measured overlap at all. */
    out_counters->serial_gpu_chain = earliest_end > latest_start ? 0u : 1u;

    int rc = 0;
    if (j0.rc != 0) rc = (int)j0.rc;
    if (j1.rc != 0 && rc == 0) rc = (int)j1.rc;

    if (rc == 0) {
        rc = f->be.reduce(
            f->be.user, out0, out1, merged,
            plan->reduce_bytes ? plan->reduce_bytes : output_bytes,
            plan->requires_sum_reduce);
    }

    WaitForSingleObject(t0, INFINITE);
    WaitForSingleObject(t1, INFINITE);
    CloseHandle(t0); CloseHandle(t1);
    CloseHandle(go); CloseHandle(done0); CloseHandle(done1);
    return rc;
}

uint64_t d2fabric_aggregate_effective_bps(const D2FabricCounters* c) {
    if (!c || !c->both_lanes_worked || c->serial_gpu_chain) return 0;
    const uint64_t start = c->start_ns[0] < c->start_ns[1] ? c->start_ns[0] : c->start_ns[1];
    const uint64_t end = c->end_ns[0] > c->end_ns[1] ? c->end_ns[0] : c->end_ns[1];
    if (end <= start) return 0;
    const uint64_t wall_ns = end - start;
    const uint64_t local_bytes = c->local_weight_bytes[0] + c->local_weight_bytes[1];

    /* Conservative: count only local weight bytes, not broadcast/reduce traffic. */
    if (local_bytes > UINT64_MAX / 1000000000ull)
        return (uint64_t)((long double)local_bytes * 1000000000.0L / (long double)wall_ns);
    return (local_bytes * 1000000000ull) / wall_ns;
}

uint64_t d2fabric_utilization_ppm(uint64_t effective_bps, uint64_t nominal_aggregate_bps) {
    if (!nominal_aggregate_bps) return 0;
    return (uint64_t)((long double)effective_bps * 1000000.0L / (long double)nominal_aggregate_bps);
}
