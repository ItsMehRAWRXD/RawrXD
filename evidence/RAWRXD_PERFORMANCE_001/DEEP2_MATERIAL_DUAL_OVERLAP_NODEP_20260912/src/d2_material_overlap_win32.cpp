#include "../include/d2_material_overlap.h"
#include <string.h>

#if !defined(_WIN32)
extern "C" int32_t D2_CALL d2_material_overlap_run(
    const D2Lane*, const D2Lane*, const D2ProductProof*, const D2OverlapPolicy*,
    D2CompactReduceFn, void*, D2OverlapReceipt*) { return -1000; }
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <math.h>

static const uint64_t D2_WAIT_FOREVER = ~0ull;

static int lane_fns_ok(const D2Lane* l) {
    return l && l->device && l->queue && l->cmd && l->query_pool && l->record_packed &&
           l->timestamp_period_ns > 0.0 &&
           l->vk.vkResetCommandBuffer && l->vk.vkBeginCommandBuffer &&
           l->vk.vkEndCommandBuffer && l->vk.vkCmdResetQueryPool &&
           l->vk.vkCmdWriteTimestamp && l->vk.vkQueueSubmit &&
           l->vk.vkCreateFence && l->vk.vkDestroyFence && l->vk.vkWaitForFences &&
           l->vk.vkGetQueryPoolResults && l->vk.vkGetCalibratedTimestampsEXT;
}

static int32_t record_lane(const D2Lane* l, const D2ProductProof* p, D2LaneTiming* t) {
    t->record_rc = l->vk.vkResetCommandBuffer(l->cmd, 0);
    if (t->record_rc != D2_VK_SUCCESS) return t->record_rc;
    D2VkCommandBufferBeginInfo bi = {};
    bi.sType = D2_VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = D2_VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    t->record_rc = l->vk.vkBeginCommandBuffer(l->cmd, &bi);
    if (t->record_rc != D2_VK_SUCCESS) return t->record_rc;

    l->vk.vkCmdResetQueryPool(l->cmd, l->query_pool, 0, 2);
    l->vk.vkCmdWriteTimestamp(l->cmd, D2_VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, l->query_pool, 0);
    uint64_t bytes = 0;
    t->record_rc = l->record_packed(l->record_user, l->cmd, p->token_id, p->operator_id, &bytes);
    if (t->record_rc != 0) return t->record_rc;
    t->packed_bytes = bytes;
    l->vk.vkCmdWriteTimestamp(l->cmd, D2_VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, l->query_pool, 1);
    t->record_rc = l->vk.vkEndCommandBuffer(l->cmd);
    return t->record_rc;
}

typedef struct SubmitCtx {
    const D2Lane* lane;
    D2LaneTiming* timing;
    HANDLE start_evt;
    D2VkFence fence;
} SubmitCtx;

static DWORD WINAPI submit_thread(LPVOID pv) {
    SubmitCtx* c = (SubmitCtx*)pv;
    WaitForSingleObject(c->start_evt, INFINITE);
    D2VkSubmitInfo si = {};
    si.sType = D2_VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &c->lane->cmd;
    c->timing->submit_rc = c->lane->vk.vkQueueSubmit(c->lane->queue, 1, &si, c->fence);
    return 0;
}

static uint64_t tick_mask(uint32_t bits) {
    if (bits == 0 || bits >= 64) return ~0ull;
    return (1ull << bits) - 1ull;
}

static int64_t signed_tick_delta(uint64_t value, uint64_t base, uint32_t bits) {
    if (bits == 0 || bits >= 64) return (int64_t)(value - base);
    const uint64_t mask = tick_mask(bits);
    const uint64_t mod = mask + 1ull;
    uint64_t d = (value - base) & mask;
    if (d >= (mod >> 1)) return -(int64_t)(mod - d);
    return (int64_t)d;
}

static uint64_t qpc_to_ns(double qpc, double fq) {
    if (qpc <= 0.0 || fq <= 0.0) return 0;
    const double ns = qpc * (1000000000.0 / fq);
    return ns <= 0.0 ? 0ull : (uint64_t)(ns + 0.5);
}

static int32_t read_and_calibrate(const D2Lane* l, D2LaneTiming* t, double qpc_freq) {
    uint64_t q[2] = {};
    t->query_rc = l->vk.vkGetQueryPoolResults(
        l->device, l->query_pool, 0, 2, sizeof(q), q, sizeof(uint64_t),
        D2_VK_QUERY_RESULT_64_BIT | D2_VK_QUERY_RESULT_WAIT_BIT);
    if (t->query_rc != D2_VK_SUCCESS) return t->query_rc;
    t->gpu_start_tick = q[0];
    t->gpu_end_tick = q[1];

    D2VkCalibratedTimestampInfoEXT ci[2] = {};
    ci[0].sType = D2_VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT;
    ci[0].timeDomain = D2_VK_TIME_DOMAIN_DEVICE_EXT;
    ci[1].sType = D2_VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT;
    ci[1].timeDomain = D2_VK_TIME_DOMAIN_QUERY_PERFORMANCE_COUNTER_EXT;
    uint64_t ts[2] = {};
    uint64_t dev = 0;
    t->calibrate_rc = l->vk.vkGetCalibratedTimestampsEXT(l->device, 2, ci, ts, &dev);
    if (t->calibrate_rc != D2_VK_SUCCESS) return t->calibrate_rc;
    t->calibrated_device_tick = ts[0];
    t->calibrated_qpc_tick = ts[1];
    t->calibration_deviation_ns = dev;

    const int64_t ds = signed_tick_delta(t->gpu_start_tick, t->calibrated_device_tick, l->timestamp_valid_bits);
    const int64_t de = signed_tick_delta(t->gpu_end_tick, t->calibrated_device_tick, l->timestamp_valid_bits);
    const double qpc_per_ns = qpc_freq / 1000000000.0;
    const double qs = (double)t->calibrated_qpc_tick + ((double)ds * l->timestamp_period_ns * qpc_per_ns);
    const double qe = (double)t->calibrated_qpc_tick + ((double)de * l->timestamp_period_ns * qpc_per_ns);
    t->mapped_start_ns = qpc_to_ns(qs, qpc_freq);
    t->mapped_end_ns = qpc_to_ns(qe, qpc_freq);
    return 0;
}

extern "C" int32_t D2_CALL d2_material_overlap_run(
    const D2Lane* l0,
    const D2Lane* l1,
    const D2ProductProof* proof,
    const D2OverlapPolicy* policy,
    D2CompactReduceFn compact_reduce,
    void* reduce_user,
    D2OverlapReceipt* out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->lane[0].record_rc = out->lane[1].record_rc = -1;
    out->lane[0].submit_rc = out->lane[1].submit_rc = -1;
    out->lane[0].wait_rc = out->lane[1].wait_rc = -1;
    out->lane[0].query_rc = out->lane[1].query_rc = -1;
    out->lane[0].calibrate_rc = out->lane[1].calibrate_rc = -1;

    if (!proof || !policy || !compact_reduce || !lane_fns_ok(l0) || !lane_fns_ok(l1)) {
        out->rc = -2; return out->rc;
    }
    if (l0->device == l1->device || l0->queue == l1->queue) {
        /* This gate is specifically for two independent device lanes. */
        out->rc = -3; return out->rc;
    }

    int32_t rc = record_lane(l0, proof, &out->lane[0]);
    if (rc != 0) { out->rc = -10; return out->rc; }
    rc = record_lane(l1, proof, &out->lane[1]);
    if (rc != 0) { out->rc = -11; return out->rc; }

    D2VkFenceCreateInfo fi = {};
    fi.sType = D2_VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    D2VkFence fences[2] = {};
    if (l0->vk.vkCreateFence(l0->device, &fi, 0, &fences[0]) != D2_VK_SUCCESS) { out->rc = -20; return out->rc; }
    if (l1->vk.vkCreateFence(l1->device, &fi, 0, &fences[1]) != D2_VK_SUCCESS) {
        l0->vk.vkDestroyFence(l0->device, fences[0], 0); out->rc = -21; return out->rc;
    }

    HANDLE evt = CreateEventW(0, TRUE, FALSE, 0);
    if (!evt) {
        l0->vk.vkDestroyFence(l0->device, fences[0], 0); l1->vk.vkDestroyFence(l1->device, fences[1], 0);
        out->rc = -22; return out->rc;
    }
    SubmitCtx c[2] = {{l0, &out->lane[0], evt, fences[0]}, {l1, &out->lane[1], evt, fences[1]}};
    HANDLE th[2] = {CreateThread(0,0,submit_thread,&c[0],0,0), CreateThread(0,0,submit_thread,&c[1],0,0)};
    if (!th[0] || !th[1]) {
        if (th[0]) CloseHandle(th[0]); if (th[1]) CloseHandle(th[1]); CloseHandle(evt);
        l0->vk.vkDestroyFence(l0->device, fences[0], 0); l1->vk.vkDestroyFence(l1->device, fences[1], 0);
        out->rc = -23; return out->rc;
    }
    SetEvent(evt);
    WaitForMultipleObjects(2, th, TRUE, INFINITE);
    CloseHandle(th[0]); CloseHandle(th[1]); CloseHandle(evt);

    if (out->lane[0].submit_rc == D2_VK_SUCCESS)
        out->lane[0].wait_rc = l0->vk.vkWaitForFences(l0->device, 1, &fences[0], D2_VK_TRUE, D2_WAIT_FOREVER);
    if (out->lane[1].submit_rc == D2_VK_SUCCESS)
        out->lane[1].wait_rc = l1->vk.vkWaitForFences(l1->device, 1, &fences[1], D2_VK_TRUE, D2_WAIT_FOREVER);

    LARGE_INTEGER fq = {};
    QueryPerformanceFrequency(&fq);
    if (fq.QuadPart <= 0) { out->rc = -24; goto cleanup; }

    if (out->lane[0].wait_rc == D2_VK_SUCCESS) read_and_calibrate(l0, &out->lane[0], (double)fq.QuadPart);
    if (out->lane[1].wait_rc == D2_VK_SUCCESS) read_and_calibrate(l1, &out->lane[1], (double)fq.QuadPart);

    {
        uint64_t rb = 0; uint32_t real = 0;
        const int32_t rr = compact_reduce(reduce_user, proof->token_id, proof->operator_id, &rb, &real);
        if (rr == 0) { out->reduce_bytes = rb; out->compact_reduce_real = real ? 1u : 0u; }
    }

    d2_overlap_evaluate(proof, policy, out);

cleanup:
    l0->vk.vkDestroyFence(l0->device, fences[0], 0);
    l1->vk.vkDestroyFence(l1->device, fences[1], 0);
    return out->rc;
}
#endif
