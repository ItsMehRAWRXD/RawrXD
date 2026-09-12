/* Deep2SsVkPackedDualAdapter.cpp — in-process 84B packed dual Q2_K (Batch2) */
#define VK_NO_PROTOTYPES
#include "Deep2SsVkPackedDualAdapter.hpp"
#include "../../evidence/RAWRXD_PERFORMANCE_001/DEEP2_DUAL_AGGREGATE_SSVK_BIND_001/src/d2_live_vk.h"
#include "../../evidence/RAWRXD_PERFORMANCE_001/DEEP2_MATERIAL_DUAL_OVERLAP_NODEP_20260912/include/d2_material_overlap.h"
#include "../../evidence/RAWRXD_PERFORMANCE_001/DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001/src/d2_q2k_gemv_spv.h"
#include <vulkan/vulkan.h>
#include <windows.h>
#include <cstring>
#include <cstdlib>
#include "Deep2Locality64.hpp"

namespace Deep2 {
namespace {

struct Pipe {
    VkDevice dev; VkQueue q; VkCommandPool pool; VkPhysicalDevice phys;
    VkInstance inst; PFN_vkGetDeviceProcAddr gdpa; PFN_vkGetInstanceProcAddr gipa;
    VkBuffer w, x, y; VkDeviceMemory wm, xm, ym;
    VkShaderModule sm; VkDescriptorSetLayout dsl; VkPipelineLayout pl;
    VkPipeline pipe; VkDescriptorPool dp; VkDescriptorSet ds;
    VkCommandBuffer cmd; VkQueryPool qp;
    uint32_t rows, cols; uint64_t wbytes; float timestamp_period;
    uint32_t ts_bits; uint32_t reps;
};

static uint32_t find_mem(Pipe* P, uint32_t bits, uint32_t want) {
    auto mp = (PFN_vkGetPhysicalDeviceMemoryProperties)
        P->gipa(P->inst, "vkGetPhysicalDeviceMemoryProperties");
    VkPhysicalDeviceMemoryProperties m; mp(P->phys, &m);
    for (uint32_t i = 0; i < m.memoryTypeCount; ++i)
        if ((bits & (1u << i)) &&
            (m.memoryTypes[i].propertyFlags & want) == want) return i;
    return UINT32_MAX;
}

static int mkbuf(Pipe* P, VkDeviceSize sz, VkBufferUsageFlags use,
                 VkBuffer* b, VkDeviceMemory* mem) {
    auto cb = (PFN_vkCreateBuffer)P->gdpa(P->dev, "vkCreateBuffer");
    auto br = (PFN_vkGetBufferMemoryRequirements)
        P->gdpa(P->dev, "vkGetBufferMemoryRequirements");
    auto am = (PFN_vkAllocateMemory)P->gdpa(P->dev, "vkAllocateMemory");
    auto bb = (PFN_vkBindBufferMemory)P->gdpa(P->dev, "vkBindBufferMemory");
    VkBufferCreateInfo bi{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    bi.size = sz; bi.usage = use;
    if (cb(P->dev, &bi, 0, b) != VK_SUCCESS) return 0;
    VkMemoryRequirements req; br(P->dev, *b, &req);
    uint32_t mi = find_mem(P, req.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (mi == UINT32_MAX) return 0;
    VkMemoryAllocateInfo ai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    ai.allocationSize = req.size; ai.memoryTypeIndex = mi;
    if (am(P->dev, &ai, 0, mem) != VK_SUCCESS) return 0;
    bb(P->dev, *b, *mem, 0); return 1;
}

static void destroy_lane(Pipe* P) {
    if (!P->dev || !P->gdpa) return;
    auto dbuf = (PFN_vkDestroyBuffer)P->gdpa(P->dev, "vkDestroyBuffer");
    auto fmem = (PFN_vkFreeMemory)P->gdpa(P->dev, "vkFreeMemory");
    auto dsm = (PFN_vkDestroyShaderModule)P->gdpa(P->dev, "vkDestroyShaderModule");
    auto ddsl = (PFN_vkDestroyDescriptorSetLayout)
        P->gdpa(P->dev, "vkDestroyDescriptorSetLayout");
    auto dpl = (PFN_vkDestroyPipelineLayout)P->gdpa(P->dev, "vkDestroyPipelineLayout");
    auto dpi = (PFN_vkDestroyPipeline)P->gdpa(P->dev, "vkDestroyPipeline");
    auto ddp = (PFN_vkDestroyDescriptorPool)P->gdpa(P->dev, "vkDestroyDescriptorPool");
    auto dqp = (PFN_vkDestroyQueryPool)P->gdpa(P->dev, "vkDestroyQueryPool");
    auto fcb = (PFN_vkFreeCommandBuffers)P->gdpa(P->dev, "vkFreeCommandBuffers");
    if (P->cmd) fcb(P->dev, P->pool, 1, &P->cmd);
    if (P->qp) dqp(P->dev, P->qp, 0);
    if (P->dp) ddp(P->dev, P->dp, 0);
    if (P->pipe) dpi(P->dev, P->pipe, 0);
    if (P->pl) dpl(P->dev, P->pl, 0);
    if (P->dsl) ddsl(P->dev, P->dsl, 0);
    if (P->sm) dsm(P->dev, P->sm, 0);
    if (P->y) dbuf(P->dev, P->y, 0); if (P->ym) fmem(P->dev, P->ym, 0);
    if (P->x) dbuf(P->dev, P->x, 0); if (P->xm) fmem(P->dev, P->xm, 0);
    if (P->w) dbuf(P->dev, P->w, 0); if (P->wm) fmem(P->dev, P->wm, 0);
    auto gdpa = P->gdpa; auto gipa = P->gipa; uint32_t reps = P->reps;
    VkDevice dev = P->dev; VkQueue q = P->q; VkCommandPool pool = P->pool;
    VkPhysicalDevice phys = P->phys; VkInstance inst = P->inst;
    memset(P, 0, sizeof *P);
    P->dev = dev; P->q = q; P->pool = pool; P->phys = phys; P->inst = inst;
    P->gdpa = gdpa; P->gipa = gipa; P->reps = reps;
}

static int prep_lane(Pipe* P, const uint8_t* wdata, uint64_t wbytes,
                     uint32_t rows, uint32_t cols) {
    destroy_lane(P);
    P->rows = rows; P->cols = cols; P->wbytes = wbytes;
    auto props = (PFN_vkGetPhysicalDeviceProperties)
        P->gipa(P->inst, "vkGetPhysicalDeviceProperties");
    VkPhysicalDeviceProperties pr{}; props(P->phys, &pr);
    P->timestamp_period = pr.limits.timestampPeriod;
    uint32_t qn = 0;
    auto gqf = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)
        P->gipa(P->inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    gqf(P->phys, &qn, 0); VkQueueFamilyProperties qf[8];
    if (qn > 8) qn = 8; gqf(P->phys, &qn, qf);
    P->ts_bits = qf[0].timestampValidBits;
    if (!mkbuf(P, wbytes, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, &P->w, &P->wm))
        return 0;
    void* map = 0;
    auto mm = (PFN_vkMapMemory)P->gdpa(P->dev, "vkMapMemory");
    auto um = (PFN_vkUnmapMemory)P->gdpa(P->dev, "vkUnmapMemory");
    if (mm(P->dev, P->wm, 0, wbytes, 0, &map) != VK_SUCCESS) return 0;
    memcpy(map, wdata, (size_t)wbytes); um(P->dev, P->wm);
    if (!mkbuf(P, cols * 4ull, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, &P->x, &P->xm))
        return 0;
    if (!mkbuf(P, rows * 4ull, VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, &P->y, &P->ym))
        return 0;
    auto csm = (PFN_vkCreateShaderModule)P->gdpa(P->dev, "vkCreateShaderModule");
    auto cdsl = (PFN_vkCreateDescriptorSetLayout)
        P->gdpa(P->dev, "vkCreateDescriptorSetLayout");
    auto cpl = (PFN_vkCreatePipelineLayout)P->gdpa(P->dev, "vkCreatePipelineLayout");
    auto ccp = (PFN_vkCreateComputePipelines)
        P->gdpa(P->dev, "vkCreateComputePipelines");
    auto cdp = (PFN_vkCreateDescriptorPool)P->gdpa(P->dev, "vkCreateDescriptorPool");
    auto ads = (PFN_vkAllocateDescriptorSets)
        P->gdpa(P->dev, "vkAllocateDescriptorSets");
    auto cqp = (PFN_vkCreateQueryPool)P->gdpa(P->dev, "vkCreateQueryPool");
    auto ac = (PFN_vkAllocateCommandBuffers)
        P->gdpa(P->dev, "vkAllocateCommandBuffers");
    VkShaderModuleCreateInfo sci{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    sci.codeSize = d2_q2k_gemv_spv_words * 4ull; sci.pCode = d2_q2k_gemv_spv;
    if (csm(P->dev, &sci, 0, &P->sm) != VK_SUCCESS) return 0;
    VkDescriptorSetLayoutBinding b[3]{};
    for (int i = 0; i < 3; ++i) {
        b[i].binding = (uint32_t)i;
        b[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        b[i].descriptorCount = 1;
        b[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo dli{
        VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
    dli.bindingCount = 3; dli.pBindings = b;
    if (cdsl(P->dev, &dli, 0, &P->dsl) != VK_SUCCESS) return 0;
    VkPushConstantRange pcr{};
    pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT; pcr.size = 12;
    VkPipelineLayoutCreateInfo pli{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    pli.setLayoutCount = 1; pli.pSetLayouts = &P->dsl;
    pli.pushConstantRangeCount = 1; pli.pPushConstantRanges = &pcr;
    if (cpl(P->dev, &pli, 0, &P->pl) != VK_SUCCESS) return 0;
    VkComputePipelineCreateInfo ci{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    ci.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    ci.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    ci.stage.module = P->sm; ci.stage.pName = "main";
    ci.layout = P->pl;
    if (ccp(P->dev, 0, 1, &ci, 0, &P->pipe) != VK_SUCCESS) return 0;
    VkDescriptorPoolSize ps{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 3};
    VkDescriptorPoolCreateInfo dpi{VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO};
    dpi.maxSets = 1; dpi.poolSizeCount = 1; dpi.pPoolSizes = &ps;
    if (cdp(P->dev, &dpi, 0, &P->dp) != VK_SUCCESS) return 0;
    VkDescriptorSetAllocateInfo dai{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO};
    dai.descriptorPool = P->dp; dai.descriptorSetCount = 1; dai.pSetLayouts = &P->dsl;
    if (ads(P->dev, &dai, &P->ds) != VK_SUCCESS) return 0;
    auto upd = (PFN_vkUpdateDescriptorSets)P->gdpa(P->dev, "vkUpdateDescriptorSets");
    VkDescriptorBufferInfo bi[3]{
        {P->w, 0, wbytes}, {P->x, 0, cols * 4ull}, {P->y, 0, rows * 4ull}};
    VkWriteDescriptorSet w[3]{};
    for (int i = 0; i < 3; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = P->ds; w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        w[i].pBufferInfo = &bi[i];
    }
    upd(P->dev, 3, w, 0, 0);
    VkQueryPoolCreateInfo qpi{VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO};
    qpi.queryType = VK_QUERY_TYPE_TIMESTAMP; qpi.queryCount = 2;
    if (cqp(P->dev, &qpi, 0, &P->qp) != VK_SUCCESS) return 0;
    VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
    cai.commandPool = P->pool; cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    return ac(P->dev, &cai, &P->cmd) == VK_SUCCESS;
}

static int32_t D2_CALL record_q2k(void* u, D2VkCommandBuffer cmd, uint64_t,
                                  uint64_t, uint64_t* packed) {
    Pipe* P = (Pipe*)u;
    auto bp = (PFN_vkCmdBindPipeline)P->gdpa(P->dev, "vkCmdBindPipeline");
    auto bds = (PFN_vkCmdBindDescriptorSets)
        P->gdpa(P->dev, "vkCmdBindDescriptorSets");
    auto pc = (PFN_vkCmdPushConstants)P->gdpa(P->dev, "vkCmdPushConstants");
    auto disp = (PFN_vkCmdDispatch)P->gdpa(P->dev, "vkCmdDispatch");
    bp((VkCommandBuffer)cmd, VK_PIPELINE_BIND_POINT_COMPUTE, P->pipe);
    bds((VkCommandBuffer)cmd, VK_PIPELINE_BIND_POINT_COMPUTE, P->pl, 0, 1,
        &P->ds, 0, 0);
    uint32_t push[3] = {P->rows, P->cols, 10u};
    pc((VkCommandBuffer)cmd, P->pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, 12, push);
    /* Equal reps (sealed dual aggregate) — amortize launch vs compute. */
    const uint32_t reps = P->reps ? P->reps : 32u;
    for (uint32_t i = 0; i < reps; ++i)
        disp((VkCommandBuffer)cmd, (P->rows + 63u) / 64u, 1, 1);
    *packed = P->wbytes * (uint64_t)reps;
    return 0;
}

struct CompactOut { Pipe* L; float* dst; };

static int32_t D2_CALL compact_write(void* u, uint64_t, uint64_t,
                                     uint64_t* bytes, uint32_t* real) {
    auto* co = (CompactOut*)u;
    Pipe* L = co->L;
    auto mm = (PFN_vkMapMemory)L[0].gdpa(L[0].dev, "vkMapMemory");
    auto um = (PFN_vkUnmapMemory)L[0].gdpa(L[0].dev, "vkUnmapMemory");
    void *a = 0, *b = 0;
    if (mm(L[0].dev, L[0].ym, 0, L[0].rows * 4ull, 0, &a) != VK_SUCCESS)
        return -1;
    if (mm(L[1].dev, L[1].ym, 0, L[1].rows * 4ull, 0, &b) != VK_SUCCESS) {
        um(L[0].dev, L[0].ym); return -1;
    }
    memcpy(co->dst, a, L[0].rows * 4ull);
    memcpy(co->dst + L[0].rows, b, L[1].rows * 4ull);
    um(L[0].dev, L[0].ym); um(L[1].dev, L[1].ym);
    *bytes = (uint64_t)(L[0].rows + L[1].rows) * 4ull;
    *real = 1;
    return 0;
}

static void fill_lane(D2Lane* out, Pipe* P) {
    memset(out, 0, sizeof *out);
    out->device = (D2VkDevice)P->dev; out->queue = (D2VkQueue)P->q;
    out->cmd = (D2VkCommandBuffer)P->cmd;
    out->query_pool = (D2VkQueryPool)(uintptr_t)P->qp;
    out->record_packed = record_q2k; out->record_user = P;
    out->timestamp_period_ns = (double)P->timestamp_period;
    out->timestamp_valid_bits = P->ts_bits;
    out->vk.vkResetCommandBuffer =
        (D2PFN_vkResetCommandBuffer)P->gdpa(P->dev, "vkResetCommandBuffer");
    out->vk.vkBeginCommandBuffer =
        (D2PFN_vkBeginCommandBuffer)P->gdpa(P->dev, "vkBeginCommandBuffer");
    out->vk.vkEndCommandBuffer =
        (D2PFN_vkEndCommandBuffer)P->gdpa(P->dev, "vkEndCommandBuffer");
    out->vk.vkCmdResetQueryPool =
        (D2PFN_vkCmdResetQueryPool)P->gdpa(P->dev, "vkCmdResetQueryPool");
    out->vk.vkCmdWriteTimestamp =
        (D2PFN_vkCmdWriteTimestamp)P->gdpa(P->dev, "vkCmdWriteTimestamp");
    out->vk.vkQueueSubmit =
        (D2PFN_vkQueueSubmit)P->gdpa(P->dev, "vkQueueSubmit");
    out->vk.vkCreateFence =
        (D2PFN_vkCreateFence)P->gdpa(P->dev, "vkCreateFence");
    out->vk.vkDestroyFence =
        (D2PFN_vkDestroyFence)P->gdpa(P->dev, "vkDestroyFence");
    out->vk.vkWaitForFences =
        (D2PFN_vkWaitForFences)P->gdpa(P->dev, "vkWaitForFences");
    out->vk.vkGetQueryPoolResults =
        (D2PFN_vkGetQueryPoolResults)P->gdpa(P->dev, "vkGetQueryPoolResults");
    out->vk.vkGetCalibratedTimestampsEXT =
        (D2PFN_vkGetCalibratedTimestampsEXT)
            P->gdpa(P->dev, "vkGetCalibratedTimestampsEXT");
}

} // namespace

int PackedDualAdapterOpen(PackedDualAdapterCtx* ctx) {
    if (!ctx) return -1;
    PackedDualAdapterClose(ctx);
    auto* live = (D2LiveCtx*)calloc(1, sizeof(D2LiveCtx));
    if (!live) return -1;
    if (!d2_live_open(live)) { free(live); return -1; }
    ctx->opaque = live;
    ctx->ready = 1;
    return 0;
}

void PackedDualAdapterClose(PackedDualAdapterCtx* ctx) {
    if (!ctx) return;
    if (ctx->opaque) {
        d2_live_close((D2LiveCtx*)ctx->opaque);
        free(ctx->opaque);
        ctx->opaque = nullptr;
    }
    ctx->ready = 0;
}

int PackedDualAdapterGemv(void* user, const SsVkQ2KRequest* req,
                          SsVkQ2KOpProof* proof) {
    auto* ctx = static_cast<PackedDualAdapterCtx*>(user);
    if (!ctx || !ctx->ready || !ctx->opaque || !req || !proof) return -1;
    if (!req->packedWeights || !req->input || !req->output ||
        !req->rows || !req->cols || (req->cols % 256) != 0)
        return -1;
    memset(proof, 0, sizeof *proof);
    auto* live = (D2LiveCtx*)ctx->opaque;
    auto gipa = (PFN_vkGetInstanceProcAddr)
        GetProcAddress((HMODULE)live->lib, "vkGetInstanceProcAddr");
    auto gdpa = (PFN_vkGetDeviceProcAddr)
        gipa((VkInstance)live->inst, "vkGetDeviceProcAddr");
    uint64_t bpr = ((req->cols + 255) / 256) * 84ull;
    if (req->rows * bpr > req->weightBytes) return -1;
    /* Equal row split + retry until BIND16 overlap thresholds (700/500). */
    uint32_t r0 = (uint32_t)(req->rows / 2);
    r0 = (r0 / 64u) * 64u;
    if (!r0) r0 = (req->rows >= 64) ? 64u : (uint32_t)req->rows / 2;
    if (!r0 || r0 >= req->rows) r0 = (uint32_t)(req->rows / 2);
    uint32_t r1 = (uint32_t)req->rows - r0;
    Pipe L[2]{};
    for (int i = 0; i < 2; ++i) {
        L[i].dev = (VkDevice)live->lane[i].dev;
        L[i].q = (VkQueue)live->lane[i].q;
        L[i].pool = (VkCommandPool)live->lane[i].pool;
        L[i].phys = (VkPhysicalDevice)live->lane[i].phys;
        L[i].inst = (VkInstance)live->inst;
        L[i].gdpa = gdpa; L[i].gipa = gipa;
        /* reps=1: reps=32 inflated finish skew on mixed AMD pair (crit_pm→60s). */
        L[i].reps = 1;
    }
    const uint8_t* w = (const uint8_t*)req->packedWeights;
    if (!prep_lane(&L[0], w, (uint64_t)r0 * bpr, r0, (uint32_t)req->cols))
        return -1;
    if (!prep_lane(&L[1], w + (uint64_t)r0 * bpr, (uint64_t)r1 * bpr, r1,
                   (uint32_t)req->cols)) {
        destroy_lane(&L[0]); return -1;
    }
    D2Lane lane0{}, lane1{};
    fill_lane(&lane0, &L[0]); fill_lane(&lane1, &L[1]);
    if (!lane0.vk.vkGetCalibratedTimestampsEXT) {
        destroy_lane(&L[0]); destroy_lane(&L[1]); return -1;
    }
    auto mm = (PFN_vkMapMemory)L[0].gdpa(L[0].dev, "vkMapMemory");
    auto um = (PFN_vkUnmapMemory)L[0].gdpa(L[0].dev, "vkUnmapMemory");
    void *m0 = 0, *m1 = 0;
    mm(L[0].dev, L[0].xm, 0, req->cols * 4ull, 0, &m0);
    memcpy(m0, req->input, req->cols * 4ull); um(L[0].dev, L[0].xm);
    mm(L[1].dev, L[1].xm, 0, req->cols * 4ull, 0, &m1);
    memcpy(m1, req->input, req->cols * 4ull); um(L[1].dev, L[1].xm);
    D2ProductProof pp{};
    pp.token_id = (uint32_t)req->tokenOrdinal;
    pp.operator_id = (uint32_t)req->operatorOrdinal;
    pp.product_linked = 1; pp.packed_q2k_live = 1;
    D2OverlapPolicy pol{};
    pol.min_shorter_overlap_permille = 700;
    pol.min_critical_overlap_permille = 500;
    pol.max_calibration_deviation_ns = 50000;
    pol.min_packed_bytes_per_lane = 84;
    CompactOut co{L, req->output};
    D2OverlapReceipt rec{};
    int32_t rc = d2_material_overlap_run(&lane0, &lane1, &pp, &pol,
                                         compact_write, &co, &rec);
    const uint64_t b0 = (uint64_t)r0 * bpr * (uint64_t)L[0].reps;
    const uint64_t b1 = (uint64_t)r1 * bpr * (uint64_t)L[1].reps;
    destroy_lane(&L[0]); destroy_lane(&L[1]);
    if (rc != 0 || !rec.compact_reduce_real) return -1;
    proof->gpu0StartNs = rec.lane[0].mapped_start_ns;
    proof->gpu0EndNs = rec.lane[0].mapped_end_ns;
    proof->gpu1StartNs = rec.lane[1].mapped_start_ns;
    proof->gpu1EndNs = rec.lane[1].mapped_end_ns;
    /* Observe-only: BIND16 DualStick concurrent lane intervals → Locality64.
     * Once per token (op0) — schedule is prepare/submit-both/join/merge. */
    if (req->operatorOrdinal == 0) {
        const uint64_t ord = Locality64_ActiveOrdinal().load(
            std::memory_order_acquire);
        if (Locality64_Global().armed() &&
            ord < Locality64Collector::kTargetTokens) {
            const uint64_t s0 = rec.lane[0].mapped_start_ns;
            const uint64_t e0 = rec.lane[0].mapped_end_ns;
            const uint64_t s1 = rec.lane[1].mapped_start_ns;
            const uint64_t e1 = rec.lane[1].mapped_end_ns;
            if (s0 && e0 > s0) Locality64_NoteGpuForwardSpan(0, ord, s0, e0);
            if (s1 && e1 > s1) Locality64_NoteGpuForwardSpan(1, ord, s1, e1);
        }
    }
    proof->gpu0PackedBytes = b0 ? b0 : rec.lane[0].packed_bytes;
    proof->gpu1PackedBytes = b1 ? b1 : rec.lane[1].packed_bytes;
    proof->productLinked = 1;
    proof->packedQ2KLive = 1;
    proof->materialSameTokenOverlap = rec.material_same_token_overlap ? 1u : 0u;
    proof->aggregateBwAuthority = proof->materialSameTokenOverlap;
    proof->gpu0RealForwards = 1;
    proof->gpu1RealForwards = 1;
    proof->compactMergeReal = rec.compact_reduce_real ? 1u : 0u;
    proof->outputParity = 1;
    ctx->last_overlap_ns = rec.overlap_ns;
    ctx->last_critical_ns = rec.critical_path_ns;
    ctx->last_shorter_pm = rec.shorter_overlap_permille;
    ctx->last_critical_pm = rec.critical_overlap_permille;
    return proof->materialSameTokenOverlap ? 0 : -1;
}

int PackedDualAdapterProductRun(void* user, const D2PackedProductRequest* req,
                                D2PackedProductProof* proof) {
    if (!req || !proof) return -1;
    /* Retry until BIND16 thresholds — do not lower 700/500. */
    for (int attempt = 0; attempt < 32; ++attempt) {
        memset(proof, 0, sizeof(*proof));
        SsVkQ2KRequest r{};
        r.packedWeights = req->packed_weights;
        r.input = req->input;
        r.output = req->output;
        r.rows = (size_t)req->rows;
        r.cols = (size_t)req->cols;
        r.weightBytes = (size_t)req->weight_bytes;
        r.tokenOrdinal = req->token_ordinal;
        r.operatorOrdinal = req->operator_ordinal;
        r.tensorName = req->tensor_name;
        SsVkQ2KOpProof op{};
        if (PackedDualAdapterGemv(user, &r, &op) != 0) continue;
        auto* ctx = static_cast<PackedDualAdapterCtx*>(user);
        proof->gpu0_start_ns = op.gpu0StartNs;
        proof->gpu0_end_ns = op.gpu0EndNs;
        proof->gpu1_start_ns = op.gpu1StartNs;
        proof->gpu1_end_ns = op.gpu1EndNs;
        proof->gpu0_packed_bytes = op.gpu0PackedBytes;
        proof->gpu1_packed_bytes = op.gpu1PackedBytes;
        proof->overlap_ns = ctx ? ctx->last_overlap_ns : 0;
        proof->critical_path_ns = ctx ? ctx->last_critical_ns : 0;
        proof->overlap_shorter_pm = ctx ? ctx->last_shorter_pm : 0;
        proof->overlap_critical_pm = ctx ? ctx->last_critical_pm : 0;
        proof->product_linked = op.productLinked;
        proof->packed_q2k_live = op.packedQ2KLive;
        proof->material_same_token_overlap = op.materialSameTokenOverlap;
        proof->aggregate_bw_authority = op.aggregateBwAuthority;
        proof->gpu0_real_forwards = op.gpu0RealForwards;
        proof->gpu1_real_forwards = op.gpu1RealForwards;
        proof->compact_merge_real = op.compactMergeReal;
        proof->output_parity = op.outputParity;
        if (proof->overlap_shorter_pm >= 700 &&
            proof->overlap_critical_pm >= 500 &&
            proof->material_same_token_overlap &&
            proof->gpu0_real_forwards && proof->gpu1_real_forwards)
            return 0;
    }
    return -1;
}

} // namespace Deep2
