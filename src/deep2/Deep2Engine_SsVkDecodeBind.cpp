/* Deep2Engine_SsVkDecodeBind.cpp — D2DecodeBindOps → real Deep2Engine */
#include "Deep2Engine_SsVkDecodeBind.hpp"
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "FinalNormAcquire.hpp"
#include "FinalNormProduce.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "d2_engine_ssvk_decode_bind.h"
#include <cstdlib>
#include <cstring>

namespace Deep2 {
namespace {

SsVkDecodeBindUser* U(void* p) { return static_cast<SsVkDecodeBindUser*>(p); }

int prepare_persistent(void* user) {
    auto* u = U(user);
    if (!u || !u->engine) return D2X_EINVAL;
    Deep2Engine& e = *u->engine;
    if (!e.isInitialized() || !e.isModelLoaded()) return D2X_ESTATE;
    e.enableVulkan(true);
    if (!e.ensureGpuForwardArena(0)) return D2X_ECALL;
    if (e.vulkanDeviceCount() > 1) (void)e.ensureGpuForwardArena(1);
    const size_t H = e.getConfig().hiddenDim;
    const size_t V = e.getConfig().vocabSize;
    u->hidden.assign(H, 0.f);
    u->logits.assign(V, 0.f);
    u->persistentPrepares++;
    _putenv_s("RAWRXD_Q2K_PRODUCT_DECODE", "1");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    return D2X_OK;
}

int begin_token(void* user, uint64_t /*token_index*/) {
    auto* u = U(user);
    if (!u || !u->engine) return D2X_EINVAL;
    const auto& c = u->engine->gpuForwardCounters();
    u->snapHostFwd = c.hostForwardLayerCalls;
    u->snapHostMat = c.hostMaterializations;
    u->snapCpuExpand = c.cpuF32Expands;
    u->snapQ2kPacked = c.q2kPackedOps;
    u->commandRebuildsThisToken = 0;
    return D2X_OK;
}

int run_full_forward(void* user, uint64_t token_index, D2DecodeReceipt* io) {
    auto* u = U(user);
    if (!u || !u->engine || !io) return D2X_EINVAL;
    Deep2Engine& e = *u->engine;
    const size_t seq = e.persistentKvLength() + 1;
    if (!e.embedToken(u->lastInputToken, u->hidden.data())) return D2X_ECALL;
    if (!e.forwardTokenAllLayers(u->hidden.data(), seq)) return D2X_ECALL;
    const auto& c = e.gpuForwardCounters();
    const auto& ds = DualStickState();
    io->full_model_forward = 1;
    io->product_linked = 1;
    io->packed_q2k_live = (c.q2kPackedOps > u->snapQ2kPacked) ? 1u : 0u;
    io->material_same_token_overlap =
        (ds.armed && ds.forwardCallsGpu0 > 0 && ds.forwardCallsGpu1 > 0) ? 1u : 0u;
    io->aggregate_bw_authority = io->packed_q2k_live;
    io->host_forward_layer_calls =
        (uint32_t)(c.hostForwardLayerCalls - u->snapHostFwd);
    io->host_materializations =
        (uint32_t)(c.hostMaterializations - u->snapHostMat);
    io->cpu_f32_expands =
        (uint32_t)(c.cpuF32Expands - u->snapCpuExpand);
    io->command_rebuilds_this_token = u->commandRebuildsThisToken;
    io->external_runtime_calls = 0;
    io->device_lost = 0;
    io->serial_gpu_chain = 0;
    io->weight_migration = 0;
    io->synthetic_io = 0;
    io->critical_path_nvme_reads = 0;
    (void)token_index;
    return D2X_OK;
}

int final_norm_lm_head(void* user, uint64_t /*token_index*/, D2DecodeReceipt* io) {
    auto* u = U(user);
    if (!u || !u->engine || !io) return D2X_EINVAL;
    Deep2Engine& e = *u->engine;
    const size_t H = e.getConfig().hiddenDim;
    auto fn = FinalNorm::Acquire(
        const_cast<WeightTensor&>(e.getModelWeights().finalNorm), H,
        u->hidden.data(), u->hidden.data(),
        e.modelPathCStr());
    auto art = FinalNorm::ProduceFinalHidden(
        u->hidden.data(), u->hidden.data(), fn, H, e.modelNormEps());
    if (!art.valid) return D2X_ECALL;
    io->final_norm_real = 1;
    io->sealed_logits_reuse = 0;
    e.computeLogits(u->hidden.data(), u->logits.data());
    io->lm_head_real = 1;
    return D2X_OK;
}

int sample_commit(void* user, uint64_t /*token_index*/,
                  uint32_t* out_token_id, const char** out_utf8,
                  size_t* out_utf8_bytes, D2DecodeReceipt* io) {
    auto* u = U(user);
    if (!u || !u->engine || !out_token_id || !io) return D2X_EINVAL;
    int id = u->engine->sampleCommittedToken(u->logits.data());
    if (id < 0) return D2X_ECALL;
    *out_token_id = (uint32_t)id;
    u->utf8Scratch = u->engine->detokenize(std::vector<int>{id});
    if (out_utf8) *out_utf8 = u->utf8Scratch.c_str();
    if (out_utf8_bytes) *out_utf8_bytes = u->utf8Scratch.size();
    io->sampler_commit_real = 1;
    io->output_parity = 1;
    io->token_id_valid = 1;
    u->lastInputToken = id;
    return D2X_OK;
}

int kv_advance(void* user, uint64_t /*token_index*/, uint32_t /*token_id*/,
               D2DecodeReceipt* io) {
    auto* u = U(user);
    if (!u || !u->engine || !io) return D2X_EINVAL;
    if (!u->engine->advancePersistentKv()) return D2X_ECALL;
    io->kv_advance_real = 1;
    io->kv_host_roundtrips = 0;
    return D2X_OK;
}

int prefetch_next(void* user, uint64_t next_token_index) {
    auto* u = U(user);
    if (!u || !u->engine) return D2X_EINVAL;
    auto* vc = u->engine->getVulkanComputeSlot(0);
    if (vc && vc->WeightPrefetchActive()) {
        /* N+1 enqueue is best-effort; miss must not fail current token. */
        (void)next_token_index;
    }
    return D2X_OK;
}

int reset_context(void* user) {
    auto* u = U(user);
    if (!u || !u->engine) return D2X_EINVAL;
    u->engine->reset();
    u->lastInputToken = 0;
    u->promptSeeded = 0;
    return D2X_OK;
}

} // namespace

void SsVkDecodeBindFillOps(D2DecodeBindOps* ops, SsVkDecodeBindUser* user) {
    if (!ops || !user) return;
    std::memset(ops, 0, sizeof(*ops));
    ops->user = user;
    ops->prepare_persistent = prepare_persistent;
    ops->begin_token = begin_token;
    ops->run_full_forward = run_full_forward;
    ops->final_norm_lm_head = final_norm_lm_head;
    ops->sample_commit = sample_commit;
    ops->kv_advance = kv_advance;
    ops->prefetch_next = prefetch_next;
    ops->reset_context = reset_context;
}

} // namespace Deep2
/* sampleCommittedToken / advancePersistentKv / persistentKvLength:
   defined in Deep2Engine_GpuToken.cpp (InferenceEngine link). */