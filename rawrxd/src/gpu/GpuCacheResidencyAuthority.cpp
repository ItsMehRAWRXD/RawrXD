// GpuCacheResidencyAuthority.cpp — RAWRXD_GPU_CACHE_RESIDENCY_AUTHORITY_001
#include "GpuCacheResidencyAuthority.h"
#include "../deep2/ReceiptAuthority.h"
#include <atomic>
namespace rawrxd { namespace gpu {
static std::atomic<uint64_t> g_uploadBytes{0}, g_perTokenUpload{0};
static std::atomic<int> g_cacheHits{0}, g_cacheMisses{0}, g_evictions{0};
static std::atomic<bool> g_lmHeadPinned{false}, g_tokenEmbedPinned{false};
void recordUpload(uint64_t bytes) { g_uploadBytes.fetch_add(bytes); g_perTokenUpload.fetch_add(bytes); }
void recordCacheHit() { g_cacheHits.fetch_add(1); }
void recordCacheMiss() { g_cacheMisses.fetch_add(1); }
void recordEviction() { g_evictions.fetch_add(1); }
void recordPinned(const std::string& tensor, bool pinned) {
    if (tensor == "lm_head") g_lmHeadPinned.store(pinned);
    if (tensor == "token_embd") g_tokenEmbedPinned.store(pinned);
}
void writeResidencyReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_GPU_CACHE_RESIDENCY_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "GPU_UPLOAD_BYTES_PER_TOKEN", (int64_t)g_perTokenUpload.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_UPLOAD_COUNT_PER_TOKEN", 0); // TODO: per-token counter
    rawrxd::receipt::writeKeyValueInt(path, "GPU_CACHE_HITS", g_cacheHits.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_CACHE_MISSES", g_cacheMisses.load());
    rawrxd::receipt::writeKeyValueInt(path, "GPU_EVICTIONS", g_evictions.load());
    rawrxd::receipt::writeKeyValueInt(path, "LM_HEAD_PINNED", g_lmHeadPinned.load() ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "TOKEN_EMBED_PINNED", g_tokenEmbedPinned.load() ? 1 : 0);
    rawrxd::receipt::endGate(path, g_evictions.load() == 0 ? "PASS" : "FAIL");
}
}} // namespace rawrxd::gpu