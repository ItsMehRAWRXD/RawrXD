// K2WeightResolve.cpp — authoritative ResolveWeight (borrow ≠ memcpy)
#include "K2WeightResolve.hpp"
#include "K2LivePathOwnership.hpp"
#include "K2LivePathTensorCache.hpp"
#include "K2ShardIo.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "StreamPathTiming.hpp"
#include "StreamTransferCounters.hpp"
#include <cstring>
#include <fstream>
#include <mutex>

namespace Deep2 {
namespace {
std::mutex g_mu;
uint64_t g_total = 0, g_cache = 0, g_shard = 0;
uint64_t g_keyMiss = 0, g_genMiss = 0, g_wsVeto = 0;
uint64_t g_typeMis = 0, g_rangeMis = 0;
uint64_t g_borrowB = 0, g_shardB = 0, g_shardCalls = 0, g_reopen = 0;
uint64_t g_mapFaultCrit = 0;
uint64_t g_gen = 1;
uint64_t g_vocabTotal = 0, g_vocabCache = 0, g_vocabShard = 0;
uint64_t g_vocabShardB = 0, g_vocabShardCalls = 0;

bool IsAttn(const char* name) { return K2LiveCache_IsMlaAttnName(name); }
bool IsVocab(const char* name) {
    return name && (std::strcmp(name, "output.weight") == 0);
}
} // namespace

void WeightResolve_Reset() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_total = g_cache = g_shard = 0;
    g_keyMiss = g_genMiss = g_wsVeto = 0;
    g_typeMis = g_rangeMis = 0;
    g_borrowB = g_shardB = g_shardCalls = g_reopen = 0;
    g_mapFaultCrit = 0;
    g_vocabTotal = g_vocabCache = g_vocabShard = 0;
    g_vocabShardB = g_vocabShardCalls = 0;
    ++g_gen;
}

uint64_t AttnResolveTotal() { return g_total; }
uint64_t AttnResolveCache() { return g_cache; }
uint64_t AttnResolveShard() { return g_shard; }
uint64_t AttnCacheKeyMiss() { return g_keyMiss; }
uint64_t AttnCacheGenMiss() { return g_genMiss; }
uint64_t AttnCacheWsVeto() { return g_wsVeto; }
uint64_t AttnCacheTypeMismatch() { return g_typeMis; }
uint64_t AttnCacheRangeMismatch() { return g_rangeMis; }
uint64_t AttnBorrowBytes() { return g_borrowB; }
uint64_t AttnShardBytes() { return g_shardB; }
uint64_t AttnShardReadCalls() { return g_shardCalls; }
uint64_t AttnShardReopen() { return g_reopen; }
uint64_t AttnMapFaultCritical() { return g_mapFaultCrit; }
uint64_t VocabResolveTotal() { return g_vocabTotal; }
uint64_t VocabResolveCache() { return g_vocabCache; }
uint64_t VocabResolveShard() { return g_vocabShard; }
uint64_t VocabShardBytes() { return g_vocabShardB; }
uint64_t VocabShardReadCalls() { return g_vocabShardCalls; }

void WeightResolve_Emit(FILE* f) {
    if (!f) f = stdout;
    fprintf(f,
            "ATTN_RESOLVE_TOTAL=%llu ATTN_RESOLVE_CACHE=%llu "
            "ATTN_RESOLVE_SHARD=%llu\n"
            "ATTN_CACHE_KEY_MISS=%llu ATTN_CACHE_GEN_MISS=%llu "
            "ATTN_CACHE_WS_VETO=%llu\n"
            "ATTN_CACHE_TYPE_MISMATCH=%llu ATTN_CACHE_RANGE_MISMATCH=%llu\n"
            "ATTN_BORROW_BYTES=%llu ATTN_SHARD_BYTES=%llu\n"
            "ATTN_SHARD_READ_CALLS=%llu ATTN_SHARD_REOPEN=%llu "
            "ATTN_MAPFAULT_CRITICAL=%llu\n"
            "VOCAB_RESOLVE_TOTAL=%llu VOCAB_RESOLVE_CACHE=%llu "
            "VOCAB_RESOLVE_SHARD=%llu\n"
            "VOCAB_SHARD_BYTES=%llu VOCAB_SHARD_READ_CALLS=%llu\n",
            (unsigned long long)g_total, (unsigned long long)g_cache,
            (unsigned long long)g_shard, (unsigned long long)g_keyMiss,
            (unsigned long long)g_genMiss, (unsigned long long)g_wsVeto,
            (unsigned long long)g_typeMis, (unsigned long long)g_rangeMis,
            (unsigned long long)g_borrowB, (unsigned long long)g_shardB,
            (unsigned long long)g_shardCalls, (unsigned long long)g_reopen,
            (unsigned long long)g_mapFaultCrit,
            (unsigned long long)g_vocabTotal, (unsigned long long)g_vocabCache,
            (unsigned long long)g_vocabShard,
            (unsigned long long)g_vocabShardB,
            (unsigned long long)g_vocabShardCalls);
    fflush(f);
}

bool ResolveWeight(const GlobalTensorIndex& index, const char* name,
                   WeightSpan& out, std::vector<uint8_t>& ownedBuf,
                   std::string& error) {
    out = {};
    ownedBuf.clear();
    if (!name || !name[0]) {
        error = "ResolveWeight: empty name";
        return false;
    }
    const bool attn = IsAttn(name);
    const bool vocab = IsVocab(name);
    const uint8_t* cached = nullptr;
    size_t cachedN = 0;
    // Authority: TryGet first — sticky MLA/output does NOT require MayCache.
    if (K2LiveCache_TryGet(name, cached, cachedN) && cached && cachedN) {
        out.data = cached;
        out.bytes = cachedN;
        out.borrowed = true;
        if (attn || vocab) {
            std::lock_guard<std::mutex> lock(g_mu);
            if (attn) {
                ++g_total;
                ++g_cache;
                g_borrowB += cachedN;
            }
            if (vocab) {
                ++g_vocabTotal;
                ++g_vocabCache;
            }
        }
        StreamTransfer_RecordRead(cachedN, true);
        if (K2LiveCache_IsOutputName(name) ||
            std::strcmp(name, "output_norm.weight") == 0)
            K2LiveCache_NoteTrampOutHit(cachedN);
        else if (K2LiveCache_IsLayerName(name))
            K2LiveCache_NoteLayerHit(cachedN);
        return true;
    }

    // Partition miss reason (TOTAL = CACHE + miss reasons).
    if (attn || vocab) {
        std::lock_guard<std::mutex> lock(g_mu);
        if (attn) {
            ++g_total;
            ++g_keyMiss; // absent from map (dominant until proven otherwise)
        }
        if (vocab) ++g_vocabTotal;
    }

    auto refOpt = index.Find(name);
    if (!refOpt) {
        error = std::string("Tensor not found: ") + name;
        return false;
    }
    const auto& ref = *refOpt;
    const std::string path = index.ShardPath(ref.shardId).string();
    ownedBuf.resize(ref.byteSize);
    const uint64_t tOpen = StreamPathTiming_NowUs();
    bool okRead =
        K2ShardIo_Read(path, ref.fileOffset, ownedBuf.data(), ref.byteSize);
    if (!okRead) {
        std::ifstream f(path, std::ios::binary);
        StreamPathTiming_Add(SPT_shardOpen(), tOpen);
        if (attn) {
            std::lock_guard<std::mutex> lock(g_mu);
            ++g_reopen;
            ++g_mapFaultCrit;
        }
        if (!f) {
            error = "Cannot open shard";
            return false;
        }
        f.seekg(static_cast<std::streamoff>(ref.fileOffset));
        const uint64_t tRd = StreamPathTiming_NowUs();
        f.read(reinterpret_cast<char*>(ownedBuf.data()), ref.byteSize);
        StreamPathTiming_Add(SPT_shardRead(), tRd);
        if (attn) StreamPathTiming_Add(SPT_shardAttn(), tRd);
        else if (name && (std::strstr(name, "ffn_") || std::strstr(name, "expert") ||
                          std::strstr(name, "moe")))
            StreamPathTiming_Add(SPT_shardMoe(), tRd);
        else
            StreamPathTiming_Add(SPT_shardOther(), tRd);
        if (static_cast<size_t>(f.gcount()) != ref.byteSize) {
            error = "Read size mismatch";
            return false;
        }
    } else {
        StreamPathTiming_Add(SPT_shardRead(), tOpen);
        if (attn) StreamPathTiming_Add(SPT_shardAttn(), tOpen);
        else if (name && (std::strstr(name, "ffn_") || std::strstr(name, "expert") ||
                          std::strstr(name, "moe")))
            StreamPathTiming_Add(SPT_shardMoe(), tOpen);
        else
            StreamPathTiming_Add(SPT_shardOther(), tOpen);
    }
    StreamTransfer_RecordRead(ref.byteSize, false);
    if (attn || vocab) {
        std::lock_guard<std::mutex> lock(g_mu);
        if (attn) {
            ++g_shard;
            g_shardB += ref.byteSize;
            ++g_shardCalls;
        }
        if (vocab) {
            ++g_vocabShard;
            g_vocabShardB += ref.byteSize;
            ++g_vocabShardCalls;
        }
    }
    if (ref.ggmlType == 0) {
        const uint64_t tR = StreamPathTiming_NowUs();
        StreamTransfer_RecordReconstruct(ref.byteSize);
        StreamPathTiming_Add(SPT_recon(), tR);
    }

    const bool putOk =
        K2LiveCache_Put(name, ownedBuf.data(), ownedBuf.size());
    if (!putOk && attn && K2LiveCache_IsLayerName(name) &&
        !K2LiveCache_LayerHostFillAllowed()) {
        std::lock_guard<std::mutex> lock(g_mu);
        ++g_wsVeto;
    }
    if (putOk) {
        StreamTransfer_RecordAlloc();
        if (K2LiveCache_IsLayerName(name)) K2LiveCache_NoteLayerAcquire();
        const uint8_t* b = nullptr;
        size_t bn = 0;
        if (K2LiveCache_TryGet(name, b, bn) && b && bn == ownedBuf.size()) {
            out.data = b;
            out.bytes = bn;
            out.borrowed = true;
            ownedBuf.clear();
            if (K2LiveCache_IsOutputName(name))
                K2LiveCache_NoteOutputWeight(bn);
            return true;
        }
        if (attn && b && bn != ownedBuf.size()) {
            std::lock_guard<std::mutex> lock(g_mu);
            ++g_rangeMis;
        }
    }
    out.data = ownedBuf.data();
    out.bytes = ownedBuf.size();
    out.borrowed = false;
    if (K2LiveCache_IsOutputName(name)) {
        K2LiveCache_NoteOutputWeight(ownedBuf.size());
        StreamPathTiming_Add(SPT_outW(), tOpen);
    }
    return true;
}

} // namespace Deep2
