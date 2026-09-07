// K2LivePathTensorCache_Prefetch.cpp — warm NEXT layers; count accept/suppress
#include "K2LivePathTensorCache.hpp"
#include "K2LivePathOwnership.hpp"
#include "Deep2LivePath.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "StreamTransferCounters.hpp"
#include <cstdio>
#include <fstream>
#include <vector>

namespace Deep2 {

static bool DiskLoad(const GlobalTensorIndex& index, const char* name,
                     std::vector<uint8_t>& out) {
    auto refOpt = index.Find(name);
    if (!refOpt) return false;
    const auto& ref = *refOpt;
    std::ifstream f(index.ShardPath(ref.shardId).string(), std::ios::binary);
    if (!f) return false;
    f.seekg(static_cast<std::streamoff>(ref.fileOffset));
    out.resize(ref.byteSize);
    f.read(reinterpret_cast<char*>(out.data()), ref.byteSize);
    if (static_cast<size_t>(f.gcount()) != ref.byteSize) return false;
    StreamTransfer_RecordRead(ref.byteSize, false);
    if (ref.ggmlType == 0) StreamTransfer_RecordReconstruct(ref.byteSize);
    return true;
}

void K2LiveCache_PrefetchLayer(const GlobalTensorIndex& index, uint32_t layer,
                               uint32_t lookahead) {
    if (!K2LiveCache_OwnsLayer()) return;
    // No host prefetch thrash beside pinned trampoline output.
    if (!K2LiveCache_LayerHostFillAllowed()) return;
    uint32_t depth = lookahead + LivePath_PrefetchBoost();
    if (depth == 0) depth = 1;
    uint64_t puts = 0, already = 0;
    for (uint32_t d = 0; d < depth; ++d) {
        const uint32_t L = layer + d;
        char n0[64], n1[64], n2[64], n3[64], n4[64], n5[64], n6[64], n7[64], n8[64];
        snprintf(n0, 64, "blk.%u.attn_q_a.weight", L);
        snprintf(n1, 64, "blk.%u.attn_q_b.weight", L);
        snprintf(n2, 64, "blk.%u.attn_kv_a_mqa.weight", L);
        snprintf(n3, 64, "blk.%u.attn_k_b.weight", L);
        snprintf(n4, 64, "blk.%u.attn_v_b.weight", L);
        snprintf(n5, 64, "blk.%u.attn_output.weight", L);
        snprintf(n6, 64, "blk.%u.attn_norm.weight", L);
        snprintf(n7, 64, "blk.%u.attn_q_a_norm.weight", L);
        snprintf(n8, 64, "blk.%u.attn_kv_a_norm.weight", L);
        if (!index.Find(n3) || !index.Find(n4)) {
            snprintf(n3, 64, "blk.%u.attn_kv_b.weight", L);
            n4[0] = 0;
        }
        const char* names[9] = {n0, n1, n2, n3, n4, n5, n6, n7, n8};
        for (int i = 0; i < 9; ++i) {
            if (!names[i] || !names[i][0]) continue;
            if (K2LiveCache_Has(names[i])) { ++already; continue; }
            std::vector<uint8_t> buf;
            if (!DiskLoad(index, names[i], buf)) continue;
            if (K2LiveCache_Put(names[i], buf.data(), buf.size())) ++puts;
        }
    }
    if (already) K2LiveCache_NotePrefetchAlready(already);
    if (puts) {
        K2LiveCache_NotePrefetchAccepted(puts);
        LivePath_NotePrefetchPromotions((uint32_t)puts);
    }
}

} // namespace Deep2
