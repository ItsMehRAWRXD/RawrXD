from pathlib import Path

# --- K2GlobalTensorIndex.cpp role classify ---
k2 = Path(r"G:\~dev\rawrxd\src\deep2\K2GlobalTensorIndex.cpp")
text = k2.read_text(encoding="utf-8")
old = '''GlobalTensorRef::TensorRole GlobalTensorIndex::ClassifyTensorRole(const std::string& name) {
    if (name.find("token_embd") != std::string::npos) return GlobalTensorRef::TensorRole::Embedding;
    if (name.find("output.weight") != std::string::npos) return GlobalTensorRef::TensorRole::Output;
    if (name.find("output_norm") != std::string::npos) return GlobalTensorRef::TensorRole::Output;
    if (name.find("attn_q_a") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_q_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_kv_a") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_v_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_k_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_output") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionO;
    if (name.find("attn_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_q_a_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_kv_a_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
'''
new = '''GlobalTensorRef::TensorRole GlobalTensorIndex::ClassifyTensorRole(const std::string& name) {
    if (name.find("token_embd") != std::string::npos) return GlobalTensorRef::TensorRole::Embedding;
    if (name.find("output.weight") != std::string::npos) return GlobalTensorRef::TensorRole::Output;
    if (name.find("output_norm") != std::string::npos) return GlobalTensorRef::TensorRole::Output;
    /* Norms before stem matches (attn_q_norm contains attn_q). */
    if (name.find("attn_q_a_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_kv_a_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_q_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_k_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
    if (name.find("attn_q_a") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_q_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_q.weight") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionQ;
    if (name.find("attn_kv_a") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_v_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_k_b") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_k.weight") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_v.weight") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionKV;
    if (name.find("attn_output") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionO;
    if (name.find("attn_norm") != std::string::npos) return GlobalTensorRef::TensorRole::AttentionNorm;
'''
if old not in text:
    raise SystemExit('K2 old block not found')
k2.write_text(text.replace(old, new), encoding='utf-8')
print('K2 OK')

root = Path(r"G:\~dev\rawrxd\src\deep2\MultiShardRootMaterialize.hpp")
root.write_text(r'''#pragma once
/* B02: fread root/layer tensor bytes from owning shard. <=99. */
#include "Deep2Engine.h"
#include "K2GlobalTensorIndex.hpp"
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace multishard_bind {

inline int Materialize(WeightTensor& wt, const GlobalTensorIndex& idx,
                       int quiet = 0) {
    if (!wt.hasFileBacking || wt.sizeBytes == 0 || wt.name.empty()) return 0;
    if (wt.data) return 1;
    const auto& path = idx.ShardPath(wt.shardId);
    FILE* f = nullptr;
    if (fopen_s(&f, path.string().c_str(), "rb") != 0 || !f) {
        std::fprintf(stderr,
                     "B03_MAT_FAIL name=%s shard=%u why=OPEN path=%s\n",
                     wt.name.c_str(), wt.shardId, path.string().c_str());
        return 0;
    }
    if (_fseeki64(f, (long long)wt.fileOffset, SEEK_SET) != 0) {
        std::fprintf(stderr, "B03_MAT_FAIL name=%s shard=%u why=SEEK off=%llu\n",
                     wt.name.c_str(), wt.shardId,
                     (unsigned long long)wt.fileOffset);
        fclose(f);
        return 0;
    }
#ifdef _WIN32
    void* p = VirtualAlloc(nullptr, wt.sizeBytes, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
#else
    void* p = nullptr;
#endif
    if (!p) {
        fclose(f);
        std::fprintf(stderr, "B03_MAT_FAIL name=%s shard=%u why=ALLOC bytes=%zu\n",
                     wt.name.c_str(), wt.shardId, wt.sizeBytes);
        return 0;
    }
    const size_t got = fread(p, 1, wt.sizeBytes, f);
    fclose(f);
    if (got != wt.sizeBytes) {
#ifdef _WIN32
        VirtualFree(p, 0, MEM_RELEASE);
#endif
        std::fprintf(stderr,
                     "B03_MAT_FAIL name=%s shard=%u why=READ got=%zu need=%zu\n",
                     wt.name.c_str(), wt.shardId, got, wt.sizeBytes);
        return 0;
    }
    wt.data = p;
    wt.mapped = true;
    if (!quiet) {
        const unsigned char* b = static_cast<const unsigned char*>(p);
        std::fprintf(stderr,
                     "B02_ROOT_MATERIALIZE=1 name=%s shard=%u off=%llu bytes=%zu "
                     "rows=%zu cols=%zu type=%d head4=%02x%02x%02x%02x\n",
                     wt.name.c_str(), wt.shardId,
                     (unsigned long long)wt.fileOffset, wt.sizeBytes, wt.rows,
                     wt.cols, wt.type, b[0], b[1], b[2], b[3]);
    }
    return 1;
}

} // namespace multishard_bind
} // namespace Deep2
''', encoding='utf-8')
print('Root OK')

Path(r"G:\~dev\rawrxd\src\deep2\MultiShardLayerMaterialize.hpp").write_text(r'''#pragma once
/* B03: materialize non-expert layer slots for HOST_DECODE MiniMax. <=99. */
#include "MultiShardRootMaterialize.hpp"

namespace Deep2 {
namespace multishard_bind {

inline int MaterializeOne(WeightTensor& wt, const GlobalTensorIndex& idx,
                          size_t layer, const char* slot, int& fail) {
    if (wt.name.empty() && !wt.hasFileBacking) return 0;
    if (!wt.hasFileBacking || wt.sizeBytes == 0) {
        std::fprintf(stderr,
                     "B03_MAT_SKIP layer=%zu slot=%s name=%s why=NO_DESC\n",
                     layer, slot, wt.name.empty() ? "(empty)" : wt.name.c_str());
        return 0;
    }
    if (wt.data) return 1;
    const int ok = Materialize(wt, idx, /*quiet=*/1);
    if (!ok) {
        fail = 1;
        std::fprintf(stderr,
                     "B03_MAT_FAIL layer=%zu slot=%s name=%s shard=%u "
                     "rows=%zu cols=%zu bytes=%zu why=BACKING_UNRESOLVED\n",
                     layer, slot, wt.name.c_str(), wt.shardId, wt.rows, wt.cols,
                     wt.sizeBytes);
        return 0;
    }
    return 1;
}

inline int MaterializeLayerAttn(LayerWeights& lw, const GlobalTensorIndex& idx,
                                size_t layer) {
    int n = 0, fail = 0;
    n += MaterializeOne(lw.attnNorm, idx, layer, "attn_norm", fail);
    n += MaterializeOne(lw.wq, idx, layer, "wq", fail);
    n += MaterializeOne(lw.wk, idx, layer, "wk", fail);
    n += MaterializeOne(lw.wv, idx, layer, "wv", fail);
    n += MaterializeOne(lw.wo, idx, layer, "wo", fail);
    n += MaterializeOne(lw.wqkv, idx, layer, "wqkv", fail);
    n += MaterializeOne(lw.attnQNorm, idx, layer, "attn_q_norm", fail);
    n += MaterializeOne(lw.attnKNorm, idx, layer, "attn_k_norm", fail);
    n += MaterializeOne(lw.ffnNorm, idx, layer, "ffn_norm", fail);
    n += MaterializeOne(lw.moeRouter, idx, layer, "moe_router", fail);
    n += MaterializeOne(lw.wGate, idx, layer, "wGate", fail);
    n += MaterializeOne(lw.moeSharedGate, idx, layer, "shared_gate", fail);
    n += MaterializeOne(lw.moeSharedUp, idx, layer, "shared_up", fail);
    n += MaterializeOne(lw.moeSharedDown, idx, layer, "shared_down", fail);
    if (fail) return -n;
    return n;
}

inline int MaterializeAllLayers(ModelWeights& mw, const GlobalTensorIndex& idx) {
    int total = 0, bad = 0;
    for (size_t i = 0; i < mw.layers.size(); ++i) {
        const int n = MaterializeLayerAttn(mw.layers[i], idx, i);
        if (n < 0) { bad = 1; total += -n; }
        else total += n;
    }
    std::fprintf(stderr, "B03_LAYER_MATERIALIZE slots=%d layers=%zu fail=%d\n",
                 total, mw.layers.size(), bad);
    return bad ? -total : total;
}

} // namespace multishard_bind
} // namespace Deep2
''', encoding='utf-8')
print('LayerMat OK')

Path(r"G:\~dev\rawrxd\src\deep2\MultiShardLayerValidate.hpp").write_text(r'''#pragma once
/* B03: fail-closed MiniMax layer attn validity before forward. <=99. */
#include "Deep2Engine.h"
#include <cstdio>

namespace Deep2 {
namespace multishard_bind {

/* valid = descriptor && shape && backingResolvable && consumerSupported */
inline int LayerAttnValid(const LayerWeights& lw, size_t layer, FILE* f) {
    auto bad = [&](const char* slot, const WeightTensor& wt, const char* why) {
        std::fprintf(f,
                     "B03_LAYER_INVALID layer=%zu slot=%s name=%s shard=%u "
                     "data=%d fileBack=%d rows=%zu cols=%zu bytes=%zu why=%s\n",
                     layer, slot, wt.name.empty() ? "(empty)" : wt.name.c_str(),
                     wt.shardId, wt.data ? 1 : 0, wt.hasFileBacking ? 1 : 0,
                     wt.rows, wt.cols, wt.sizeBytes, why);
        return 0;
    };
    auto ok = [&](const char* slot, const WeightTensor& wt) -> int {
        if (wt.name.empty()) return bad(slot, wt, "UNBOUND_DESCRIPTOR");
        if (wt.rows == 0 || wt.cols == 0 || wt.sizeBytes == 0)
            return bad(slot, wt, "SHAPE");
        if (!wt.hasFileBacking && !wt.data)
            return bad(slot, wt, "BACKING_UNRESOLVABLE");
        if (!wt.data) return bad(slot, wt, "DATA_NULL_NOT_MATERIALIZED");
        if (wt.rows * wt.cols == 0) return bad(slot, wt, "CONSUMER_UNSUPPORTED");
        return 1;
    };
    if (!ok("attn_norm", lw.attnNorm)) return 0;
    if (!ok("wq", lw.wq)) return 0;
    if (!ok("wk", lw.wk)) return 0;
    if (!ok("wv", lw.wv)) return 0;
    if (!ok("wo", lw.wo)) return 0;
    if (!ok("ffn_norm", lw.ffnNorm)) return 0;
    if (!ok("moe_router", lw.moeRouter)) return 0;
    if (!lw.attnQNorm.name.empty() && !ok("attn_q_norm", lw.attnQNorm)) return 0;
    if (!lw.attnKNorm.name.empty() && !ok("attn_k_norm", lw.attnKNorm)) return 0;
    if (lw.wq.rows % 128u != 0) return bad("wq", lw.wq, "HEAD_DIM_Q_NOT_128_ALIGNED");
    if (lw.wk.rows % 128u != 0) return bad("wk", lw.wk, "HEAD_DIM_K_NOT_128_ALIGNED");
    if (lw.wv.rows % 128u != 0) return bad("wv", lw.wv, "HEAD_DIM_V_NOT_128_ALIGNED");
    return 1;
}

inline void DumpLayer0BindTable(const LayerWeights& lw, FILE* f) {
    if (!f) return;
    auto row = [&](const char* slot, const WeightTensor& wt) {
        std::fprintf(f,
                     "B03_L0_BIND slot=%s name=%s shard=%u rows=%zu cols=%zu "
                     "type=%d bytes=%zu data=%d fileBack=%d\n",
                     slot, wt.name.empty() ? "(empty)" : wt.name.c_str(),
                     wt.shardId, wt.rows, wt.cols, wt.type, wt.sizeBytes,
                     wt.data ? 1 : 0, wt.hasFileBacking ? 1 : 0);
    };
    row("attn_norm", lw.attnNorm);
    row("wq", lw.wq); row("wk", lw.wk); row("wv", lw.wv); row("wo", lw.wo);
    row("attn_q_norm", lw.attnQNorm); row("attn_k_norm", lw.attnKNorm);
    row("ffn_norm", lw.ffnNorm); row("moe_router", lw.moeRouter);
}

inline int ValidateAllLayers(const ModelWeights& mw, FILE* f = stderr) {
    if (!f) f = stderr;
    if (!mw.layers.empty()) DumpLayer0BindTable(mw.layers[0], f);
    size_t ok = 0;
    for (size_t i = 0; i < mw.layers.size(); ++i)
        ok += static_cast<size_t>(LayerAttnValid(mw.layers[i], i, f));
    const int pass = (ok == mw.layers.size() && !mw.layers.empty()) ? 1 : 0;
    std::fprintf(f,
                 "B03_LAYER_TENSORS_VALID=%zu/%zu\n"
                 "B03_ATTENTION_BIND_VALID=%d\n",
                 ok, mw.layers.size(), pass);
    return pass;
}

} // namespace multishard_bind
} // namespace Deep2
''', encoding='utf-8')
print('Validate OK')

# Ensure BindAll uses fail-closed materialize return
bind = Path(r"G:\~dev\rawrxd\src\deep2\MultiShardWeightBind.hpp")
bt = bind.read_text(encoding='utf-8')
if 'layerSlots >= 0' not in bt:
    raise SystemExit('BindAll missing fail-closed layerSlots check')
print('BindAll OK')
print('ALL_WRITES_DONE')
