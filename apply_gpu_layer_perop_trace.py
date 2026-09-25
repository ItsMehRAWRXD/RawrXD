#!/usr/bin/env python3
"""Apply per-operation finite check instrumentation inside forwardLayerGpuResident."""
import sys, os

PATH = r"F:\~dev\rawrxd\src\deep2\Deep2Engine_GpuForward.cpp"

with open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

# ------------------------------------------------------------------
# 1) Insert the per-buffer check lambda right after the Run::G0 line.
# ------------------------------------------------------------------
OLD1 = """    using rawr::gpu_iso::Run;
    (void)Run::G0;

    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), *attnNormBuf, vc->ArenaNormed(),"""

NEW1 = """    using rawr::gpu_iso::Run;
    (void)Run::G0;

    // ---- per-operation finite tracer (layer-scope) ----
    const bool traceLayer = GpuFiniteTraceEnabled();
    std::vector<float> traceScratch;
    if (traceLayer) traceScratch.resize(H);
    auto traceBuf = [&](const char* opName,
                        CPUInference::VulkanCompute::DeviceBuf& buf,
                        uint32_t count) {
        if (!traceLayer) return;
        if (count > traceScratch.size()) count = static_cast<uint32_t>(traceScratch.size());
        bool ok = vc->DownloadVector(buf, traceScratch.data(), count);
        if (!ok) {
            std::fprintf(stderr, "GPU_LAYER_TRACE layer=%u op=%s DOWNLOAD_FAIL\n", layer, opName);
            std::fflush(stderr);
            return;
        }
        GpuFiniteWitness fw = ScanGpuFiniteWitness(traceScratch.data(), count);
        std::fprintf(stderr,
            "GPU_LAYER_TRACE layer=%u op=%s fin=%zu nan=%zu inf=%zu firstBad=%zu\n",
            layer, opName, fw.finite, fw.nanCount, fw.infCount, fw.firstBad);
        std::fflush(stderr);
    };
    traceBuf("ENTRY_HIDDEN", vc->ArenaHidden(), H);

    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), *attnNormBuf, vc->ArenaNormed(),"""

if OLD1 not in src:
    print("FAIL: anchor 1 not found")
    sys.exit(1)
src = src.replace(OLD1, NEW1, 1)

# ------------------------------------------------------------------
# 2) After first DispatchRmsNorm
# ------------------------------------------------------------------
OLD2 = """    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), *attnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "attnNorm");
    ++c.rmsNormOps;

    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;"""

NEW2 = """    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), *attnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "attnNorm");
    traceBuf("RMSNORM_ATTN", vc->ArenaNormed(), H);
    ++c.rmsNormOps;

    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;"""

if OLD2 not in src:
    print("FAIL: anchor 2 not found")
    sys.exit(1)
src = src.replace(OLD2, NEW2, 1)

# ------------------------------------------------------------------
# 3) After QKV GEMV
# ------------------------------------------------------------------
OLD3 = """        if (!gemvOverlap3(lw.wq, lw.wk, lw.wv, vc->ArenaNormed(),
                          vc->ArenaQ(), vc->ArenaK(), vc->ArenaV(), qDim, kvDim, kvDim, H))
            return fail("GEMV_QKV", "qkvOverlap3");
        c.qkvOps += 3;
    }
    if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,"""

NEW3 = """        if (!gemvOverlap3(lw.wq, lw.wk, lw.wv, vc->ArenaNormed(),
                          vc->ArenaQ(), vc->ArenaK(), vc->ArenaV(), qDim, kvDim, kvDim, H))
            return fail("GEMV_QKV", "qkvOverlap3");
        traceBuf("GEMV_Q", vc->ArenaQ(), qDim);
        traceBuf("GEMV_K", vc->ArenaK(), kvDim);
        traceBuf("GEMV_V", vc->ArenaV(), kvDim);
        c.qkvOps += 3;
    }
    if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,"""

if OLD3 not in src:
    print("FAIL: anchor 3 not found")
    sys.exit(1)
src = src.replace(OLD3, NEW3, 1)

# ------------------------------------------------------------------
# 4) After RoPE
# ------------------------------------------------------------------
OLD4 = """        return fail("ROPE", "DispatchRope");
    ++c.ropeOps;
    {
        DEEP2_GPU_CHILD_SCOPE(kvScope, KVUpdate);
        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail("APPEND_KV", "AppendKV");"""

NEW4 = """        return fail("ROPE", "DispatchRope");
    traceBuf("ROPE_Q", vc->ArenaQ(), qDim);
    traceBuf("ROPE_K", vc->ArenaK(), kvDim);
    ++c.ropeOps;
    {
        DEEP2_GPU_CHILD_SCOPE(kvScope, KVUpdate);
        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail("APPEND_KV", "AppendKV");"""

if OLD4 not in src:
    print("FAIL: anchor 4 not found")
    sys.exit(1)
src = src.replace(OLD4, NEW4, 1)

# ------------------------------------------------------------------
# 5) After AppendKV
# ------------------------------------------------------------------
OLD5 = """        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail("APPEND_KV", "AppendKV");
    }
    {
        DEEP2_GPU_CHILD_SCOPE(attnScope, DeviceAttention);"""

NEW5 = """        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail("APPEND_KV", "AppendKV");
        traceBuf("APPEND_KV_KCACHE", vc->ArenaKCache(), kvDim * (pos + 1));
        traceBuf("APPEND_KV_VCACHE", vc->ArenaVCache(), kvDim * (pos + 1));
    }
    {
        DEEP2_GPU_CHILD_SCOPE(attnScope, DeviceAttention);"""

if OLD5 not in src:
    print("FAIL: anchor 5 not found")
    sys.exit(1)
src = src.replace(OLD5, NEW5, 1)

# ------------------------------------------------------------------
# 6) After attention decode
# ------------------------------------------------------------------
OLD6 = """            return fail("ATTN_DECODE", "DispatchAttnDecode");
        ++c.softmaxOps;
        ++c.attnValueOps;
    }
    {
        DEEP2_GPU_CHILD_SCOPE(oProjScope, AttentionOutputProj);"""

NEW6 = """            return fail("ATTN_DECODE", "DispatchAttnDecode");
        traceBuf("ATTN_OUT", vc->ArenaAttn(), H);
        ++c.softmaxOps;
        ++c.attnValueOps;
    }
    {
        DEEP2_GPU_CHILD_SCOPE(oProjScope, AttentionOutputProj);"""

if OLD6 not in src:
    print("FAIL: anchor 6 not found")
    sys.exit(1)
src = src.replace(OLD6, NEW6, 1)

# ------------------------------------------------------------------
# 7) After O-proj GEMV + residual add
# ------------------------------------------------------------------
OLD7 = """        if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(),
                                     vc->ArenaResidual(), H))
            return fail("RESIDUAL", "attnResidual");
        ++c.residualOps;
    }

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),"""

NEW7 = """        if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(),
                                     vc->ArenaResidual(), H))
            return fail("RESIDUAL", "attnResidual");
        traceBuf("RESIDUAL_ATTN", vc->ArenaResidual(), H);
        ++c.residualOps;
    }

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),"""

if OLD7 not in src:
    print("FAIL: anchor 7 not found")
    sys.exit(1)
src = src.replace(OLD7, NEW7, 1)

# ------------------------------------------------------------------
# 8) After FFN RMSNorm
# ------------------------------------------------------------------
OLD8 = """    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "ffnNorm");

    ++c.ffnNormOps;"""

NEW8 = """    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "ffnNorm");
    traceBuf("RMSNORM_FFN", vc->ArenaNormed(), H);

    ++c.ffnNormOps;"""

if OLD8 not in src:
    print("FAIL: anchor 8 not found")
    sys.exit(1)
src = src.replace(OLD8, NEW8, 1)

# ------------------------------------------------------------------
# 9) After SwiGLU
# ------------------------------------------------------------------
OLD9 = """        if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
            return fail("SWIGLU", "DispatchSwiGLU");
        ++c.ffnActOps;
        if (!gemv(lw.wDown, vc->ArenaFFNAct(), vc->ArenaDown(), H, inter)) return fail("GEMV_FFN", "wDown");"""

NEW9 = """        if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
            return fail("SWIGLU", "DispatchSwiGLU");
        traceBuf("SWIGLU", vc->ArenaFFNAct(), inter);
        ++c.ffnActOps;
        if (!gemv(lw.wDown, vc->ArenaFFNAct(), vc->ArenaDown(), H, inter)) return fail("GEMV_FFN", "wDown");"""

if OLD9 not in src:
    print("FAIL: anchor 9 not found")
    sys.exit(1)
src = src.replace(OLD9, NEW9, 1)

# ------------------------------------------------------------------
# 10) After final residual add
# ------------------------------------------------------------------
OLD10 = """        if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(),
                                     vc->ArenaHidden(), H))
            return fail("RESIDUAL", "ffnResidual");
        ++c.ffnResidualOps;
    }"""

NEW10 = """        if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(),
                                     vc->ArenaHidden(), H))
            return fail("RESIDUAL", "ffnResidual");
        traceBuf("RESIDUAL_FFN", vc->ArenaHidden(), H);
        ++c.ffnResidualOps;
    }"""

if OLD10 not in src:
    print("FAIL: anchor 10 not found")
    sys.exit(1)
src = src.replace(OLD10, NEW10, 1)

# ------------------------------------------------------------------
# Bump build revision
# ------------------------------------------------------------------
OLD_REV = "constexpr uint64_t kGpuForwardBuildRevision = 2026092401ULL;"
NEW_REV = "constexpr uint64_t kGpuForwardBuildRevision = 2026092402ULL;"
src = src.replace(OLD_REV, NEW_REV, 1)

with open(PATH, "w", encoding="utf-8") as f:
    f.write(src)

print("OK: per-operation trace applied. build rev bumped.")
