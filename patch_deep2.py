import io, os, sys

PATH = r"F:\rawrxd\src\deep2\Deep2Engine.cpp"

with io.open(PATH, "r", encoding="utf-8", newline=None) as f:
    src = f.read()

def replace_once(text, old, new, label):
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected 1 match, found {n}")
    return text.replace(old, new, 1)

HELPERS = r'''
// ============================================================================
// Attention geometry authority (F02/S01)
//
// Geometry is derived from the actual bound weight tensors.  Metadata can be
// wrong (e.g. Gemma3 advertises headDim=288 while Q is 4*256).  The KV cache
// and scratch buffers must use the weight geometry, and every consumer must
// agree on it before allocation or decode.
// ============================================================================
struct AttentionGeometry
{
    size_t headDim = 0;
    size_t numHeads = 0;
    size_t numKVHeads = 0;
    bool valid = false;
    std::string detail;
};

static bool deriveAttentionGeometry(const ModelWeights &mw, AttentionGeometry &g)
{
    g = AttentionGeometry{};
    if (mw.layers.empty())
    {
        g.detail = "no bound layers";
        return false;
    }
    if (mw.useMLA)
    {
        if (mw.headDim == 0 || mw.numHeads == 0 || mw.numKVHeads == 0)
        {
            g.detail = "MLA geometry incomplete";
            return false;
        }
        g.headDim = mw.headDim;
        g.numHeads = mw.numHeads;
        g.numKVHeads = mw.numKVHeads;
        g.valid = true;
        return true;
    }
    if (mw.numHeads == 0 || mw.hiddenDim == 0)
    {
        g.detail = "metadata head/hidden dimensions are zero";
        return false;
    }

    bool haveFirst = false;
    size_t seenLayers = 0;
    for (size_t i = 0; i < mw.layers.size(); ++i)
    {
        const LayerWeights &lw = mw.layers[i];
        if (lw.hasSSM && !lw.wq.data && !lw.wqkv.data)
            continue; // SSM-only layer does not use attention KV

        size_t qRows = lw.wq.data ? lw.wq.rows : 0;
        size_t kRows = lw.wk.data ? lw.wk.rows : 0;
        size_t vRows = lw.wv.data ? lw.wv.rows : 0;

        if (lw.wqkv.data)
        {
            // Fused QKV: rows = hiddenDim + 2*kvDim.
            if (lw.wqkv.rows <= mw.hiddenDim ||
                ((lw.wqkv.rows - mw.hiddenDim) % 2) != 0)
            {
                g.detail = "layer " + std::to_string(i) +
                           " fused QKV row count is inconsistent";
                return false;
            }
            if (qRows == 0) qRows = mw.hiddenDim;
            if (kRows == 0) kRows = (lw.wqkv.rows - mw.hiddenDim) / 2;
            if (vRows == 0) vRows = kRows;
        }

        if (qRows == 0 && kRows == 0 && vRows == 0)
            continue; // no attention tensors on this layer

        if (qRows == 0 || kRows == 0 || vRows == 0)
        {
            g.detail = "layer " + std::to_string(i) +
                       " has incomplete attention tensors";
            return false;
        }
        if ((qRows % mw.numHeads) != 0)
        {
            g.detail = "layer " + std::to_string(i) +
                       " Q rows are not divisible by numHeads";
            return false;
        }
        const size_t layerHeadDim = qRows / mw.numHeads;
        if (layerHeadDim == 0)
        {
            g.detail = "layer " + std::to_string(i) + " derived headDim=0";
            return false;
        }
        if ((kRows % layerHeadDim) != 0 || (vRows % layerHeadDim) != 0)
        {
            g.detail = "layer " + std::to_string(i) +
                       " K/V rows are not divisible by headDim";
            return false;
        }
        if (kRows != vRows)
        {
            g.detail = "layer " + std::to_string(i) +
                       " K and V row counts differ; KV layout cannot store both";
            return false;
        }
        const size_t layerKVHeads = kRows / layerHeadDim;
        if (layerKVHeads == 0 || (mw.numHeads % layerKVHeads) != 0)
        {
            g.detail = "layer " + std::to_string(i) +
                       " GQA head count is invalid";
            return false;
        }

        if (!haveFirst)
        {
            g.headDim = layerHeadDim;
            g.numHeads = mw.numHeads;
            g.numKVHeads = layerKVHeads;
            haveFirst = true;
        }
        else
        {
            if (layerHeadDim != g.headDim || layerKVHeads != g.numKVHeads)
            {
                g.detail = "layer " + std::to_string(i) +
                           " attention geometry differs from layer 0";
                return false;
            }
        }
        ++seenLayers;
    }

    if (!haveFirst || seenLayers == 0)
    {
        g.detail = "no attention layers found";
        return false;
    }
    g.valid = true;
    return true;
}

static bool reconcileAttentionGeometryFor(ModelWeights &mw, EngineConfig &cfg,
                                         std::string &detail)
{
    if (mw.layers.empty())
    {
        detail = "no bound layers (pre-load)";
        return true;
    }
    AttentionGeometry g;
    if (!deriveAttentionGeometry(mw, g))
    {
        detail = g.detail;
        return false;
    }
    if (mw.numHeads != g.numHeads)
    {
        detail = "metadata numHeads does not match weight geometry";
        return false;
    }

    if (mw.headDim != g.headDim)
    {
        printf("[Deep2Engine] ATTN_GEOM_OVERRIDE headDim weight=%zu previous=%zu\n",
               g.headDim, mw.headDim);
        mw.headDim = g.headDim;
        cfg.headDim = g.headDim;
    }
    if (mw.numKVHeads != g.numKVHeads)
    {
        printf("[Deep2Engine] ATTN_GEOM_OVERRIDE kvHeads weight=%zu previous=%zu\n",
               g.numKVHeads, mw.numKVHeads);
        mw.numKVHeads = g.numKVHeads;
        cfg.numKVHeads = g.numKVHeads;
    }
    detail = "headDim=" + std::to_string(g.headDim) +
             " qHeads=" + std::to_string(g.numHeads) +
             " kvHeads=" + std::to_string(g.numKVHeads);
    return true;
}

static bool configureKVCacheFor(ModelWeights &mw, EngineConfig &cfg,
                                std::unique_ptr<KVCache> &kvCache,
                                const char *reason)
{
    if (!cfg.useKVCache)
    {
        kvCache.reset();
        return true;
    }

    std::string detail;
    if (!reconcileAttentionGeometryFor(mw, cfg, detail))
    {
        printf("[Deep2Engine] KV_CACHE_CONFIG_FAILED reason=%s detail=%s\n",
               reason ? reason : "?", detail.c_str());
        return false;
    }

    AttentionGeometry g;
    const bool haveGeometry = deriveAttentionGeometry(mw, g);
    size_t attnLayers = 0;
    for (const auto &lw : mw.layers)
    {
        if (lw.hasSSM && !lw.wq.data && !lw.wqkv.data)
            continue;
        if (lw.wq.data || lw.wk.data || lw.wv.data || lw.wqkv.data)
            ++attnLayers;
    }
    if (attnLayers == 0)
        attnLayers = mw.numLayers;

    const size_t headDim = haveGeometry
                               ? g.headDim
                               : (mw.headDim ? mw.headDim : cfg.headDim);
    const size_t kvHeads =
        haveGeometry ? g.numKVHeads
                     : (mw.numKVHeads ? mw.numKVHeads
                                      : (mw.numHeads ? mw.numHeads : cfg.numKVHeads));
    const size_t maxSeq = cfg.maxSeqLen > 0 ? cfg.maxSeqLen : 4096;

    if (headDim == 0 || kvHeads == 0 || attnLayers == 0 || maxSeq == 0)
    {
        printf("[Deep2Engine] KV_CACHE_CONFIG_FAILED reason=%s headDim=%zu kvHeads=%zu layers=%zu maxSeq=%zu\n",
               reason ? reason : "?", headDim, kvHeads, attnLayers, maxSeq);
        return false;
    }

    if (kvCache && kvCache->headDimSize() == headDim &&
        kvCache->headCount() == kvHeads && kvCache->numLayers() == attnLayers)
    {
        kvCache->reset();
        printf("[Deep2Engine] KV_CACHE_REUSED reason=%s layers=%zu heads=%zu dim=%zu positions=%zu\n",
               reason ? reason : "?", attnLayers, kvHeads, headDim,
               kvCache->maxSeqLen());
        return true;
    }

    auto fresh = std::make_unique<KVCache>();
    KVCacheConfig vc;
    vc.numLayers = attnLayers;
    vc.maxSeqLen = maxSeq;
    vc.numHeads = kvHeads;
    vc.headDim = headDim;
    if (!fresh->initialize(vc))
    {
        printf("[Deep2Engine] KV_CACHE_CONFIG_FAILED reason=%s initialize=false\n",
               reason ? reason : "?");
        return false;
    }
    kvCache = std::move(fresh);
    printf("[Deep2Engine] KV_CACHE_CONFIGURED reason=%s layers=%zu positions=%zu kvHeads=%zu headDim=%zu\n",
           reason ? reason : "?", attnLayers, maxSeq, kvHeads, headDim);
    return true;
}

static bool validateKVCacheGeometryFor(const ModelWeights &mw,
                                       const EngineConfig &cfg,
                                       const KVCache &kvCache,
                                       std::string &detail)
{
    if (!kvCache.initialized())
    {
        detail = "cache not initialized";
        return false;
    }
    AttentionGeometry g;
    const bool haveGeometry = deriveAttentionGeometry(mw, g);
    const size_t headDim = haveGeometry
                               ? g.headDim
                               : (mw.headDim ? mw.headDim : cfg.headDim);
    const size_t kvHeads =
        haveGeometry ? g.numKVHeads
                     : (mw.numKVHeads ? mw.numKVHeads
                                      : (mw.numHeads ? mw.numHeads : cfg.numKVHeads));
    size_t attnLayers = 0;
    for (const auto &lw : mw.layers)
    {
        if (lw.hasSSM && !lw.wq.data && !lw.wqkv.data)
            continue;
        if (lw.wq.data || lw.wk.data || lw.wv.data || lw.wqkv.data)
            ++attnLayers;
    }
    if (attnLayers == 0)
        attnLayers = mw.numLayers;

    if (kvCache.headDimSize() != headDim || kvCache.headCount() != kvHeads ||
        kvCache.numLayers() != attnLayers)
    {
        detail = "cache geometry mismatch";
        return false;
    }
    if (kvCache.currentLength() > kvCache.maxSeqLen())
    {
        detail = "cache position exceeds capacity";
        return false;
    }
    detail = "ok";
    return true;
}
'''

anchor = "static float g_ropeScaling = 1.0f;\n"
src = replace_once(src, anchor, anchor + HELPERS, "insert geometry helpers")

RECEIPT = r'''
std::string Deep2Engine::kvGeometryReceipt() const
{
    std::string detail;
    const bool ok = kvCache && validateKVCacheGeometryFor(modelWeights, config, *kvCache, detail);
    char buf[512];
    std::snprintf(buf, sizeof(buf),
                  "KV_GEOMETRY valid=%d layers=%zu positions=%zu kvHeads=%zu "
                  "headDim=%zu weightHeads=%zu weightKVHeads=%zu weightHeadDim=%zu "
                  "currentLen=%u detail=%s",
                  ok ? 1 : 0,
                  kvCache ? kvCache->numLayers() : 0,
                  kvCache ? kvCache->maxSeqLen() : 0,
                  kvCache ? kvCache->headCount() : 0,
                  kvCache ? kvCache->headDimSize() : 0,
                  modelWeights.numHeads, modelWeights.numKVHeads, modelWeights.headDim,
                  kvCache ? kvCache->currentLength() : 0,
                  detail.c_str());
    return std::string(buf);
}
'''
meta_anchor = """const ModelMetadata& Deep2Engine::getModelMetadata() const
{
    return ggufResult.metadata;
}
"""
src = replace_once(src, meta_anchor, meta_anchor + RECEIPT, "insert kvGeometryReceipt")

INIT_OLD = """    // Initialize KV cache with correct GQA dimensions
    if (config.useKVCache)
    {
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        kvConfig.numLayers = config.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen;
        kvConfig.numHeads = config.numKVHeads > 0 ? config.numKVHeads : config.numHeads;
        kvConfig.headDim = config.headDim > 0 ? config.headDim : (config.hiddenDim / config.numHeads);

        printf("[KVCache] Allocating: layers=%zu seq=%zu kv_heads=%zu headDim=%zu\\n", kvConfig.numLayers,
               kvConfig.maxSeqLen, kvConfig.numHeads, kvConfig.headDim);

        if (!kvCache->initialize(kvConfig))
        {
            printf("[Deep2Engine] ERROR: Failed to initialize KV cache\\n");
            return false;
        }
    }

    // Initialize KV cache with correct GQA dimensions
    if (config.useKVCache)
    {
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        kvConfig.numLayers = config.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen;
        kvConfig.numHeads = config.numKVHeads > 0 ? config.numKVHeads : config.numHeads;
        kvConfig.headDim = config.headDim > 0 ? config.headDim : (config.hiddenDim / config.numHeads);

        printf("[KVCache] Allocating: layers=%zu seq=%zu kv_heads=%zu headDim=%zu\\n", kvConfig.numLayers,
               kvConfig.maxSeqLen, kvConfig.numHeads, kvConfig.headDim);

        if (!kvCache->initialize(kvConfig))
        {
            printf("[Deep2Engine] ERROR: Failed to initialize KV cache\\n");
            return false;
        }
    }
"""
INIT_NEW = """    // Single authoritative KV-cache setup.  At initialize() time the model
    // may not be bound yet; configureKVCacheFor() falls back to config and
    // loadModel() rebuilds it from the bound weight geometry.
    if (!configureKVCacheFor(modelWeights, config, kvCache, "initialize"))
    {
        printf("[Deep2Engine] ERROR: Failed to initialize KV cache\\n");
        return false;
    }
"""
src = replace_once(src, INIT_OLD, INIT_NEW, "deduplicate initialize KV")

LOAD_OLD = """    // Re-allocate buffers with correct dimensions
    deallocateBuffers();
    if (!allocateBuffers())
    {
        printf("[Deep2Engine] ERROR: Failed to re-allocate buffers\\n");
        return false;
    }

    // loadModel-only clients (e.g. RawrXD-Agentic) never call initialize() —
    // ensure thread pool, KV cache, and quant dispatch are ready here.
    if (config.useThreadPool && !threadPool)
    {
        threadPool = std::make_unique<ThreadPool>(config.numThreads);
        printf("[Deep2Engine] ThreadPool (loadModel): %zu threads\\n", threadPool->size());
    }
    Deep2::QuantKernelRegistry::Instance().Initialize();

    // Always (re)build KV cache for GGUF loads — do not require a prior initialize()
    // KV cache is sized for attention layers only; SSM layers manage recurrent
    // state separately (ssmMambaState / ssmMambaConvState).
    if (config.useKVCache)
    {
        if (kvCache)
            kvCache->reset();
        kvCache = std::make_unique<KVCache>();
        KVCacheConfig kvConfig;
        size_t attnLayers = 0;
        for (const auto& t : layerTopology_)
            if (t.mixer == LayerMixer::Attention) ++attnLayers;
        kvConfig.numLayers = attnLayers > 0 ? attnLayers : modelWeights.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen > 0 ? config.maxSeqLen : 4096;
        kvConfig.numHeads = modelWeights.numKVHeads > 0 ? modelWeights.numKVHeads : modelWeights.numHeads;
        kvConfig.headDim = modelWeights.headDim;
        if (!kvCache->initialize(kvConfig))
        {
            printf("[Deep2Engine] ERROR: KV cache init failed after loadModel\\n");
            return false;
        }
        printf("[Deep2Engine] KV cache: %zu layers x %zu positions x %zu heads x %zu dim = %.2f MB\\n",
               kvConfig.numLayers, kvConfig.maxSeqLen, kvConfig.numHeads, kvConfig.headDim,
               (double)kvConfig.totalSize() / (1024.0 * 1024.0));
    }
"""
LOAD_NEW = """    // Reconcile geometry from the bound weight tensors BEFORE allocating any
    // scratch buffer or KV cache.  Metadata alone is not authoritative.
    {
        std::string geomDetail;
        if (!reconcileAttentionGeometryFor(modelWeights, config, geomDetail))
        {
            printf("[Deep2Engine] ERROR: attention geometry reconciliation failed: %s\\n",
                   geomDetail.c_str());
            return false;
        }
        printf("[Deep2Engine] ATTN_GEOMETRY_RECONCILED %s\\n", geomDetail.c_str());
    }

    // Re-allocate buffers with correct dimensions
    deallocateBuffers();
    if (!allocateBuffers())
    {
        printf("[Deep2Engine] ERROR: Failed to re-allocate buffers\\n");
        return false;
    }

    // loadModel-only clients (e.g. RawrXD-Agentic) never call initialize() —
    // ensure thread pool, KV cache, and quant dispatch are ready here.
    if (config.useThreadPool && !threadPool)
    {
        threadPool = std::make_unique<ThreadPool>(config.numThreads);
        printf("[Deep2Engine] ThreadPool (loadModel): %zu threads\\n", threadPool->size());
    }
    Deep2::QuantKernelRegistry::Instance().Initialize();

    // One authoritative KV-cache setup for every load path.
    if (!configureKVCacheFor(modelWeights, config, kvCache, "loadModel"))
    {
        printf("[Deep2Engine] ERROR: KV cache configuration failed after loadModel\\n");
        return false;
    }
"""
src = replace_once(src, LOAD_OLD, LOAD_NEW, "rewire loadModel KV")

GEN_OLD = """    // ── Ensure KV cache exists before completion gate ──
    // reset() above only resets an existing cache; it does not create one.
    // loadModel() creates it, but be defensive for loadModel-only clients
    // that may call generate() without a prior initialize() path.
    if (config.useKVCache && !kvCache)
    {
        KVCacheConfig kvConfig{};
        size_t attnLayers = 0;
        for (const auto& t : layerTopology_)
            if (t.mixer == LayerMixer::Attention) ++attnLayers;
        kvConfig.numLayers = attnLayers > 0 ? attnLayers : modelWeights.numLayers;
        kvConfig.maxSeqLen = config.maxSeqLen > 0 ? config.maxSeqLen : 4096;
        kvConfig.numHeads = modelWeights.numKVHeads > 0 ? modelWeights.numKVHeads : modelWeights.numHeads;
        kvConfig.headDim = modelWeights.headDim;
        kvCache = std::make_unique<KVCache>();
        if (!kvCache->initialize(kvConfig))
        {
            fprintf(stderr,
                    "[Deep2Engine] ERROR: KV cache init failed before generate\\n");
            m_generationStop = GenerationStopReason::KV_INIT_FAILED;
            return 0;
        }
    }
"""
GEN_NEW = """    // ── Validate/repair KV geometry before the completion gate ──
    // reset() above only resets an existing cache; it does not create one.
    // loadModel() creates it, but be defensive for loadModel-only clients.
    if (config.useKVCache)
    {
        std::string geomDetail;
        if (!kvCache ||
            !validateKVCacheGeometryFor(modelWeights, config, *kvCache, geomDetail))
        {
            if (!configureKVCacheFor(modelWeights, config, kvCache, "generate"))
            {
                fprintf(stderr,
                        "[Deep2Engine] ERROR: KV cache validation failed before generate: %s\\n",
                        geomDetail.c_str());
                m_generationStop = GenerationStopReason::KV_INIT_FAILED;
                return 0;
            }
        }
    }
"""
src = replace_once(src, GEN_OLD, GEN_NEW, "rewire generate KV guard")

# Stop-reason propagation in generate() catch paths.
src = replace_once(
    src,
    """                catch (const std::exception& ex)
                {
                    fprintf(stderr,
                            "[B3_ABORT] prefill exception at layer=%zu: %s\\n", layer, ex.what());
                    fflush(stderr);
                    return 0;
                }""",
    """                catch (const std::exception& ex)
                {
                    fprintf(stderr,
                            "[B3_ABORT] prefill exception at layer=%zu: %s\\n", layer, ex.what());
                    fflush(stderr);
                    m_generationStop = GenerationStopReason::EXCEPTION;
                    return 0;
                }""",
    "prefill layer catch stop reason",
)

src = replace_once(
    src,
    """        catch (const std::exception& ex)
        {
            fprintf(stderr, "[B3_ABORT] %s\\n", ex.what());
            return 0;
        }""",
    """        catch (const std::exception& ex)
        {
            fprintf(stderr, "[B3_ABORT] %s\\n", ex.what());
            m_generationStop = GenerationStopReason::EXCEPTION;
            return 0;
        }""",
    "prompt trace catch stop reason",
)

src = replace_once(
    src,
    """                    if (!forwardTokenAllLayers(h, inputPos + 1))
                    {
                        fprintf(stderr, "[B3_ABORT] decode gpu/cpu forward fail\\n");
                        return tokensGenerated;
                    }""",
    """                    if (!forwardTokenAllLayers(h, inputPos + 1))
                    {
                        fprintf(stderr, "[B3_ABORT] decode gpu/cpu forward fail\\n");
                        if (m_generationStop == GenerationStopReason::NONE)
                            m_generationStop = GenerationStopReason::FORWARD_FAULT;
                        return tokensGenerated;
                    }""",
    "decode forward failure stop reason",
)

src = replace_once(
    src,
    """                catch (const std::exception& ex)
                {
                    fprintf(stderr,
                            "[B3_ABORT] decode exception: %s\\n", ex.what());
                    fflush(stderr);
                    return tokensGenerated;
                }""",
    """                catch (const std::exception& ex)
                {
                    fprintf(stderr,
                            "[B3_ABORT] decode exception: %s\\n", ex.what());
                    fflush(stderr);
                    m_generationStop = GenerationStopReason::EXCEPTION;
                    return tokensGenerated;
                }""",
    "decode exception stop reason",
)

src = replace_once(
    src,
    """                catch (const std::exception& ex)
                {
                    fprintf(stderr,
                            "[B3_ABORT] decode exception at layer=%zu: %s\\n", layer, ex.what());
                    fflush(stderr);
                    return tokensGenerated;
                }""",
    """                catch (const std::exception& ex)
                {
                    fprintf(stderr,
                            "[B3_ABORT] decode exception at layer=%zu: %s\\n", layer, ex.what());
                    fflush(stderr);
                    m_generationStop = GenerationStopReason::EXCEPTION;
                    return tokensGenerated;
                }""",
    "decode layer catch stop reason",
)

src = replace_once(
    src,
    """    catch (const std::exception& e)
    {
        fprintf(stderr, "[Deep2Engine] generate() exception: %s\\n", e.what());
        return 0;
    }
    catch (...)
    {
        fprintf(stderr, "[Deep2Engine] generate() unknown exception\\n");
        return 0;
    }""",
    """    catch (const std::exception& e)
    {
        fprintf(stderr, "[Deep2Engine] generate() exception: %s\\n", e.what());
        m_generationStop = GenerationStopReason::EXCEPTION;
        return 0;
    }
    catch (...)
    {
        fprintf(stderr, "[Deep2Engine] generate() unknown exception\\n");
        m_generationStop = GenerationStopReason::EXCEPTION;
        return 0;
    }""",
    "outer generate catch stop reason",
)

with io.open(PATH, "w", encoding="utf-8", newline="\r\n") as f:
    f.write(src)

print("patched Deep2Engine.cpp")
print("bytes", os.path.getsize(PATH))
print("lines", src.count("\n") + 1)