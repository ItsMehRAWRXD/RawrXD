import io, os
P = r"F:\rawrxd\test_deep2_inference.cpp"
with io.open(P, "r", encoding="utf-8", newline=None) as f:
    s = f.read()

anchor = """    std::cout << "  Context length: " << meta.maxPositionEmbeddings << std::endl;
"""
addition = """    std::cout << "  Context length: " << meta.maxPositionEmbeddings << std::endl;

    // ── S01 geometry receipt: weight-derived KV geometry must match ──
    {
        const auto &mw = engine.getModelWeights();
        const auto *kv = engine.getKVCache();
        if (!kv)
        {
            std::cerr << "FAIL: KV cache missing after load" << std::endl;
            return 1;
        }
        if (kv->headDimSize() != mw.headDim || kv->headCount() != mw.numKVHeads)
        {
            std::cerr << "FAIL: KV geometry does not match model weights: "
                      << "cacheDim=" << kv->headDimSize()
                      << " weightDim=" << mw.headDim
                      << " cacheKVHeads=" << kv->headCount()
                      << " weightKVHeads=" << mw.numKVHeads << std::endl;
            return 1;
        }
        std::cout << "  " << engine.kvGeometryReceipt() << std::endl;
    }
"""
if s.count(anchor) != 1:
    raise SystemExit("harness anchor not found exactly once")
s = s.replace(anchor, addition, 1)

# Final generation stop-reason check before the PASS print.
old_tail = """    if (!streamResult.completed || streamResult.generatedTokens == 0)
    {
        std::cerr << "FAIL: Streaming did not generate tokens" << std::endl;
        return 1;
    }
"""
new_tail = """    if (!streamResult.completed || streamResult.generatedTokens == 0)
    {
        std::cerr << "FAIL: Streaming did not generate tokens" << std::endl;
        return 1;
    }
    if (engine.generationStopReason() != Deep2::Deep2Engine::GenerationStopReason::COMPLETED)
    {
        std::cerr << "FAIL: generation stop reason="
                  << Deep2::Deep2Engine::GenerationStopReasonName(engine.generationStopReason())
                  << std::endl;
        return 1;
    }
"""
if s.count(old_tail) != 1:
    raise SystemExit("harness tail anchor not found exactly once")
s = s.replace(old_tail, new_tail, 1)

with io.open(P, "w", encoding="utf-8", newline="\r\n") as f:
    f.write(s)
print("patched test_deep2_inference.cpp")