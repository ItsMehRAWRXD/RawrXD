import re

path = r'f:\~dev\rawrxd\src\deep2\Deep2Engine.cpp'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# Verify current signature
assert 'bool Deep2Engine::loadModel(const std::string\u0026 ggufPath, ModelLoadDiag* diag) {' in text, 'Unexpected signature'

# Stage definitions: each tuple is (old_block, new_block)
stages = [
    # Stage 2: GGUF load failed
    (
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF load failed: %s\\n",
                     loader->error().c_str());
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF load failed: %s\\n",
                     loader->error().c_str());
        if (diag) {
            diag->stageCode = 2;
            diag->stageName = "LOAD_GGUF_OPEN";
            diag->message = std::string("GGUFLoader::load() failed: ") + loader->error().c_str();
        }
        return false;'''
    ),
    # Stage 3: missing general.architecture
    (
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF missing general.architecture\\n");
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF missing general.architecture\\n");
        if (diag) {
            diag->stageCode = 3;
            diag->stageName = "LOAD_ARCH_MISSING";
            diag->message = "GGUF metadata lacks general.architecture.";
        }
        return false;'''
    ),
    # Stage 4: missing token embedding tensor
    (
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF missing token embedding tensor\\n");
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF missing token embedding tensor\\n");
        if (diag) {
            diag->stageCode = 4;
            diag->stageName = "BIND_TOKEN_EMBED";
            diag->message = "Missing token_embd.weight or token_embeddings.weight tensor.";
        }
        return false;'''
    ),
    # Stage 5: embedding geometry mismatch
    (
        '''        std::fprintf(stderr, "[Deep2Engine] embedding geometry mismatch\\n");
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] embedding geometry mismatch\\n");
        if (diag) {
            diag->stageCode = 5;
            diag->stageName = "EMBED_GEOMETRY";
            diag->message = "Embedding geometry mismatch (hiddenDim==0, hiddenDim!=embedCols, or vocabSize==0).";
        }
        return false;'''
    ),
    # Stage 6: invalid transformer head/layer geometry
    (
        '''        std::fprintf(stderr, "[Deep2Engine] invalid transformer head/layer geometry\\n");
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] invalid transformer head/layer geometry\\n");
        if (diag) {
            diag->stageCode = 6;
            diag->stageName = "HEAD_LAYER_GEOMETRY";
            diag->message = "Invalid head/layer geometry (numLayers==0, numHeads==0, numKVHeads==0, hiddenDim%numHeads!=0, or numHeads%numKVHeads!=0).";
        }
        return false;'''
    ),
    # Stage 7: GGUF missing layer-norm epsilon
    (
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF missing layer-norm epsilon\\n");
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] GGUF missing layer-norm epsilon\\n");
        if (diag) {
            diag->stageCode = 7;
            diag->stageName = "NORM_EPS_MISSING";
            diag->message = "GGUF missing attention.layer_norm_rms_epsilon / attention.layer_norm_epsilon.";
        }
        return false;'''
    ),
    # Stage 8: final norm / LM-head topology invalid
    (
        '''        std::fprintf(stderr, "[Deep2Engine] final norm / LM-head topology invalid\\n");
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] final norm / LM-head topology invalid\\n");
        if (diag) {
            diag->stageCode = 8;
            diag->stageName = "FINAL_NORM_LMHEAD";
            diag->message = "Final norm or LM-head topology invalid (missing data, or lmHead.rows!=vocabSize, or lmHead.cols!=hiddenDim).";
        }
        return false;'''
    ),
]

for old, new in stages:
    if old not in text:
        raise RuntimeError(f'Pattern not found: {old[:80]}...')
    text = text.replace(old, new, 1)

# Layer-specific patterns (use regex because of %zu variables)
layer_stages = [
    # Stage 9: MoE router geometry mismatch
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu MoE router geometry mismatch\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu MoE router geometry mismatch\\n",
            layer);
        if (diag) {
            diag->stageCode = 9;
            diag->stageName = "MOE_ROUTER_GEOMETRY";
            diag->message = "Layer MoE router geometry mismatch (rows!=numExperts or cols!=hiddenDim).";
        }
        return false;'''
    ),
    # Stage 10: missing routed expert tensors
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu missing routed expert tensors\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu missing routed expert tensors\\n",
            layer);
        if (diag) {
            diag->stageCode = 10;
            diag->stageName = "MOE_EXPERT_TENSOR_MISSING";
            diag->message = "Missing routed expert tensors (gate/up/down) for MoE layer.";
        }
        return false;'''
    ),
    # Stage 11: incomplete expert set
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu incomplete expert set\\n", layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu incomplete expert set\\n", layer);
        if (diag) {
            diag->stageCode = 11;
            diag->stageName = "MOE_INCOMPLETE_EXPERT_SET";
            diag->message = "Incomplete expert set (moeGate/Up/Down size != numExperts).";
        }
        return false;'''
    ),
    # Stage 12: expert geometry mismatch
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu expert %zu geometry mismatch\\n",
            layer, e\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu expert %zu geometry mismatch\\n",
            layer, e);
        if (diag) {
            diag->stageCode = 12;
            diag->stageName = "MOE_EXPERT_GEOMETRY_MISMATCH";
            diag->message = "Expert geometry mismatch (gate/up/down dimensions incorrect).";
        }
        return false;'''
    ),
    # Stage 13: incomplete shared expert
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu incomplete shared expert\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu incomplete shared expert\\n",
            layer);
        if (diag) {
            diag->stageCode = 13;
            diag->stageName = "MOE_SHARED_EXPERT_INCOMPLETE";
            diag->message = "Incomplete shared expert (some tensors present but not all).";
        }
        return false;'''
    ),
    # Stage 14: missing transformer norm tensors
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu missing transformer norm tensors\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu missing transformer norm tensors\\n",
            layer);
        if (diag) {
            diag->stageCode = 14;
            diag->stageName = "LAYER_NORM_MISSING";
            diag->message = "Missing attn_norm.weight or ffn_norm.weight for layer.";
        }
        return false;'''
    ),
    # Stage 15: missing Q/K/V topology
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu missing Q/K/V topology\\n", layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu missing Q/K/V topology\\n", layer);
        if (diag) {
            diag->stageCode = 15;
            diag->stageName = "QKV_TOPOLOGY_MISSING";
            diag->message = "Missing Q/K/V topology (neither split nor fused QKV present).";
        }
        return false;'''
    ),
    # Stage 16: missing dense FFN tensors
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu missing dense FFN tensors\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu missing dense FFN tensors\\n",
            layer);
        if (diag) {
            diag->stageCode = 16;
            diag->stageName = "DENSE_FFN_MISSING";
            diag->message = "Missing dense FFN tensors (wUp or wDown not bound).";
        }
        return false;'''
    ),
    # Stage 17: FFN geometry mismatch
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu FFN geometry mismatch\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu FFN geometry mismatch\\n",
            layer);
        if (diag) {
            diag->stageCode = 17;
            diag->stageName = "FFN_GEOMETRY_MISMATCH";
            diag->message = "Dense FFN geometry mismatch (wUp/wDown dimensions incorrect).";
        }
        return false;'''
    ),
    # Stage 18: attention projection geometry mismatch
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu attention projection geometry mismatch\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu attention projection geometry mismatch\\n",
            layer);
        if (diag) {
            diag->stageCode = 18;
            diag->stageName = "ATTN_PROJECTION_GEOMETRY";
            diag->message = "Attention projection geometry mismatch (wq/wk/wv/wo dimensions incorrect).";
        }
        return false;'''
    ),
]

for pat, repl in layer_stages:
    m = re.search(pat, text)
    if not m:
        raise RuntimeError(f'Layer pattern not found: {pat[:80]}...')
    text = text[:m.start()] + repl + text[m.end():]

# Remaining non-layer stages
remaining = [
    # Stage 19: missing feed-forward geometry
    (
        r'''        std::fprintf\(stderr, "\[Deep2Engine\] missing feed-forward geometry\\n"\);
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] missing feed-forward geometry\\n");
        if (diag) {
            diag->stageCode = 19;
            diag->stageName = "FEED_FORWARD_GEOMETRY_MISSING";
            diag->message = "Missing feed-forward geometry (intermediateDim==0 for dense model).";
        }
        return false;'''
    ),
    # Stage 20: invalid MoE metadata
    (
        r'''        std::fprintf\(stderr, "\[Deep2Engine\] invalid MoE metadata\\n"\);
        return false;''',
        '''        std::fprintf(stderr, "[Deep2Engine] invalid MoE metadata\\n");
        if (diag) {
            diag->stageCode = 20;
            diag->stageName = "MOE_METADATA_INVALID";
            diag->message = "Invalid MoE metadata (numExpertsPerToken==0, >numExperts, or moeIntermediateDim==0).";
        }
        return false;'''
    ),
    # Stage 21: unsupported expert_gating_func
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] unsupported expert_gating_func=%lld\\n",
            static_cast<long long>\(gating\)\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] unsupported expert_gating_func=%lld\\n",
            static_cast<long long>(gating));
        if (diag) {
            diag->stageCode = 21;
            diag->stageName = "MOE_GATING_FUNC_UNSUPPORTED";
            diag->message = "Unsupported expert_gating_func value.";
        }
        return false;'''
    ),
    # Stage 22: neither complete dense nor MoE FFN
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu has neither complete dense nor MoE FFN\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu has neither complete dense nor MoE FFN\\n",
            layer);
        if (diag) {
            diag->stageCode = 22;
            diag->stageName = "HYBRID_FFN_INCOMPLETE";
            diag->message = "Layer has neither complete dense nor MoE FFN tensors.";
        }
        return false;'''
    ),
    # Stage 23: router initialization failed
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu router initialization failed\\n",
            layer\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu router initialization failed\\n",
            layer);
        if (diag) {
            diag->stageCode = 23;
            diag->stageName = "MOE_ROUTER_INIT_FAILED";
            diag->message = "MoE router initialization failed for layer.";
        }
        return false;'''
    ),
    # Stage 24: expert byte overflow
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] layer %zu expert %zu byte overflow\\n",
            layer, e\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] layer %zu expert %zu byte overflow\\n",
            layer, e);
        if (diag) {
            diag->stageCode = 24;
            diag->stageName = "MOE_EXPERT_BYTE_OVERFLOW";
            diag->message = "Expert byte size overflow (sum of gate/up/down bytes exceeds limits).";
        }
        return false;'''
    ),
    # Stage 25: expert_count>0 but no MoE layer tensors were bound
    (
        r'''        std::fprintf\(stderr,
            "\[Deep2Engine\] expert_count>0 but no MoE layer tensors were bound\\n"\);
        return false;''',
        '''        std::fprintf(stderr,
            "[Deep2Engine] expert_count>0 but no MoE layer tensors were bound\\n");
        if (diag) {
            diag->stageCode = 25;
            diag->stageName = "MOE_NO_LAYERS_BOUND";
            diag->message = "MoE enabled (expert_count>0) but no MoE layer tensors were bound.";
        }
        return false;'''
    ),
    # Stage 26: initialize(recovered) failed
    (
        r'''        if \(!initialize\(recovered\)\) {
            modelWeights\.loaded = false;
            ggufResult = \{\};
            return false;
        }''',
        '''        if (!initialize(recovered)) {
            if (diag) {
                diag->stageCode = 26;
                diag->stageName = "ENGINE_INIT_FAILED";
                diag->message = "Engine initialize(recovered) failed after GGUF bind.";
            }
            modelWeights.loaded = false;
            ggufResult = {};
            return false;
        }'''
    ),
    # Stage 27: allocateBuffers failed
    (
        r'''    \} else if \(!allocateBuffers\(\)\) {
        modelWeights\.loaded = false;
        ggufResult = \{\};
        return false;
    }''',
        '''    } else if (!allocateBuffers()) {
        if (diag) {
            diag->stageCode = 27;
            diag->stageName = "BUFFER_ALLOC_FAILED";
            diag->message = "allocateBuffers() failed after GGUF bind.";
        }
        modelWeights.loaded = false;
        ggufResult = {};
        return false;
    }'''
    ),
    # Stage 28: KV cache allocation failed
    (
        r'''            std::fprintf\(stderr, "\[Deep2Engine\] KV cache allocation failed\\n"\);
            modelWeights\.loaded = false;
            ggufResult = \{\};
            return false;''',
        '''            std::fprintf(stderr, "[Deep2Engine] KV cache allocation failed\\n");
            if (diag) {
                diag->stageCode = 28;
                diag->stageName = "KV_CACHE_ALLOC_FAILED";
                diag->message = "KV cache allocation failed.";
            }
            modelWeights.loaded = false;
            ggufResult = {};
            return false;'''
    ),
]

for pat, repl in remaining:
    m = re.search(pat, text)
    if not m:
        raise RuntimeError(f'Remaining pattern not found: {pat[:80]}...')
    text = text[:m.start()] + repl + text[m.end():]

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print('Instrumentation complete. Stages 2-28 added.')
