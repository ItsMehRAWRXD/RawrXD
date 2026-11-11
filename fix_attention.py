import re

# Read the file
with open(r'F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp', 'r') as f:
    content = f.read()

# Find and replace the AttentionFwd function
# Pattern to match from the start of AttentionFwd to the start of MlaDecompressFwd
old_pattern = r'(// This is ONLY a token-zero kernel.*?return true;\s*\n\s*}\s*\n\s*// Input x\[2048\] -> A projection)'

new_function = '''// Causal attention with MLA KV cache.
    // q: [heads, key] - current query (content key + positional key, NOT yet RoPE'd)
    // KV cache contains compressed kv_latent [512] and k_rope_raw [64] for all positions.
    // Keys are RoPE'd at READ time for their respective positions.
    static bool AttentionFwd(const float* q, const float* kv, float* output,
                             size_t qN, size_t kvN, size_t outputN,
                             const MlaKVCache* kvCache = nullptr, size_t layerIdx = 0, size_t position = 0,
                             uint32_t opId = 0)
    {
        const size_t heads = GEN::ModelConfig::kHeadCount;
        const size_t key = GEN::ModelConfig::kKeyLength;
        const size_t value = GEN::ModelConfig::kValueLength;
        const size_t rope = GEN::ModelConfig::kRopeDimensionCount;
        const size_t noRope = key - rope;
        const size_t kSize = heads * key;
        const size_t vSize = heads * value;
        
        if (!q || !output || qN != heads * key || outputN != heads * value) return false;
        
        // If no KV cache or position 0, use simple path (kv contains current K/V)
        if (!kvCache || position == 0) {
            if (!kv || kvN != heads * (key + value)) return false;
            // At position 0, softmax over single element = 1.0, so output = V
            std::memcpy(output, kv + heads * key, heads * value * sizeof(float));
            return true;
        }
        
        // Causal attention with KV cache
        // q: [heads, key] - current query (content key + positional key, NOT yet RoPE'd)
        // KV cache contains compressed kv_latent [512] and k_rope_raw [64] for all positions 0..position
        const size_t seq_len = position + 1; // including current
        if (layerIdx >= kvCache->layers.size() || kvCache->layers[layerIdx].Size() != seq_len) {
            std::fprintf(stderr, "[KV] Invalid layer or prefix at position %zu, layer %zu\n", position, layerIdx);
            return false;
        }
        
        const float* all_kv_latent = kvCache->layers[layerIdx].ReadAllKvLatent();
        const float* all_k_rope_raw = kvCache->layers[layerIdx].ReadAllKRopeRaw();
        if (!all_kv_latent || !all_k_rope_raw) return false;
        
        // Apply RoPE to query's positional component at current position
        // q layout per head: [noRope=128 content | rope=64 positional]
        std::vector<float> q_rope(heads * key);
        const float base = static_cast<float>(GEN::ModelConfig::kRopeFreqBase);
        for (size_t head = 0; head < heads; ++head) {
            const float* q_head = q + head * key;
            float* q_rope_head = q_rope.data() + head * key;
            // Content key (noRope=128) unchanged
            std::memcpy(q_rope_head, q_head, 128 * sizeof(float));
            // Positional key (rope=64) - apply RoPE at current position
            for (size_t i = 0; i < 64; i += 2) {
                float theta = powf(base, -static_cast<float>(i) / 64.0f);
                float alpha = static_cast<float>(position) * theta;
                float ca = cosf(alpha), sa = sinf(alpha);
                float p0 = q_head[128 + i];
                float p1 = q_head[128 + i + 1];
                q_rope_head[128 + i] = p0 * ca - p1 * sa;
                q_rope_head[128 + i + 1] = p0 * sa + p1 * ca;
            }
        }
        
        const float scale = 1.0f / sqrtf(192.0f); // 1/sqrt(192)
        const bool capture_scores = g_differential_recorder.ShouldRecord(position);
        std::vector<float> captured_scores, captured_weights;
        if (capture_scores) {
            captured_scores.resize(16 * seq_len);
            captured_weights.resize(16 * seq_len);
        }
        
        // DIFF: Record query after RoPE
        DIFF_RECORD("Attention_Q_RoPE", opId, layerIdx, position, "q_rope", q_rope.data(), {(int64_t)16 * 192});
        
        // For each head, compute attention over all cached positions
        for (size_t head = 0; head < 16; ++head) {
            // Query for this head (with RoPE applied): q_rope[head * 192 ... (head+1)*192 - 1]
            const float* q_head = q_rope.data() + head * 192;
            
            // Split query into q_nope (128) and q_pe (64)
            const float* q_nope = q_head;
            const float* q_pe = q_head + 128;
            
            // Accumulator for output values
            std::vector<float> out_acc(128, 0.0f);
            float denom = 0.0f;
            
            // Find max score for numerical stability
            float max_score = -INFINITY;
            for (size_t pos = 0; pos < seq_len; ++pos) {
                // Reconstruct K for this position and head:
                // K = [kv_latent (512) per pos] + [k_rope (64) with RoPE at pos]
                // Per head: K_nope (128) from kv_latent + K_pe (64) from k_rope_raw with RoPE at pos
                
                const float* kv_latent_pos = kvCache->layers[0].ReadKvLatent(pos);
                const float* k_rope_raw_pos = kvCache->layers[0].ReadKRopeRaw(pos);
                if (!kv_latent_pos || !k_rope_raw_pos) return false;
                
                // K_nope for this head: 128 elements from kv_latent
                const float* k_nope = kv_latent_pos + head * 128;
                
                // K_pe: apply RoPE to k_rope_raw at this position
                float k_pe[64];
                const float* k_rope_raw = all_k_rope_raw + pos * 64;
                for (size_t i = 0; i < 64; i += 2) {
                    float theta = powf(base, -static_cast<float>(i) / 64.0f);
                    float alpha = static_cast<float>(pos) * theta;
                    float ca = cosf(alpha), sa = sinf(alpha);
                    float p0 = k_rope_raw[i];
                    float p1 = k_rope_raw[i + 1];
                    k_pe[i] = p0 * ca - p1 * sa;
                    k_pe[i + 1] = p0 * sa + p1 * ca;
                }
                
                // Compute dot product q·k (both have RoPE at their respective positions)
                float score = 0.0f;
                // q_nope (128) dot k_nope (128)
                for (size_t i = 0; i < 128; ++i) {
                    score += q_nope[i] * k_nope[i];
                }
                // q_pe (64) dot k_pe (64) - both have RoPE at their positions
                for (size_t i = 0; i < 64; ++i) {
                    score += q_head[128 + i] * k_pe[i];
                }
                score *= scale;
                if (capture_scores) captured_scores[head * seq_len + pos] = score;
                
                if (score > max_score) max_score = score;
            }
            
            // Compute softmax and weighted sum
            for (size_t pos = 0; pos < seq_len; ++pos) {
                const float* kv_latent_pos = kvCache->layers[0].ReadKvLatent(pos);
                const float* k_rope_raw_pos = kvCache->layers[0].ReadKRopeRaw(pos);
                if (!kv_latent_pos || !k_rope_raw_pos) return false;
                
                const float* k_nope = kv_latent_pos + head * 128;
                const float* k_rope_raw = all_k_rope_raw + pos * 64;
                float k_pe[64];
                for (size_t i = 0; i < 64; i += 2) {
                    float theta = powf(base, -static_cast<float>(i) / 64.0f);
                    float alpha = static_cast<float>(pos) * theta;
                    float ca = cosf(alpha), sa = sinf(alpha);
                    float p0 = k_rope_raw[i];
                    float p1 = k_rope_raw[i + 1];
                    k_pe[i] = p0 * ca - p1 * sa;
                    k_pe[i + 1] = p0 * sa + p1 * ca;
                }
                
                float score = 0.0f;
                for (size_t i = 0; i < 128; ++i) {
                    score += q_nope[i] * k_nope[i];
                }
                for (size_t i = 0; i < 64; ++i) {
                    score += q_head[128 + i] * k_pe[i];
                }
                score *= scale;
                
                float exp_score = expf(score - max_score);
                if (capture_scores) captured_weights[head * seq_len + pos] = exp_score;
                denom += exp_score;
                
                // V is the value from expanded KV at this position
                // kv passed to this function contains [K (3072), V (2048)] for current position
                const float* v_head = kv + 3072 + head * 128;
                for (size_t i = 0; i < 128; ++i) {
                    out_acc[i] += exp_score * v_head[i];
                }
            }
            
            // Normalize and write output
            float* out_head = output + head * 128;
            for (size_t i = 0; i < 128; ++i) {
                out_head[i] = out_acc[i] / denom;
            }
            if (capture_scores)
                for (size_t pos = 0; pos < seq_len; ++pos)
                    captured_weights[head * seq_len + pos] /= denom;
        }
        if (capture_scores) {
            DIFF_RECORD("Attention_Scores", opId, layerIdx, position, "scaled_scores",
                        captured_scores.data(), (std::vector<int64_t>{16, static_cast<int64_t>(seq_len)}));
            DIFF_RECORD("Attention_Weights", opId, layerIdx, position, "softmax",
                        captured_weights.data(), (std::vector<int64_t>{16, static_cast<int64_t>(seq_len)}));
        }
        
        // DIFF: Record attention output
        DIFF_RECORD("Attention_Output", opId, layerIdx, position, "output", output, {(int64_t)16 * 128});
        
        return true;
    }

 // Input x[2048] -> A projection [576] -> A projection'''

# Replace
content = re.sub(old_pattern, new_function, content, flags=re.DOTALL)

# Write the file
with open(r'F:\rawrxd\tools\rawrxd_modelgenie_ir_executor.cpp', 'w') as f:
    f.write(content)

print("Replacement done")