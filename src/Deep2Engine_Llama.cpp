// The Llama forward path.
//
// Llama differs from Phi-3 in three ways that matter to the forward pass:
//
//   - it has separate query, key and value projections, where Phi-3 has one
//     fused matrix,
//   - its key and value matrices are narrower than its query matrix when the
//     model uses grouped-query attention, and
//   - its rotary embedding pairs the two halves of a head, where Phi-3 pairs
//     adjacent elements.
//
// The rotary frequencies are the same set either way. What differs is which
// elements of a head are paired, so the pairing is what has to be
// implemented separately, and getting it wrong produces a model that
// generates fluent nonsense.
//
// The Phi-3 path is untouched: this file adds to it.

#include "Deep2Engine.hpp"

#include "core/HostKvRing.hpp"
#include "core/KvWindowPlan.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {

// Weighted RMSNorm: out = weight * x / sqrt(mean(x^2) + eps).
//
// The same form the Phi-3 path uses. The weight is a separate tensor in
// both architectures, and it is applied to a copy of the stream, never to
// the stream itself.
void rmsNormLlama(float* x, const float* weight, size_t n, float eps) {
    if (n == 0) return;
    double ss = 0.0;
    for (size_t i = 0; i < n; ++i) ss += static_cast<double>(x[i]) * x[i];
    const float inv = 1.0f / std::sqrt(static_cast<float>(ss / n) + eps);
    for (size_t i = 0; i < n; ++i) x[i] = x[i] * inv * weight[i];
}

// Rotary embedding, Llama convention.
//
// The frequency of a pair is 1/theta^(2i/dim), the same set of
// frequencies Phi-3 uses, but the two elements of a pair are the ones half
// a head apart rather than the ones next to each other.
void applyRotaryNeoX(float* v, size_t headDim, size_t position, double theta, double scale) {
    if (headDim < 2) return;
    const size_t half = headDim / 2;
    for (size_t i = 0; i < half; ++i) {
        const double frequency = 1.0 / std::pow(theta, (2.0 * i) / static_cast<double>(headDim));
        const double angle = static_cast<double>(position) * frequency * scale;
        const float s = static_cast<float>(std::sin(angle));
        const float c = static_cast<float>(std::cos(angle));
        const float a = v[i];
        const float b = v[i + half];
        v[i] = a * c - b * s;
        v[i + half] = a * s + b * c;
    }
}

// Grouped-query attention.
//
// The query has numHeads heads; the key and the value have numKVHeads.
// Every groupSize query heads share one key head and one value head, so the
// key head a query head reads is its own divided by the group size.
//
// The key and the value live in the ring, whose row for a position is the
// key and value width, that is numKVHeads * headDim, and not the hidden
// width. That is the difference a grouped-query model makes to the ring
// geometry, and it is the reason the ring's width is a parameter rather
// than the hidden size.
void llamaGroupedAttention(float* out, const float* q, const deep2::HostKvRing& ring,
                           uint32_t layer, uint32_t startLogical, uint32_t count,
                           uint32_t numHeads, uint32_t numKVHeads, uint32_t headDim) {
    std::memset(out, 0, static_cast<size_t>(numHeads) * headDim * sizeof(float));
    if (count == 0 || numKVHeads == 0 || numHeads < numKVHeads) return;

    const uint32_t groupSize = numHeads / numKVHeads;
    const float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    std::vector<float> scores(count);

    for (uint32_t h = 0; h < numHeads; ++h) {
        const uint32_t kvHead = h / groupSize;
        const float* qh = q + (static_cast<size_t>(h) * headDim);

        // Scores against every cached position. The ring holds the keys in
        // half precision, as the device cache does, so they are converted on
        // the way out.
        float maxScore = -std::numeric_limits<float>::infinity();
        for (uint32_t t = 0; t < count; ++t) {
            const uint16_t* kh = ring.keyRow(layer, startLogical + t);
            if (!kh) return;
            kh += static_cast<size_t>(kvHead) * headDim;
            float dotProduct = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                dotProduct += qh[d] * deep2::KvHalfToFloat(kh[d]);
            }
            const float score = dotProduct * scale;
            scores[t] = score;
            if (score > maxScore) maxScore = score;
        }

        // Softmax over the window, with the maximum subtracted out.
        float expSum = 0.0f;
        for (uint32_t t = 0; t < count; ++t) {
            scores[t] = std::exp(scores[t] - maxScore);
            expSum += scores[t];
        }
        const float invExpSum = (expSum > 0.0f) ? (1.0f / expSum) : 0.0f;

        // Weighted sum of the values.
        float* headOut = out + (static_cast<size_t>(h) * headDim);
        for (uint32_t t = 0; t < count; ++t) {
            const uint16_t* vh = ring.valueRow(layer, startLogical + t);
            if (!vh) return;
            vh += static_cast<size_t>(kvHead) * headDim;
            const float weight = scores[t] * invExpSum;
            for (uint32_t d = 0; d < headDim; ++d) {
                headOut[d] += weight * deep2::KvHalfToFloat(vh[d]);
            }
        }
    }
}

}  // namespace

// Place one tensor of a Llama layer on the devices, split by output rows.
bool Deep2Engine::placeLlamaResident(const std::string& name, ResidentProjection& slot,
                                     double& uploadMs, uint32_t& tensorCount) {
    const deep2::TensorEntry* entry = rom.findTensor(name);
    if (!entry) {
        fprintf(stderr, "[Llama] %s not found\n", name.c_str());
        return false;
    }

    try {
        fprintf(stderr, "[PLACE] %s begin\n", name.c_str());
        if (entry->type == deep2::TensorType::Q2_K) {
            if (!uploadResidentQuantWeight(*entry, slot.quant)) {
                fprintf(stderr, "[Llama] Failed to place %s in packed form\n", name.c_str());
                return false;
            }
            slot.packed = true;
            slot.rows = slot.quant.totalRows;
            slot.cols = slot.quant.cols;
            ++tensorCount;
            fprintf(stderr, "[PLACE] %s end\n", name.c_str());
            return true;
        }

        deep2::DequantizedTensor dq;
        if (!dequantTensor(*entry, dq)) {
            fprintf(stderr, "[Llama] Failed to dequantize %s\n", name.c_str());
            return false;
        }
        slot.rows = dq.rows;
        slot.cols = dq.cols;
        const deep2::TensorView view{ deep2::TensorType::F32,
                                      reinterpret_cast<const uint8_t*>(dq.data.data()),
                                      dq.data.size() * sizeof(float),
                                      { dq.rows, dq.cols }, true };
        const bool ok = uploadResidentSplitWeight(view, slot.f32);
        dq.data.clear();
        dq.data.shrink_to_fit();
        ++tensorCount;
        fprintf(stderr, "[PLACE] %s end\n", name.c_str());
        return ok;
    } catch (const std::exception& e) {
        fprintf(stderr, "[Llama] placing %s threw (%s): %s\n",
                name.c_str(), typeid(e).name(), e.what());
        return false;
    } catch (...) {
        fprintf(stderr, "[Llama] placing %s threw a non-standard exception\n", name.c_str());
        return false;
    }
}

// The Llama forward pass.
//
// The token loop is the same shape as the Phi-3 one: every position is
// processed for every layer, and the key and the value of each position go
// into the ring before the attention reads them, so a position always sees
// itself.
bool Deep2Engine::executeLlamaROMForwardImpl(const std::vector<uint32_t>& inputTokens,
                                             std::vector<float>& outputLogits,
                                             std::vector<float>& baselineLogits,
                                             bool forceCpuPath) {
    if (!initialized || !romMode) {
        fprintf(stderr, "[Llama] Engine not initialized or not in ROM mode\n");
        return false;
    }

    const auto& geometry = rom.geometry();
    if (geometry.arch != deep2::ModelArch::Llama) {
        fprintf(stderr, "[Llama] the model is not a Llama architecture\n");
        return false;
    }

    const size_t hiddenDim = geometry.hiddenDim;
    const size_t numLayers = geometry.numLayers;
    const size_t numHeads = geometry.numHeads;
    const size_t numKVHeads = geometry.numKVHeads ? geometry.numKVHeads : numHeads;
    const size_t headDim = hiddenDim / numHeads;
    const size_t vocabSize = geometry.vocabSize;
    const size_t intermediateDim = geometry.intermediateDim;
    const size_t kvWidth = numKVHeads * headDim;

    std::cout << "[Llama] forward pass for " << inputTokens.size() << " tokens"
              << ": layers=" << numLayers << " hidden=" << hiddenDim
              << " heads=" << numHeads << " kvHeads=" << numKVHeads
              << " headDim=" << headDim << " kvWidth=" << kvWidth
              << " vocab=" << vocabSize << " intermediate=" << intermediateDim << "\n" << std::flush;

    if (numHeads == 0 || headDim == 0 || numKVHeads == 0 || numHeads % numKVHeads != 0) {
        fprintf(stderr, "[Llama] the head geometry is not usable: %zu heads, %zu kv heads, head dim %zu\n",
                numHeads, numKVHeads, headDim);
        return false;
    }

    // The token embedding and the final norm are the same tensors the Phi-3
    // path reads, under the same names.
    const deep2::TensorEntry* tokenEmb = rom.findTensor("token_embd.weight");
    if (!tokenEmb) {
        fprintf(stderr, "[Llama] token_embd.weight not found\n");
        return false;
    }
    if (!m_tokenEmbReady) {
        if (!dequantTensor(*tokenEmb, m_tokenEmb)) {
            fprintf(stderr, "[Llama] Failed to dequantize token_embd.weight\n");
            return false;
        }
        m_tokenEmbReady = true;
    }
    if (m_outputNorm.data.empty()) {
        const deep2::TensorEntry* outputNorm = rom.findTensor("output_norm.weight");
        if (!outputNorm) {
            fprintf(stderr, "[Llama] output_norm.weight not found\n");
            return false;
        }
        if (!dequantTensor(*outputNorm, m_outputNorm)) {
            fprintf(stderr, "[Llama] Failed to dequantize output_norm.weight\n");
            return false;
        }
    }

    const double theta = ctx.cfg.ropeThetaGlobal;
    const double scale = ctx.cfg.ropeScaleFactor;

    // The window is chosen from the memory budget rather than from the
    // model's advertised maximum context, the same way the Phi-3 path does
    // it. The key and value width of a grouped-query model is narrower than
    // its hidden width, so the footprint is smaller than the Phi-3 case.
    uint32_t kvWindow = 4096;
    {
        const uint32_t kvHeads = static_cast<uint32_t>(numKVHeads);
        const uint32_t heads = static_cast<uint32_t>(numHeads);
        const uint32_t hd = static_cast<uint32_t>(headDim);
        uint64_t totalVram = 0;
        if (vulkan) {
            for (size_t i = 0; i < vulkan->gpuCount(); ++i) totalVram += vulkan->gpu(i)->vramBytes;
        }
        const uint64_t resident = deep2::KvResidentWeightBytes(
            static_cast<uint32_t>(numLayers), static_cast<uint32_t>(hiddenDim),
            static_cast<uint32_t>(intermediateDim), static_cast<uint32_t>(vocabSize));
        const uint64_t margin = totalVram / 4;
        const uint64_t budget = (totalVram > resident + margin) ? (totalVram - resident - margin) : 0;
        uint32_t chosen = deep2::DetermineSafeContextWindow(
            static_cast<uint32_t>(geometry.maxSeqLen), static_cast<uint32_t>(numLayers),
            kvHeads, hd, deep2::kKvBytesFp16, budget);
        // The reference path keeps a copy of the same window in host memory,
        // so the window also has to fit there.
        const uint64_t hostBudget = 8ull * 1024ull * 1024ull * 1024ull;
        const uint32_t hostWindow = deep2::DetermineSafeContextWindow(
            static_cast<uint32_t>(geometry.maxSeqLen), static_cast<uint32_t>(numLayers),
            kvHeads, hd, deep2::kKvBytesFp16, hostBudget);
        if (hostWindow && hostWindow < chosen) chosen = hostWindow;
        if (chosen) kvWindow = chosen;
        fprintf(stderr, "[KV_WINDOW] advertised=%u budget=%llu GB -> window=%u (fp16, %llu MB)\n",
                static_cast<uint32_t>(geometry.maxSeqLen),
                static_cast<unsigned long long>(budget / (1024ull * 1024ull * 1024ull)),
                kvWindow,
                static_cast<unsigned long long>(deep2::KvWindowBytes(
                    static_cast<uint32_t>(numLayers), kvHeads, hd, deep2::kKvBytesFp16, kvWindow)
                    / (1024ull * 1024ull)));
    }

    // The ring holds the positions this pass actually processes. Reserving
    // the whole window instead costs the key and value width times the
    // window in host memory, and that allocation is what made the Phi-3 run
    // fail intermittently under memory pressure.
    const uint32_t ringWindow = (kvWindow < static_cast<uint32_t>(inputTokens.size()))
                                    ? kvWindow
                                    : static_cast<uint32_t>(inputTokens.size());
    deep2::HostKvRing kvRing;
    kvRing.reset(static_cast<uint32_t>(numLayers), ringWindow, static_cast<uint32_t>(kvWidth));

    // The output projection.
    //
    // Llama 3.2 ties it to the token embedding: there is no output.weight,
    // and the vocabulary projection is the embedding matrix read the other
    // way round. Both uses are the same row-major matrix, so the embedding
    // the input lookup reads is also the head.
    const bool tiedOutput = (rom.findTensor("output.weight") == nullptr);
    const char* outputName = tiedOutput ? "token_embd.weight" : "output.weight";
    if (tiedOutput) {
        fprintf(stderr, "[Llama] the output projection is tied to the token embedding\n");
    }

    // The output projection is placed like the layer weights.
    bool outputResident = false;

    // The resident weights, placed once and then read in place.
    bool resident = !forceCpuPath && vulkanReady && vulkan && vulkan->gpuCount() >= 1;
    std::vector<ResidentLlamaLayer> llamaLayers;
    ResidentProjection outputProj;
    if (resident) {
        llamaLayers.resize(numLayers);
        double uploadMs = 0.0;
        uint32_t tensorCount = 0;
        bool ok = true;
        for (size_t layer = 0; layer < numLayers && ok; ++layer) {
            const std::string prefix = "blk." + std::to_string(layer) + ".";
            ResidentLlamaLayer& lw = llamaLayers[layer];
            lw.ready = placeLlamaResident(prefix + "attn_q.weight", lw.q, uploadMs, tensorCount) &&
                        placeLlamaResident(prefix + "attn_k.weight", lw.k, uploadMs, tensorCount) &&
                        placeLlamaResident(prefix + "attn_v.weight", lw.v, uploadMs, tensorCount) &&
                        placeLlamaResident(prefix + "attn_output.weight", lw.o, uploadMs, tensorCount) &&
                        placeLlamaResident(prefix + "ffn_gate.weight", lw.gate, uploadMs, tensorCount) &&
                        placeLlamaResident(prefix + "ffn_up.weight", lw.up, uploadMs, tensorCount) &&
                        placeLlamaResident(prefix + "ffn_down.weight", lw.down, uploadMs, tensorCount);
            ok = lw.ready;
        }
        if (!ok) {
            fprintf(stderr, "[Llama] the resident placement failed; using the CPU path\n");
            resident = false;
        }
    }

    // A matrix of the layer, on whichever path is running.
    struct Matrix {
        const float* cpu = nullptr;   // dequantized on the host
        const ResidentProjection* resident = nullptr;
    };

    // The layer weights are read on the CPU path and placed on the resident
    // path. The CPU copies are kept for the duration of the pass.
    std::vector<deep2::DequantizedTensor> cpuWeights(static_cast<size_t>(numLayers) * 7);
    auto loadCpu = [&](size_t layer, int which, const std::string& name) -> bool {
        const deep2::TensorEntry* entry = rom.findTensor(name);
        if (!entry) return false;
        return dequantTensor(*entry, cpuWeights[static_cast<size_t>(layer) * 7 + which]);
    };

    if (!resident) {
        for (size_t layer = 0; layer < numLayers; ++layer) {
            const std::string prefix = "blk." + std::to_string(layer) + ".";
            if (!loadCpu(layer, 0, prefix + "attn_q.weight") ||
                !loadCpu(layer, 1, prefix + "attn_k.weight") ||
                !loadCpu(layer, 2, prefix + "attn_v.weight") ||
                !loadCpu(layer, 3, prefix + "attn_output.weight") ||
                !loadCpu(layer, 4, prefix + "ffn_gate.weight") ||
                !loadCpu(layer, 5, prefix + "ffn_up.weight") ||
                !loadCpu(layer, 6, prefix + "ffn_down.weight")) {
                fprintf(stderr, "[Llama] Layer %zu is missing a weight\n", layer);
                return false;
            }
        }
    }

    outputLogits.assign(vocabSize, 0.0f);
    baselineLogits.assign(vocabSize, 0.0f);
    std::vector<float> hiddenStates(hiddenDim, 0.0f);

    // A matrix times a vector, on whichever path is running.
    auto matVec = [&](const Matrix& m, const float* x, std::vector<float>& y,
                      uint64_t rows, uint64_t cols) -> bool {
        if (rows == 0 || cols == 0) return false;
        if (m.resident) {
            const deep2::TensorView xView{ deep2::TensorType::F32,
                                           reinterpret_cast<const uint8_t*>(x),
                                           static_cast<uint64_t>(cols) * sizeof(float),
                                           { cols }, true };
            return gemvResidentProjection(*m.resident, xView, y);
        }
        if (!m.cpu) return false;
        y.assign(static_cast<size_t>(rows), 0.0f);
        deep2::gemvFloat(m.cpu, x, y.data(), rows, cols);
        return true;
    };

    for (size_t tokenPos = 0; tokenPos < inputTokens.size(); ++tokenPos) {
        const uint32_t token = inputTokens[tokenPos];
        const uint64_t embRow = (token < m_tokenEmb.cols) ? token : 0;
        std::memcpy(hiddenStates.data(), &m_tokenEmb.data[embRow * hiddenDim],
                    hiddenDim * sizeof(float));

        for (size_t layer = 0; layer < numLayers; ++layer) {
            const size_t slot = layer * 7;
            Matrix q, k, v, o, gate, up, down;
            if (resident) {
                const ResidentLlamaLayer& lw = llamaLayers[layer];
                q.resident = &lw.q; k.resident = &lw.k; v.resident = &lw.v;
                o.resident = &lw.o; gate.resident = &lw.gate;
                up.resident = &lw.up; down.resident = &lw.down;
            } else {
                q.cpu = cpuWeights[slot + 0].data.data();
                k.cpu = cpuWeights[slot + 1].data.data();
                v.cpu = cpuWeights[slot + 2].data.data();
                o.cpu = cpuWeights[slot + 3].data.data();
                gate.cpu = cpuWeights[slot + 4].data.data();
                up.cpu = cpuWeights[slot + 5].data.data();
                down.cpu = cpuWeights[slot + 6].data.data();
            }

            // ---- attention ----
            std::vector<float> normIn(hiddenDim, 0.0f);
            std::memcpy(normIn.data(), hiddenStates.data(), hiddenDim * sizeof(float));
            {
                const deep2::TensorEntry* attnNorm =
                    rom.findTensor("blk." + std::to_string(layer) + ".attn_norm.weight");
                if (!attnNorm) {
                    fprintf(stderr, "[Llama] Layer %zu is missing attn_norm.weight\n", layer);
                    return false;
                }
                deep2::DequantizedTensor normDq;
                if (!dequantTensor(*attnNorm, normDq)) {
                    fprintf(stderr, "[Llama] Layer %zu: attn_norm dequant failed\n", layer);
                    return false;
                }
                rmsNormLlama(normIn.data(), normDq.data.data(), hiddenDim, 1e-5f);
            }

            std::vector<float> qVec(static_cast<size_t>(numHeads) * headDim, 0.0f);
            std::vector<float> kVec(kvWidth, 0.0f);
            std::vector<float> vVec(kvWidth, 0.0f);
            if (!matVec(q, normIn.data(), qVec, numHeads * headDim, hiddenDim) ||
                !matVec(k, normIn.data(), kVec, kvWidth, hiddenDim) ||
                !matVec(v, normIn.data(), vVec, kvWidth, hiddenDim)) {
                fprintf(stderr, "[Llama] Layer %zu: the query, key or value projection failed\n", layer);
                return false;
            }

            // Rotary embedding, per head, on the query and the key.
            for (size_t h = 0; h < numHeads; ++h) {
                applyRotaryNeoX(qVec.data() + (h * headDim), headDim, tokenPos, theta, scale);
            }
            for (size_t h = 0; h < numKVHeads; ++h) {
                applyRotaryNeoX(kVec.data() + (h * headDim), headDim, tokenPos, theta, scale);
            }

            // The key and the value of this position go into the ring before
            // the attention reads it, so a position always sees itself.
            kvRing.append(static_cast<uint32_t>(layer), static_cast<uint32_t>(tokenPos),
                          kVec.data(), vVec.data());

            const uint32_t logicalCount = static_cast<uint32_t>(tokenPos) + 1;
            const uint32_t startLogical = deep2::KvWindowStart(logicalCount, ringWindow);
            const uint32_t count = deep2::KvWindowCount(logicalCount, ringWindow);

            std::vector<float> attnOut(hiddenDim, 0.0f);
            llamaGroupedAttention(attnOut.data(), qVec.data(), kvRing,
                                  static_cast<uint32_t>(layer), startLogical, count,
                                  static_cast<uint32_t>(numHeads),
                                  static_cast<uint32_t>(numKVHeads),
                                  static_cast<uint32_t>(headDim));

            // The attention output is projected before it joins the stream.
            std::vector<float> attnProj(hiddenDim, 0.0f);
            if (!matVec(o, attnOut.data(), attnProj, hiddenDim, hiddenDim)) {
                fprintf(stderr, "[Llama] Layer %zu: the attention output projection failed\n", layer);
                return false;
            }
            for (size_t i = 0; i < hiddenDim; ++i) hiddenStates[i] += attnProj[i];

            // ---- feed forward ----
            std::vector<float> ffnIn(hiddenDim, 0.0f);
            std::memcpy(ffnIn.data(), hiddenStates.data(), hiddenDim * sizeof(float));
            {
                const deep2::TensorEntry* ffnNorm =
                    rom.findTensor("blk." + std::to_string(layer) + ".ffn_norm.weight");
                if (!ffnNorm) {
                    fprintf(stderr, "[Llama] Layer %zu is missing ffn_norm.weight\n", layer);
                    return false;
                }
                deep2::DequantizedTensor normDq;
                if (!dequantTensor(*ffnNorm, normDq)) {
                    fprintf(stderr, "[Llama] Layer %zu: ffn_norm dequant failed\n", layer);
                    return false;
                }
                rmsNormLlama(ffnIn.data(), normDq.data.data(), hiddenDim, 1e-5f);
            }

            std::vector<float> gateVec(intermediateDim, 0.0f);
            std::vector<float> upVec(intermediateDim, 0.0f);
            if (!matVec(gate, ffnIn.data(), gateVec, intermediateDim, hiddenDim) ||
                !matVec(up, ffnIn.data(), upVec, intermediateDim, hiddenDim)) {
                fprintf(stderr, "[Llama] Layer %zu: the gate or up projection failed\n", layer);
                return false;
            }
            // SwiGLU: silu(gate) * up.
            for (size_t i = 0; i < intermediateDim; ++i) {
                const float g = gateVec[i];
                gateVec[i] = (g / (1.0f + std::exp(-g))) * upVec[i];
            }

            std::vector<float> ffnOut(hiddenDim, 0.0f);
            if (!matVec(down, gateVec.data(), ffnOut, hiddenDim, intermediateDim)) {
                fprintf(stderr, "[Llama] Layer %zu: the down projection failed\n", layer);
                return false;
            }
            for (size_t i = 0; i < hiddenDim; ++i) hiddenStates[i] += ffnOut[i];
        }

        // ---- final norm and the output projection ----
        {
            std::vector<float> finalNorm(hiddenDim, 0.0f);
            std::memcpy(finalNorm.data(), hiddenStates.data(), hiddenDim * sizeof(float));
            rmsNormLlama(finalNorm.data(), m_outputNorm.data.data(), hiddenDim, 1e-5f);

            std::vector<float> logits(vocabSize, 0.0f);
            bool ok = false;
            if (resident && outputResident) {
                const deep2::TensorView xView{ deep2::TensorType::F32,
                                               reinterpret_cast<const uint8_t*>(finalNorm.data()),
                                               hiddenDim * sizeof(float),
                                               { hiddenDim }, true };
                ok = gemvResidentProjection(outputProj, xView, logits);
            }
            if (!ok) {
                logits.assign(vocabSize, 0.0f);
                if (tiedOutput) {
                    // The embedding matrix is the head: the same rows, the same
                    // layout, read the other way round.
                    deep2::gemvFloat(m_tokenEmb.data.data(), finalNorm.data(), logits.data(),
                                     vocabSize, hiddenDim);
                } else {
                    const deep2::TensorEntry* outputEntry = rom.findTensor("output.weight");
                    if (!outputEntry) {
                        fprintf(stderr, "[Llama] output.weight not found\n");
                        return false;
                    }
                    deep2::DequantizedTensor outDq;
                    if (!dequantTensor(*outputEntry, outDq)) {
                        fprintf(stderr, "[Llama] output.weight dequant failed\n");
                        return false;
                    }
                    deep2::gemvFloat(outDq.data.data(), finalNorm.data(), logits.data(),
                                     outDq.rows, outDq.cols);
                }
            }
            outputLogits = logits;
            if (tokenPos == 0) baselineLogits = logits;
        }
    }

    // A pass that produced a non-finite logit is a failure, not a result.
    for (float v : outputLogits) {
        if (!std::isfinite(v)) {
            fprintf(stderr, "[Llama] the forward pass produced a non-finite logit\n");
            return false;
        }
    }
    return true;
}

bool Deep2Engine::executeLlamaROMForwardPass(const std::vector<uint32_t>& inputTokens,
                                              std::vector<float>& outputLogits,
                                              std::vector<float>& baselineLogits,
                                              bool forceCpuPath) {
    return executeLlamaROMForwardImpl(inputTokens, outputLogits, baselineLogits, forceCpuPath);
}

// Run the forward pass for whichever architecture the model has.
//
// The Phi-3 path is unchanged. A Llama model takes the Llama path, which
// has its own projections, its own rotary convention and its own head
// mapping.
bool Deep2Engine::executeROMForwardPass(const std::vector<uint32_t>& inputTokens,
                                        std::vector<float>& outputLogits,
                                        std::vector<float>& baselineLogits,
                                        bool forceCpuPath) {
    if (romMode && rom.geometry().arch == deep2::ModelArch::Llama) {
        return executeLlamaROMForwardImpl(inputTokens, outputLogits, baselineLogits, forceCpuPath);
    }
    return executePhi3ROMForwardImpl(inputTokens, outputLogits, baselineLogits,
                                     nullptr, 0, forceCpuPath);
}
