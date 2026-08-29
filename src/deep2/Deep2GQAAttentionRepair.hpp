#pragma once
/*
===============================================================================
 RawrXD Deep2 — GQA Attention Context Repair
 File: src/deep2/Deep2GQAAttentionRepair.hpp

 WHY THIS EXISTS
 ---------------
 A grouped-query-attention model may have:

   hiddenDim   = numHeads   * headDim
   kvDim       = numKVHeads * headDim

 Example from the observed TinyLlama-style trace:

   hiddenDim   = 2048
   Q rows      = 2048
   K/V rows    = 256

 Therefore:

   numHeads / numKVHeads = 8 query heads per KV head

 The raw V projection is ONLY kvDim=256 floats. It MUST NOT be passed directly
 to attn_output.weight, whose input width is hiddenDim=2048.

 Correct path:

   Q: [numHeads,   headDim]
   K: [numKVHeads, headDim]
   V: [numKVHeads, headDim]
                 |
                 v
         causal GQA attention
                 |
                 v
   context: [numHeads, headDim] == hiddenDim floats
                 |
                 v
   attn_output.weight [hiddenDim x hiddenDim]

 At position 0, causal attention contains one key/value position. Softmax is
 exactly 1.0, so:

   context[qHead, :] == V[kvHeadFor(qHead), :]

 This file enforces that invariant and provides the full decode-time GQA
 context implementation.

 It is dependency-free C++20 and does not depend on llama.cpp/Ollama.

 INTEGRATION
 -----------
 Existing Deep2 code likely already computes:
   - attnQ        hiddenDim floats
   - attnK        kvDim floats
   - attnV        kvDim floats
   - RoPE-applied Q/K

 Replace any code that feeds attnV/raw KV-sized storage directly into the
 output projection with:

   GQAConfig cfg{
       hiddenDim,
       numHeads,
       numKVHeads,
       headDim,
       maxSeqLen
   };

   GQAKVCacheView cache{
       keyCachePtr,
       valueCachePtr,
       keyCacheFloatCapacity,
       valueCacheFloatCapacity
   };

   std::vector<float> context(hiddenDim);

   GQAAttentionRepair::decode(
       cfg,
       position,
       ropeQ,          // hiddenDim
       ropeK,          // kvDim
       attnV,          // kvDim
       cache,
       context.data(), // hiddenDim
       hiddenDim
   );

   // THIS is the input to blk.N.attn_output.weight:
   linear(attn_output_weight, context.data(), attnO.data(), hiddenDim);

 IMPORTANT
 ---------
 Do not "fix" this by repeating the entire 256-float V vector 8 times.
 Repetition must occur per KV HEAD mapping:

   qHead  0..7   -> kvHead 0
   qHead  8..15  -> kvHead 1
   qHead 16..23  -> kvHead 2
   qHead 24..31  -> kvHead 3

 and for position > 0 each query head must independently compute attention
 scores across cached K positions before accumulating mapped V slices.

===============================================================================
*/

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace Deep2 {

struct GQAConfig {
    std::size_t hiddenDim = 0;
    std::size_t numHeads = 0;
    std::size_t numKVHeads = 0;
    std::size_t headDim = 0;
    std::size_t maxSeqLen = 0;

    std::size_t kvDim() const noexcept {
        return numKVHeads * headDim;
    }

    std::size_t queryGroupSize() const noexcept {
        return numKVHeads == 0
            ? 0
            : numHeads / numKVHeads;
    }

    void validate() const {
        if (hiddenDim == 0 ||
            numHeads == 0 ||
            numKVHeads == 0 ||
            headDim == 0 ||
            maxSeqLen == 0) {
            throw std::runtime_error(
                "GQA config contains zero dimension");
        }

        if (numHeads * headDim != hiddenDim) {
            throw std::runtime_error(
                "GQA invariant failed: numHeads*headDim != hiddenDim");
        }

        if (numHeads % numKVHeads != 0) {
            throw std::runtime_error(
                "GQA invariant failed: numHeads is not divisible by numKVHeads");
        }

        if (numKVHeads > numHeads) {
            throw std::runtime_error(
                "GQA invariant failed: numKVHeads > numHeads");
        }
    }
};

struct GQAKVCacheView {
    // Layout:
    //   [position][kvHead][headDim]
    //
    // In floats:
    //   position * (numKVHeads*headDim)
    // + kvHead  * headDim
    // + d
    float* keys = nullptr;
    float* values = nullptr;

    std::size_t keyCapacityFloats = 0;
    std::size_t valueCapacityFloats = 0;
};

struct GQADiagnostics {
    std::size_t position = 0;
    std::size_t scoreCount = 0;
    std::size_t queryHeadsProcessed = 0;

    double qL2 = 0.0;
    double currentKL2 = 0.0;
    double currentVL2 = 0.0;
    double contextL2 = 0.0;

    float contextMin = 0.0f;
    float contextMax = 0.0f;

    std::size_t nonFinite = 0;
};

class GQAAttentionRepair final {
public:
    static constexpr float kDefaultEpsilon = 1.0e-20f;

    // Decode one token position.
    //
    // ropeQ:
    //   [numHeads][headDim] = hiddenDim floats
    //
    // ropeK:
    //   [numKVHeads][headDim] = kvDim floats
    //
    // currentV:
    //   [numKVHeads][headDim] = kvDim floats
    //
    // outputContext:
    //   [numHeads][headDim] = hiddenDim floats
    //
    // Causal domain:
    //   cached positions [0, position]
    static GQADiagnostics decode(
        const GQAConfig& cfg,
        std::size_t position,
        const float* ropeQ,
        std::size_t qCount,
        const float* ropeK,
        std::size_t kCount,
        const float* currentV,
        std::size_t vCount,
        GQAKVCacheView cache,
        float* outputContext,
        std::size_t outputCount)
    {
        cfg.validate();

        requirePointer(ropeQ, "ropeQ");
        requirePointer(ropeK, "ropeK");
        requirePointer(currentV, "currentV");
        requirePointer(cache.keys, "KV key cache");
        requirePointer(cache.values, "KV value cache");
        requirePointer(outputContext, "output context");

        if (position >= cfg.maxSeqLen) {
            throw std::runtime_error(
                "GQA position exceeds configured maxSeqLen");
        }

        const std::size_t kvDim = cfg.kvDim();

        if (qCount != cfg.hiddenDim) {
            throw std::runtime_error(
                "GQA Q width mismatch: expected hiddenDim");
        }

        if (kCount != kvDim) {
            throw std::runtime_error(
                "GQA K width mismatch: expected numKVHeads*headDim");
        }

        if (vCount != kvDim) {
            throw std::runtime_error(
                "GQA V width mismatch: expected numKVHeads*headDim");
        }

        if (outputCount != cfg.hiddenDim) {
            throw std::runtime_error(
                "GQA context width mismatch: output MUST equal hiddenDim");
        }

        const std::size_t requiredCacheFloats =
            checkedMul(cfg.maxSeqLen, kvDim);

        if (cache.keyCapacityFloats < requiredCacheFloats) {
            throw std::runtime_error(
                "GQA key cache capacity is too small");
        }

        if (cache.valueCapacityFloats < requiredCacheFloats) {
            throw std::runtime_error(
                "GQA value cache capacity is too small");
        }

        rejectNonFinite(
            ropeQ,
            qCount,
            "GQA Q input");

        rejectNonFinite(
            ropeK,
            kCount,
            "GQA K input");

        rejectNonFinite(
            currentV,
            vCount,
            "GQA V input");

        // Store the RoPE-transformed K and raw/current V at this position.
        //
        // The cache stride is kvDim, NOT hiddenDim.
        float* keyDestination =
            cache.keys +
            checkedMul(position, kvDim);

        float* valueDestination =
            cache.values +
            checkedMul(position, kvDim);

        std::memcpy(
            keyDestination,
            ropeK,
            checkedMul(
                kvDim,
                sizeof(float)));

        std::memcpy(
            valueDestination,
            currentV,
            checkedMul(
                kvDim,
                sizeof(float)));

        std::fill(
            outputContext,
            outputContext + outputCount,
            0.0f);

        const float scale =
            1.0f /
            std::sqrt(
                static_cast<float>(
                    cfg.headDim));

        const std::size_t groupSize =
            cfg.queryGroupSize();

        std::vector<float> scores(
            position + 1);

        std::vector<float> probabilities(
            position + 1);

        for (std::size_t qHead = 0;
             qHead < cfg.numHeads;
             ++qHead) {

            // Standard contiguous GQA head mapping:
            //
            //   kvHead = qHead / (numHeads / numKVHeads)
            //
            // e.g. 32 Q heads / 4 KV heads:
            //   0..7 -> 0
            //   8..15 -> 1
            //   16..23 -> 2
            //   24..31 -> 3
            const std::size_t kvHead =
                qHead / groupSize;

            if (kvHead >= cfg.numKVHeads) {
                throw std::runtime_error(
                    "GQA mapped KV head is out of range");
            }

            const float* q =
                ropeQ +
                checkedMul(
                    qHead,
                    cfg.headDim);

            float* contextHead =
                outputContext +
                checkedMul(
                    qHead,
                    cfg.headDim);

            float maxScore =
                -std::numeric_limits<float>::infinity();

            // Causal attention: only positions <= current position.
            for (std::size_t tokenPos = 0;
                 tokenPos <= position;
                 ++tokenPos) {

                const float* k =
                    keyHead(
                        cfg,
                        cache,
                        tokenPos,
                        kvHead);

                double dot = 0.0;

                for (std::size_t d = 0;
                     d < cfg.headDim;
                     ++d) {

                    dot +=
                        static_cast<double>(q[d]) *
                        static_cast<double>(k[d]);
                }

                const float score =
                    static_cast<float>(
                        dot *
                        static_cast<double>(
                            scale));

                scores[tokenPos] =
                    score;

                maxScore =
                    std::max(
                        maxScore,
                        score);
            }

            // Numerically stable softmax.
            double denominator = 0.0;

            for (std::size_t tokenPos = 0;
                 tokenPos <= position;
                 ++tokenPos) {

                const float exponent =
                    std::exp(
                        scores[tokenPos] -
                        maxScore);

                probabilities[tokenPos] =
                    exponent;

                denominator +=
                    static_cast<double>(
                        exponent);
            }

            if (!std::isfinite(denominator) ||
                denominator <=
                    static_cast<double>(
                        kDefaultEpsilon)) {

                throw std::runtime_error(
                    "GQA softmax denominator is invalid");
            }

            const float inverseDenominator =
                static_cast<float>(
                    1.0 /
                    denominator);

            for (std::size_t tokenPos = 0;
                 tokenPos <= position;
                 ++tokenPos) {

                probabilities[tokenPos] *=
                    inverseDenominator;
            }

            // Weighted V accumulation is written into the QUERY head slot,
            // producing hiddenDim output even though V itself is only kvDim.
            for (std::size_t tokenPos = 0;
                 tokenPos <= position;
                 ++tokenPos) {

                const float probability =
                    probabilities[tokenPos];

                const float* v =
                    valueHead(
                        cfg,
                        cache,
                        tokenPos,
                        kvHead);

                for (std::size_t d = 0;
                     d < cfg.headDim;
                     ++d) {

                    contextHead[d] +=
                        probability *
                        v[d];
                }
            }
        }

        rejectNonFinite(
            outputContext,
            outputCount,
            "GQA output context");

        // The position-0 invariant is exact enough to catch the specific
        // raw-V-versus-hidden-context bug immediately.
        if (position == 0) {
            certifyPositionZero(
                cfg,
                currentV,
                vCount,
                outputContext,
                outputCount);
        }

        return diagnostics(
            cfg,
            position,
            ropeQ,
            qCount,
            ropeK,
            kCount,
            currentV,
            vCount,
            outputContext,
            outputCount);
    }

    // Position 0 has one causal key/value position, therefore softmax=1.
    // Each query head's context MUST exactly copy its mapped KV V head.
    static void certifyPositionZero(
        const GQAConfig& cfg,
        const float* currentV,
        std::size_t vCount,
        const float* context,
        std::size_t contextCount,
        float absTolerance = 1.0e-6f,
        float relTolerance = 1.0e-5f)
    {
        cfg.validate();

        if (!currentV ||
            !context) {
            throw std::runtime_error(
                "GQA position-0 certification received null pointer");
        }

        if (vCount != cfg.kvDim()) {
            throw std::runtime_error(
                "GQA position-0 V count mismatch");
        }

        if (contextCount != cfg.hiddenDim) {
            throw std::runtime_error(
                "GQA position-0 context count mismatch");
        }

        const std::size_t groupSize =
            cfg.queryGroupSize();

        for (std::size_t qHead = 0;
             qHead < cfg.numHeads;
             ++qHead) {

            const std::size_t kvHead =
                qHead / groupSize;

            const float* expected =
                currentV +
                checkedMul(
                    kvHead,
                    cfg.headDim);

            const float* actual =
                context +
                checkedMul(
                    qHead,
                    cfg.headDim);

            for (std::size_t d = 0;
                 d < cfg.headDim;
                 ++d) {

                const float a =
                    actual[d];

                const float b =
                    expected[d];

                const float difference =
                    std::fabs(a - b);

                const float tolerance =
                    absTolerance +
                    relTolerance *
                    std::max(
                        std::fabs(a),
                        std::fabs(b));

                if (difference > tolerance) {
                    throw std::runtime_error(
                        "GQA position-0 invariant failed at qHead=" +
                        std::to_string(qHead) +
                        " kvHead=" +
                        std::to_string(kvHead) +
                        " dim=" +
                        std::to_string(d) +
                        " actual=" +
                        std::to_string(a) +
                        " expected=" +
                        std::to_string(b));
                }
            }
        }
    }

    // Guard immediately before attn_output.weight.
    //
    // Call this even after integrating decode(). It prevents a future path
    // from accidentally feeding kvDim data to a hiddenDim projection.
    static void certifyOutputProjectionInput(
        const GQAConfig& cfg,
        const float* context,
        std::size_t contextCount,
        float maximumReasonableAbs =
            1.0e6f)
    {
        cfg.validate();

        requirePointer(
            context,
            "attention output-projection input");

        if (contextCount !=
            cfg.hiddenDim) {

            throw std::runtime_error(
                "ATTN_O input contract violation: "
                "attn_output.weight requires hiddenDim input; "
                "received " +
                std::to_string(
                    contextCount) +
                ", expected " +
                std::to_string(
                    cfg.hiddenDim) +
                ". Do not pass raw kvDim V into the output projection.");
        }

        for (std::size_t i = 0;
             i < contextCount;
             ++i) {

            if (!std::isfinite(
                    context[i])) {

                throw std::runtime_error(
                    "ATTN_O input contains non-finite value");
            }

            if (std::fabs(
                    context[i]) >
                maximumReasonableAbs) {

                throw std::runtime_error(
                    "ATTN_O input is already numerically explosive before "
                    "the output projection");
            }
        }
    }

    // Diagnostic check immediately after attn_output projection.
    //
    // This does not silently clamp bad activations. It fails loudly.
    static void certifyProjectedAttention(
        const float* context,
        std::size_t contextCount,
        const float* projected,
        std::size_t projectedCount,
        float maximumNormGain = 1.0e4f)
    {
        requirePointer(
            context,
            "attention context");

        requirePointer(
            projected,
            "projected attention");

        rejectNonFinite(
            context,
            contextCount,
            "attention context");

        rejectNonFinite(
            projected,
            projectedCount,
            "projected attention");

        const double inputNorm =
            l2(
                context,
                contextCount);

        const double outputNorm =
            l2(
                projected,
                projectedCount);

        // If the context is exactly zero, a bias-free projection should also
        // be zero. Deep2's common Llama-style attn_output projections are
        // bias-free.
        if (inputNorm == 0.0) {
            if (outputNorm != 0.0) {
                throw std::runtime_error(
                    "ATTN_O produced nonzero output from zero context");
            }

            return;
        }

        const double gain =
            outputNorm /
            inputNorm;

        if (!std::isfinite(gain) ||
            gain >
                static_cast<double>(
                    maximumNormGain)) {

            throw std::runtime_error(
                "ATTN_O norm gain is implausible: inputNorm=" +
                std::to_string(inputNorm) +
                " outputNorm=" +
                std::to_string(outputNorm) +
                " gain=" +
                std::to_string(gain) +
                ". Check GQA context width, buffer lifetime, and matrix input "
                "stride before changing numerical thresholds.");
        }
    }

private:
    static void requirePointer(
        const void* pointer,
        const char* name)
    {
        if (!pointer) {
            throw std::runtime_error(
                std::string(name) +
                " is null");
        }
    }

    static std::size_t checkedMul(
        std::size_t a,
        std::size_t b)
    {
        if (a != 0 &&
            b >
                std::numeric_limits<
                    std::size_t>::max() /
            a) {

            throw std::runtime_error(
                "GQA size multiplication overflow");
        }

        return a * b;
    }

    static const float* keyHead(
        const GQAConfig& cfg,
        const GQAKVCacheView& cache,
        std::size_t position,
        std::size_t kvHead)
    {
        const std::size_t offset =
            checkedMul(
                position,
                cfg.kvDim()) +
            checkedMul(
                kvHead,
                cfg.headDim);

        if (offset >
                cache.keyCapacityFloats ||
            cfg.headDim >
                cache.keyCapacityFloats -
                offset) {

            throw std::runtime_error(
                "GQA key-cache head lookup out of bounds");
        }

        return
            cache.keys +
            offset;
    }

    static const float* valueHead(
        const GQAConfig& cfg,
        const GQAKVCacheView& cache,
        std::size_t position,
        std::size_t kvHead)
    {
        const std::size_t offset =
            checkedMul(
                position,
                cfg.kvDim()) +
            checkedMul(
                kvHead,
                cfg.headDim);

        if (offset >
                cache.valueCapacityFloats ||
            cfg.headDim >
                cache.valueCapacityFloats -
                offset) {

            throw std::runtime_error(
                "GQA value-cache head lookup out of bounds");
        }

        return
            cache.values +
            offset;
    }

    static void rejectNonFinite(
        const float* data,
        std::size_t count,
        const char* label)
    {
        for (std::size_t i = 0;
             i < count;
             ++i) {

            if (!std::isfinite(
                    data[i])) {

                throw std::runtime_error(
                    std::string(label) +
                    " contains a non-finite value at index " +
                    std::to_string(i));
            }
        }
    }

    static double l2(
        const float* data,
        std::size_t count)
    {
        double sum = 0.0;

        for (std::size_t i = 0;
             i < count;
             ++i) {

            const double value =
                static_cast<double>(
                    data[i]);

            sum +=
                value *
                value;
        }

        return
            std::sqrt(sum);
    }

    static GQADiagnostics diagnostics(
        const GQAConfig& cfg,
        std::size_t position,
        const float* q,
        std::size_t qCount,
        const float* k,
        std::size_t kCount,
        const float* v,
        std::size_t vCount,
        const float* context,
        std::size_t contextCount)
    {
        GQADiagnostics d;

        d.position =
            position;

        d.scoreCount =
            cfg.numHeads *
            (position + 1);

        d.queryHeadsProcessed =
            cfg.numHeads;

        d.qL2 =
            l2(q, qCount);

        d.currentKL2 =
            l2(k, kCount);

        d.currentVL2 =
            l2(v, vCount);

        d.contextL2 =
            l2(
                context,
                contextCount);

        if (contextCount != 0) {
            d.contextMin =
                context[0];

            d.contextMax =
                context[0];
        }

        for (std::size_t i = 0;
             i < contextCount;
             ++i) {

            if (!std::isfinite(
                    context[i])) {

                ++d.nonFinite;
            }
            else {
                d.contextMin =
                    std::min(
                        d.contextMin,
                        context[i]);

                d.contextMax =
                    std::max(
                        d.contextMax,
                        context[i]);
            }
        }

        return d;
    }
};

// -----------------------------------------------------------------------------
// Optional self-test
//
// Build one translation unit with:
//   #define RAWRXD_GQA_ATTENTION_SELFTEST
//   #include "Deep2GQAAttentionRepair.hpp"
//
// The test proves:
//   - output width is hiddenDim
//   - position-0 per-head mapping is correct
//   - later-position softmax remains finite
// -----------------------------------------------------------------------------

#ifdef RAWRXD_GQA_ATTENTION_SELFTEST


inline int runGQAAttentionRepairSelfTest()
{
    GQAConfig cfg;

    cfg.hiddenDim = 2048;
    cfg.numHeads = 32;
    cfg.numKVHeads = 4;
    cfg.headDim = 64;
    cfg.maxSeqLen = 4;

    cfg.validate();

    std::vector<float> q(
        cfg.hiddenDim);

    std::vector<float> k(
        cfg.kvDim());

    std::vector<float> v(
        cfg.kvDim());

    for (std::size_t i = 0;
         i < q.size();
         ++i) {

        q[i] =
            static_cast<float>(
                (static_cast<int>(i % 17) - 8) *
                0.01);
    }

    for (std::size_t h = 0;
         h < cfg.numKVHeads;
         ++h) {

        for (std::size_t d = 0;
             d < cfg.headDim;
             ++d) {

            k[h * cfg.headDim + d] =
                static_cast<float>(
                    (h + 1) *
                    0.01 +
                    d *
                    0.0001);

            v[h * cfg.headDim + d] =
                static_cast<float>(
                    h * 10.0 +
                    d *
                    0.01);
        }
    }

    std::vector<float> keyCache(
        cfg.maxSeqLen *
        cfg.kvDim(),
        0.0f);

    std::vector<float> valueCache(
        cfg.maxSeqLen *
        cfg.kvDim(),
        0.0f);

    GQAKVCacheView cache;

    cache.keys =
        keyCache.data();

    cache.values =
        valueCache.data();

    cache.keyCapacityFloats =
        keyCache.size();

    cache.valueCapacityFloats =
        valueCache.size();

    std::vector<float> context(
        cfg.hiddenDim);

    const auto d0 =
        GQAAttentionRepair::decode(
            cfg,
            0,
            q.data(),
            q.size(),
            k.data(),
            k.size(),
            v.data(),
            v.size(),
            cache,
            context.data(),
            context.size());

    GQAAttentionRepair::
        certifyOutputProjectionInput(
            cfg,
            context.data(),
            context.size());

    // Explicit head mapping checks.
    const std::size_t group =
        cfg.queryGroupSize();

    for (std::size_t qHead = 0;
         qHead < cfg.numHeads;
         ++qHead) {

        const std::size_t kvHead =
            qHead / group;

        for (std::size_t d = 0;
             d < cfg.headDim;
             ++d) {

            const float expected =
                v[
                    kvHead *
                    cfg.headDim +
                    d];

            const float actual =
                context[
                    qHead *
                    cfg.headDim +
                    d];

            if (std::fabs(
                    expected -
                    actual) >
                1.0e-6f) {

                std::cerr
                    << "[GQA_SELFTEST_FAIL] "
                    << "qHead="
                    << qHead
                    << " kvHead="
                    << kvHead
                    << " d="
                    << d
                    << " actual="
                    << actual
                    << " expected="
                    << expected
                    << "\n";

                return 1;
            }
        }
    }

    // Position 1 with changed K/V proves the general cached path.
    for (std::size_t i = 0;
         i < k.size();
         ++i) {

        k[i] += 0.025f;
        v[i] += 0.5f;
    }

    const auto d1 =
        GQAAttentionRepair::decode(
            cfg,
            1,
            q.data(),
            q.size(),
            k.data(),
            k.size(),
            v.data(),
            v.size(),
            cache,
            context.data(),
            context.size());

    if (d0.nonFinite != 0 ||
        d1.nonFinite != 0) {

        std::cerr
            << "[GQA_SELFTEST_FAIL] non-finite context\n";

        return 2;
    }

    std::cout
        << "[GQA_SELFTEST_PASS]\n"
        << "hiddenDim="
        << cfg.hiddenDim
        << "\nkvDim="
        << cfg.kvDim()
        << "\nnumHeads="
        cfg.numHeads
        << "\nnumKVHeads="
        << cfg.numKVHeads
        << "\nheadDim="
        << cfg.headDim
        << "\ngroupSize="
        << cfg.queryGroupSize()
        << "\npos0_context_l2="
        << d0.contextL2
        << "\npos1_context_l2="
        << d1.contextL2
        << "\n";

    return 0;
}

#endif // RAWRXD_GQA_ATTENTION_SELFTEST

} // namespace Deep2
