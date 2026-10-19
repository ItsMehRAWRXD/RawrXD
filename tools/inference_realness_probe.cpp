// ============================================================================
// inference_realness_probe.cpp
// ============================================================================
// Proves UltraFastInferenceEngine produces OUTPUT DERIVED FROM MODEL WEIGHTS
// rather than a fabricated constant, and that a missing/corrupt model FAILS
// instead of silently substituting dummy data (which the old code did).
//
// Build:
//   cl /EHsc /std:c++latest /I<repo>/src/inference /I<repo>/src/backend /I<repo>/3rdparty
//      /I<VULKAN_SDK>/Include inference_realness_probe.cpp ultra_fast_inference.cpp
// Run:
//   inference_realness_probe.exe <path-to-gguf-or-float32>

#include "ultra_fast_inference.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace rawrxd::inference;

namespace
{

int g_fail = 0;

void Report(const char* name, bool ok, const std::string& detail)
{
    std::printf("%-34s %s  %s\n", name, ok ? "PASS" : "FAIL", detail.c_str());
    if (!ok)
    {
        ++g_fail;
    }
}

// Build a deterministic pseudo-random float32 blob that is NOT a GGUF file.
bool WriteFloat32Blob(const std::string& path, size_t floats, uint32_t seed)
{
    std::ofstream f(path, std::ios::binary);
    if (!f)
    {
        return false;
    }
    uint32_t s = seed;
    for (size_t i = 0; i < floats; ++i)
    {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        const float v = static_cast<float>(static_cast<int32_t>(s >> 8) - 16777216) / 8388608.0f;
        f.write(reinterpret_cast<const char*>(&v), sizeof(v));
    }
    return true;
}

std::vector<int32_t> RunWith(const std::string& model_path, int max_tokens,
                             uint32_t vocab, uint32_t hidden, float temp)
{
    AutonomousInferenceEngine::InferenceConfig cfg;
    cfg.model_path = model_path;
    cfg.enable_gpu = false;
    cfg.enable_hotpatching = false;
    cfg.enable_streaming_pruning = false;
    cfg.temperature = temp;
    cfg.vocab_size_override = vocab;
    cfg.hidden_size_override = hidden;

    AutonomousInferenceEngine engine(cfg);
    std::vector<int32_t> out;
    engine.infer(std::vector<int32_t>{65, 66, 67}, [&](const std::string& s) {
        out.push_back(std::atoi(s.c_str()));
    }, max_tokens);
    return out;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::printf("usage: inference_realness_probe <model-path>\n");
        return 2;
    }

    const std::string model = argv[1];
    const uint32_t VOCAB = 512;
    const uint32_t HIDDEN = 64;

    // ---- 1. Generated tokens must come from the weights, not a constant -----
    const std::vector<int32_t> a = RunWith(model, 16, VOCAB, HIDDEN, 1.0f);
    Report("produces_tokens", !a.empty(),
           "n=" + std::to_string(a.size()) + " first=" + (a.empty() ? std::string("-")
                                                                    : std::to_string(a[0])));

    bool in_range = true;
    for (int32_t t : a)
    {
        if (t < 0 || t >= static_cast<int32_t>(VOCAB))
        {
            in_range = false;
            break;
        }
    }
    Report("tokens_in_vocab_range", in_range, "ids must be < " + std::to_string(VOCAB));

    // The old implementation returned (prob*32000)%32000 from a single scalar,
    // so every run produced one repeated value. Real sampling varies.
    bool varies = false;
    for (size_t i = 1; i < a.size(); ++i)
    {
        if (a[i] != a[0])
        {
            varies = true;
            break;
        }
    }
    Report("output_varies_across_steps", varies,
           varies ? "tokens differ (sampled)" : "all tokens identical (fabricated)");

    // ---- 2. Determinism: same input + same weights => same output -----------
    const std::vector<int32_t> b = RunWith(model, 16, VOCAB, HIDDEN, 1.0f);
    Report("deterministic_same_input", a == b, "reproducible run");

    // ---- 3. Different weights must change the output -----------------------
    // Generate a small deterministic weight blob rather than copying the model
    // under test, which may be hundreds of gigabytes.
    const std::string alt = "inference_probe_alt.bin";
    if (!WriteFloat32Blob(alt, static_cast<size_t>(VOCAB) * HIDDEN * 2u, 999u))
    {
        Report("alt_weight_blob", false, "could not write");
    }
    const std::vector<int32_t> c = RunWith(alt, 16, VOCAB, HIDDEN, 1.0f);
    Report("output_tracks_weights", a != c,
           a != c ? "different weights -> different tokens" : "output independent of weights");
    std::remove(alt.c_str());

    // ---- 3b. Baseline blob must produce output too -------------------------
    const std::string base = "inference_probe_base.bin";
    if (WriteFloat32Blob(base, static_cast<size_t>(VOCAB) * HIDDEN * 2u, 999u))
    {
        const std::vector<int32_t> d = RunWith(base, 16, VOCAB, HIDDEN, 1.0f);
        Report("float32_blob_accepted", !d.empty(),
               d.empty() ? "flat blob produced nothing" : "n=" + std::to_string(d.size()));
    }
    std::remove(base.c_str());

    // ---- 4. Missing model must NOT yield silent dummy weights --------------
    const std::vector<int32_t> missing = RunWith("definitely_not_a_model_xyz.gguf", 8, VOCAB, HIDDEN, 1.0f);
    Report("missing_model_yields_nothing", missing.empty(),
           missing.empty() ? "no fabricated output"
                           : "produced " + std::to_string(missing.size()) + " tokens from nothing");

    // ---- 5. Corrupt (non-GGUF) file must be rejected -----------------------
    const std::string junk = "inference_probe_junk.bin";
    WriteFloat32Blob(junk, VOCAB * HIDDEN, 12345u);
    const std::vector<int32_t> j = RunWith(junk, 8, VOCAB, HIDDEN, 1.0f);
    Report("non_gguf_rejected", j.empty(), j.empty() ? "refused" : "accepted garbage");
    std::remove(junk.c_str());

    // ---- 6. Temperature must influence sampling ---------------------------
    const std::vector<int32_t> cold = RunWith(model, 16, VOCAB, HIDDEN, 0.05f);
    const std::vector<int32_t> hot = RunWith(model, 16, VOCAB, HIDDEN, 2.0f);
    Report("temperature_is_wired", cold != hot,
           cold != hot ? "low vs high temperature differ" : "temperature ignored");

    std::printf("\n[inference-realness] failures=%d\n", g_fail);
    std::printf("[inference-realness] %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}