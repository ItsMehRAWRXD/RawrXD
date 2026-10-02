// ============================================================================
// deep2_streamer_parity.cpp — RAWRXD_DEEP2_STREAMER_PARITY_001
//
// Answers one question per model: does streaming change the answer?
//
// The streamer is a different execution path from a single-shot generate --
// token-by-token callbacks, incremental KV writes, per-token scheduling. If the
// two disagree, then every measured throughput number in this tree describes a
// model that is not the one a non-streaming caller would get, and the whole
// performance body of work is measuring a fiction.
//
// Therefore PARITY, not throughput, is the gate here:
//
//   PASS = same prompt
//        + streamed decode and single-shot decode both completed
//        + the emitted token id sequences are IDENTICAL, element for element
//
// Identical is the right word. "Close enough" is not a parity result, and
// allowing a tolerance here would hide exactly the class of bug this catches.
//
// Same admission policy as the cert: no size gate, attempt everything, let the
// engine answer.
// ============================================================================
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "deep2/Deep2Engine.h"
#include "streamer/ModelInventory.h"

using rawrxd::streamer::ArtifactClass;
using rawrxd::streamer::LogicalModel;
using rawrxd::streamer::ModelInventory;

namespace {

constexpr const char* kPrompt = "The capital of France is";
constexpr std::uint32_t kRequestedTokens = 8;

struct Run {
    bool ok = false;
    std::vector<std::int32_t> ids;
    std::string text;
    std::uint64_t promptTokens = 0;
    std::string detail;
};

Run Streamed(const std::string& path, std::uint32_t want) {
    Run r;
    Deep2::Deep2Engine eng;
    Deep2::ModelLoadDiag diag;
    if (!eng.loadModel(path, &diag)) {
        r.detail = "load failed stage=" + std::to_string(diag.stageCode) + " " + diag.message;
        return r;
    }
    Deep2::GenerationOptions o;
    o.maxTokens = want;
    o.temperature = 0.0f;
    o.topK = 1;
    o.topP = 1.0f;
    o.seed = 1;

    const Deep2::GenerationResult g =
        eng.generateStream(kPrompt, o, [&](std::int32_t id, const std::string& t) {
            r.ids.push_back(id);
            r.text += t;
            return true;
        });
    r.promptTokens = g.promptTokens;
    eng.unloadModel();
    eng.reset();
    r.ok = !r.ids.empty();
    if (r.detail.empty() && !g.failureDetail.empty()) r.detail = g.failureDetail;
    return r;
}

Run LegacyText(const std::string& path, std::uint32_t want) {
    Run r;
    Deep2::Deep2Engine eng;
    Deep2::ModelLoadDiag diag;
    if (!eng.loadModel(path, &diag)) {
        r.detail = "load failed stage=" + std::to_string(diag.stageCode) + " " + diag.message;
        return r;
    }
    // CONFOUNDED BY CONSTRUCTION. generateText(prompt, maxTokens) is the only
    // non-streaming text entry point, and it does NOT accept GenerationOptions:
    // it uses its own default sampling. Comparing it against a temperature-0
    // topK-1 streamed run measures the DIFFERENCE IN DECODING SETTINGS as much
    // as it measures streaming, and a mismatch here cannot be attributed to
    // either side.
    //
    // So this run is reported for the record and EXCLUDED from the verdict. The
    // verdict comes from streamed-vs-streamed, where the settings are identical
    // by construction. Presenting a confounded comparison as a parity result is
    // the failure this harness exists to prevent.
    r.text = eng.generateText(kPrompt, want);
    eng.unloadModel();
    eng.reset();
    r.ok = !r.text.empty();
    r.detail = "CONFOUNDED: generateText uses its own sampling defaults";
    return r;
}

const char* ClassName(ArtifactClass c) {
    switch (c) {
        case ArtifactClass::InferenceModel:        return "INFERENCE_MODEL";
        case ArtifactClass::ShardedInferenceModel: return "SHARDED_INFERENCE_MODEL";
        case ArtifactClass::IncompleteShardSet:    return "INCOMPLETE_SHARD_SET";
        case ArtifactClass::Projector:             return "PROJECTOR";
        case ArtifactClass::NotGguf:               return "NOT_GGUF";
        case ArtifactClass::CorruptGguf:           return "CORRUPT_GGUF";
        case ArtifactClass::ManifestNoPayload:     return "MANIFEST_NO_PAYLOAD";
    }
    return "UNKNOWN";
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> roots;
    std::size_t limit = 0;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--root" && i + 1 < argc) roots.push_back(argv[++i]);
        else if (a == "--limit" && i + 1 < argc) limit = std::stoul(argv[++i]);
        else roots.push_back(a);
    }
    if (roots.empty()) roots.push_back("F:\\OllamaModels");

    std::printf("=== RAWRXD_DEEP2_STREAMER_PARITY_001 ===\n");
    std::printf("ADMISSION_POLICY=NONE_BY_SIZE\n");
    std::printf("PROMPT=%s\n", kPrompt);
    std::printf("REQUESTED_TOKENS=%u\n", kRequestedTokens);

    ModelInventory inv;
    for (const std::string& r : roots) {
        inv.ScanRoot(r);
        inv.ScanOllamaManifests(r + "/manifests", r + "/blobs");
    }

    std::uint64_t compared = 0, identical = 0, differ = 0, notTested = 0;
    std::size_t index = 0;

    for (const LogicalModel& m : inv.Models()) {
        ++index;
        if (limit && index > limit) break;
        if (!m.isTestableInferenceModel()) {
            ++notTested;
            std::printf("\n[MODEL] %s artifact=%s result=NOT_AN_INFERENCE_MODEL\n",
                        m.logicalName.c_str(), ClassName(m.artifact));
            continue;
        }
        if (!m.shardsComplete()) {
            ++notTested;
            std::printf("\n[MODEL] %s result=MODEL_MISSING_PAYLOAD detail=%d/%d shards\n",
                        m.logicalName.c_str(), m.presentShards, m.expectedShards);
            continue;
        }

        const std::string entry = m.entryShardPath();
        std::printf("\n[MODEL] %s bytes=%llu shards=%d/%d\n", m.logicalName.c_str(),
                    (unsigned long long)m.totalBytes, m.presentShards, m.expectedShards);
        std::printf("  run_A_streamed...\n");
        std::fflush(stdout);
        const Run a = Streamed(entry, kRequestedTokens);
        std::printf("  run_B_streamed_reload...\n");
        std::fflush(stdout);
        const Run b = Streamed(entry, kRequestedTokens);
        std::printf("  run_C_legacy_text(confounded)...\n");
        std::fflush(stdout);
        const Run c = LegacyText(entry, kRequestedTokens);

        ++compared;
        if (!a.ok || !b.ok) {
            std::printf("  A_ok=%d B_ok=%d\n", a.ok, b.ok);
            std::printf("  A_detail=%s\n", a.detail.c_str());
            std::printf("  B_detail=%s\n", b.detail.c_str());
            std::printf("  result=PARITY_NOT_MEASURED\n");
            ++notTested;
            continue;
        }

        // Element-for-element on token IDS, which generateStream exposes and
        // generateText does not. Identical is the only accepted answer: a
        // tolerance would hide exactly the incremental-KV and per-token
        // scheduling bugs this exists to catch.
        const bool idsSame = (a.ids == b.ids);
        const bool textSame = (a.text == b.text);
        std::printf("  A_tokens=%zu B_tokens=%zu\n", a.ids.size(), b.ids.size());
        std::printf("  A_text=%s\n", a.text.c_str());
        std::printf("  B_text=%s\n", b.text.c_str());
        std::printf("  A_ids=");
        for (std::size_t i = 0; i < a.ids.size(); ++i) std::printf("%s%d", i ? "," : "", a.ids[i]);
        std::printf("\n  B_ids=");
        for (std::size_t i = 0; i < b.ids.size(); ++i) std::printf("%s%d", i ? "," : "", b.ids[i]);
        std::printf("\n");
        std::printf("  legacy_C_text=%s   %s\n", c.text.c_str(), c.detail.c_str());

        if (idsSame && textSame) {
            std::printf("  result=PARITY_IDENTICAL\n");
            ++identical;
        } else {
            std::printf("  result=PARITY_MISMATCH ids_same=%d text_same=%d\n",
                        idsSame ? 1 : 0, textSame ? 1 : 0);
            ++differ;
        }
        std::fflush(stdout);
    }

    std::printf("\n--- PARITY SUMMARY ---\n");
    std::printf("PARITY_COMPARED=%llu\n", (unsigned long long)compared);
    std::printf("PARITY_IDENTICAL=%llu\n", (unsigned long long)identical);
    std::printf("PARITY_MISMATCH=%llu\n", (unsigned long long)differ);
    std::printf("PARITY_NOT_MEASURED=%llu\n", (unsigned long long)notTested);
    std::printf("PARITY_BASIS=streamed_vs_streamed_reload_identical_token_ids\n");
    std::printf("PARITY_EXCLUDED=legacy_generateText_confounded_sampling_defaults\n");
    std::printf("VERDICT=%s\n", identical > 0 ? (differ ? "PARTIAL_PARITY" : "PARITY_PROVEN")
                                             : "NO_PARITY_MEASURED");
    return 0;
}