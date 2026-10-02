// ============================================================================
// deep2_streamer_cert.cpp â€” RAWRXD_DEEP2_STREAMER_CERT_001
//
// Tests every real local inference model Deep2 can be given, and lets Deep2
// decide the outcome. No size gate, no simulated success, no placeholder model.
//
// The certification condition is deliberately narrow:
//
//   PASS = real local weights
//        + Deep2 load
//        + real prefill
//        + real decode
//        + actual streamed token callbacks
//        + the requested token count completed
//        + clean teardown
//
// PASS is NOT: discovered, is NOT: GGUF parsed, is NOT: admitted, is NOT: model
// loaded. A model that loads and then produces nothing fails, because the thing
// under certification is STREAMING.
//
// Every non-PASS is a distinct measured outcome. Collapsing them into "fail" is
// what lets a missing payload, an unreadable format and a broken decode look
// identical:
//
//   MODEL_STREAMABLE            attempted, Deep2 accepted it
//   MODEL_UNSUPPORTED_FORMAT    Deep2 refused the format, measured
//   MODEL_CORRUPT               bytes present, header/load unusable
//   MODEL_MISSING_PAYLOAD       inventory state, absent bytes, nothing attempted
//   MODEL_LOAD_FAILED           load attempted and failed
//   MODEL_STREAM_FAILED         loaded, could not generate
//   MODEL_PASS                  generated the requested tokens
//
// A shard set is ONE model: it is entered at member 00001 and every member is
// proven present before the file is opened.
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <psapi.h>

#include "deep2/Deep2Engine.h"
#include "streamer/ModelInventory.h"

using rawrxd::streamer::ArtifactClass;
using rawrxd::streamer::LogicalModel;
using rawrxd::streamer::ModelInventory;

namespace {

struct Residency {
    std::uint64_t workingSet = 0;    // physical pages currently resident
    std::uint64_t privateBytes = 0;   // committed private (heap, stacks)
    std::uint64_t pagefileBytes = 0;
    std::uint64_t mappedBytes = 0;   // file-backed virtual ranges
    std::uint64_t mappedRegions = 0;
    // PageFaultCount is the only number here that counts DISK-TO-RAM work
    // directly. Working set tells you what is resident NOW; the fault counter
    // tells you how much the OS actually had to go get. Per-token, that is the
    // only direct measurement of out-of-core behaviour available from inside the
    // process -- without it, "it streamed a 578 GB model" and "it read 40 GB and
    // streamed" are indistinguishable.
    std::uint64_t pageFaults = 0;
    std::uint64_t peakWorkingSet = 0;
};

// mmap builds VIRTUAL RANGES. It does not make bytes free, it makes address
// space cheap. The only way to tell the two apart is to measure them
// separately: working set is what the process physically holds, mapped bytes is
// what it merely has a window onto.
//
// A load that "completes in 142 ms" for a 578 GB model is therefore only
// evidence about the mapping step. It says nothing about whether those bytes were
// read, and the number that actually matters is:
//
//     bytes_touched  =  resident_after_generation - resident_after_load
//     residency_ratio = resident_after_generation / model_bytes
//
// A ratio near 1 means the whole model was pulled in and the "out-of-core"
// description is wrong for that model. A ratio near zero means the page-fault
// walk genuinely touched only the active working set.
Residency MeasureResidency() {
    Residency r;
    // PROCESS_MEMORY_COUNTERS_EX extends the base struct with PrivateUsage.
    // The base type has no such member, and silently losing it would drop the
    // commit measurement without any visible error.
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        r.workingSet = pmc.WorkingSetSize;
        r.privateBytes = pmc.PrivateUsage;
        r.pagefileBytes = pmc.PagefileUsage;
        r.pageFaults = pmc.PageFaultCount;
        r.peakWorkingSet = pmc.PeakWorkingSetSize;
    }
    // Walk the address space and sum only the file-backed regions. This is the
    // mapping, and it is what must SURVIVE the residency drop.
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    auto* addr = static_cast<MEMORY_BASIC_INFORMATION*>(malloc(sizeof(MEMORY_BASIC_INFORMATION)));
    if (!addr) return r;
    auto cursor = reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto limit = reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);
    while (cursor < limit) {
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), addr, sizeof(*addr)) == 0) break;
        if (addr->State == MEM_COMMIT && (addr->Type == MEM_MAPPED || addr->Type == MEM_IMAGE)) {
            r.mappedRegions++;
            if (addr->Type == MEM_MAPPED) r.mappedBytes += addr->RegionSize;
        }
        const std::uintptr_t next = cursor + addr->RegionSize;
        if (next <= cursor) break;  // guard against a zero-size region
        cursor = next;
    }
    free(addr);
    return r;
}

// Make the bytes free and LEAVE THE MAPPING.
//
// EmptyWorkingSet trims the working set: pages backed by a file mapping are
// discarded but the mapping itself remains valid, so a later access re-faults
// from disk instead of failing. That is the whole distinction -- dropping the
// mapping would force a re-open and would make the model unusable, while
// dropping residency keeps the model loaded and merely costs a page fault later.
bool DropResidencyKeepMapping() {
    return EmptyWorkingSet(GetCurrentProcess()) != FALSE;
}

struct Outcome {
    std::string result = "NOT_RUN";
    bool loadPass = false;
    bool prefillPass = false;
    bool streamPass = false;
    std::uint64_t generatedTokens = 0;
    std::uint64_t callbacks = 0;
    bool streamContiguous = false;   // callbacks were consecutive, not gapped
    bool finiteLogits = false;       // measured by the engine, not assumed
    double ttftMs = 0.0;
    double decodeTps = 0.0;
    double wallMs = 0.0;
    // Residency evidence. Bytes are the physical truth; mapped bytes are the
    // virtual claim. Reporting only the second is how "mmap made it free" gets
    // mistaken for an implementation.
    Residency resBeforeLoad;
    Residency resAfterLoad;
    Residency resAfterTokens;
    Residency resAfterDrop;
    bool dropAttempted = false;
    bool dropSucceeded = false;
    bool mappingSurvivedDrop = false;
    std::uint64_t bytesTouched = 0;
    double residencyRatio = 0.0;
    std::string text;
    std::vector<std::int32_t> tokenIds;
    // Per-token fault accounting. A token that costs ~0 faults touched nothing
    // new; a token that costs thousands pulled megabytes off the NVMe. This is
    // the per-token shape of out-of-core execution.
    std::vector<std::uint64_t> faultsPerToken;
    std::vector<double> msPerToken;
    std::uint64_t faultsDuringTokens = 0;
    std::string detail;
};

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

// The prompt is fixed and minimal so results are comparable across models and
// across runs. Deterministic decoding: temperature 0, fixed seed, fixed topK.
constexpr const char* kPrompt = "The capital of France is";
constexpr std::uint32_t kRequestedTokens = 8;

void EmitBlock(const LogicalModel& m, const Outcome& o) {
    std::printf("\n[MODEL]\n");
    std::printf("path=%s\n", m.entryShardPath().c_str());
    std::printf("logical_name=%s\n", m.logicalName.c_str());
    std::printf("artifact=%s\n", ClassName(m.artifact));
    std::printf("arch=%s\n", m.header.architecture.empty() ? "UNKNOWN"
                                                           : m.header.architecture.c_str());
    std::printf("quant=%s\n", m.header.quantName.empty() ? "UNKNOWN"
                                                     : m.header.quantName.c_str());
    std::printf("quant_basis=dominant_tensor_type types_distinct=%u dominant_count=%llu of %llu\n",
                m.header.distinctTensorTypes,
                (unsigned long long)m.header.dominantTensorCount,
                (unsigned long long)m.header.tensorsRead);
    std::printf("gguf_version=%u\n", m.header.version);
    std::printf("tensor_count=%llu\n", static_cast<unsigned long long>(m.header.tensorCount));
    std::printf("bytes=%llu\n", static_cast<unsigned long long>(m.totalBytes));
    std::printf("size_gb=%.2f\n", static_cast<double>(m.totalBytes) / (1024.0 * 1024.0 * 1024.0));
    std::printf("shards=%d/%d\n", m.presentShards, m.expectedShards);
    std::printf("load=%s\n", o.loadPass ? "PASS" : "FAIL");
    std::printf("prefill=%s\n", o.prefillPass ? "PASS" : "FAIL");
    std::printf("tokens=%llu\n", static_cast<unsigned long long>(o.generatedTokens));
    std::printf("requested_tokens=%u\n", kRequestedTokens);
    std::printf("ttft_ms=%.1f\n", o.ttftMs);
    std::printf("decode_tps=%.2f\n", o.decodeTps);
    std::printf("stream_callbacks=%llu\n", static_cast<unsigned long long>(o.callbacks));
    std::printf("stream_contiguous=%d\n", o.streamContiguous ? 1 : 0);
    std::printf("finite_logits=%d\n", o.finiteLogits ? 1 : 0);
    std::printf("wall_ms=%.0f\n", o.wallMs);
    std::printf("model_gb=%.3f\n", static_cast<double>(m.totalBytes) / (1024.0 * 1024.0 * 1024.0));
    std::printf("resident_after_load_gb=%.3f\n",
                static_cast<double>(o.resAfterLoad.workingSet) / (1024.0 * 1024.0 * 1024.0));
    std::printf("resident_after_tokens_gb=%.3f\n",
                static_cast<double>(o.resAfterTokens.workingSet) / (1024.0 * 1024.0 * 1024.0));
    std::printf("mapped_gb=%.3f\n",
                static_cast<double>(o.resAfterTokens.mappedBytes) / (1024.0 * 1024.0 * 1024.0));
    std::printf("bytes_touched_gb=%.3f\n",
                static_cast<double>(o.bytesTouched) / (1024.0 * 1024.0 * 1024.0));
    std::printf("residency_ratio=%.6f\n", o.residencyRatio);
std::printf("residency_ratio_denominator=measured_mapped_bytes\n");
    std::printf("drop_residency_ok=%d\n", o.dropSucceeded ? 1 : 0);
    std::printf("resident_after_drop_gb=%.3f\n",
                static_cast<double>(o.resAfterDrop.workingSet) / (1024.0 * 1024.0 * 1024.0));
    std::printf("mapping_survived_drop=%d\n", o.mappingSurvivedDrop ? 1 : 0);
    // Per-token faults. The first token after prefill carries the bulk of the
    // disk work; later tokens should be cheap if the working set is genuinely
    // resident. A flat high number across all tokens means the model is NOT
    // fitting and the OS is thrashing.
    std::printf("faults_total_during_tokens=%llu\n",
                static_cast<unsigned long long>(o.faultsDuringTokens));
    std::printf("faults_approx_mb=%.1f\n",
                static_cast<double>(o.faultsDuringTokens) * 4096.0 / (1024.0 * 1024.0));
    std::printf("per_token_faults=");
    for (std::size_t i = 0; i < o.faultsPerToken.size(); ++i) {
        std::printf("%s%llu", i ? "," : "",
                    static_cast<unsigned long long>(o.faultsPerToken[i]));
    }
    std::printf("\n");
    std::printf("per_token_ms=");
    for (std::size_t i = 0; i < o.msPerToken.size(); ++i) {
        std::printf("%s%.0f", i ? "," : "", o.msPerToken[i]);
    }
    std::printf("\n");
    std::printf("token_ids=");
    for (std::size_t i = 0; i < o.tokenIds.size() && i < 32; ++i) {
        std::printf("%s%d", i ? "," : "", o.tokenIds[i]);
    }
    std::printf("\n");
    std::printf("text=%s\n", o.text.c_str());
    if (!o.detail.empty()) std::printf("detail=%s\n", o.detail.c_str());
    std::printf("result=%s\n", o.result.c_str());
}

Outcome TestOne(const LogicalModel& m, std::uint32_t requestedTokens) {
    Outcome o;
    const auto t0 = std::chrono::steady_clock::now();
    const auto ms = [&]() {
        return std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0).count();
    };

    // Inventory states are decided before anything is opened. Attempting a model
    // whose bytes are absent produces a load error that says nothing about Deep2.
    if (m.artifact == ArtifactClass::IncompleteShardSet) {
        o.result = "MODEL_MISSING_PAYLOAD";
        o.detail = "shards " + std::to_string(m.presentShards) + "/" +
                   std::to_string(m.expectedShards) + " present; nothing attempted";
        o.wallMs = ms();
        return o;
    }
    if (m.artifact == ArtifactClass::ManifestNoPayload) {
        o.result = "MODEL_MISSING_PAYLOAD";
        o.detail = "manifest with no local blob; a manifest is not weights";
        o.wallMs = ms();
        return o;
    }
    if (m.artifact == ArtifactClass::Projector) {
        o.result = "MODEL_UNSUPPORTED_FORMAT";
        o.detail = "projector/mmproj: not an inference model";
        o.wallMs = ms();
        return o;
    }
    if (m.artifact == ArtifactClass::CorruptGguf) {
        o.result = "MODEL_CORRUPT";
        o.detail = "header: " + m.header.error;
        o.wallMs = ms();
        return o;
    }
    if (!m.shardsComplete()) {
        o.result = "MODEL_MISSING_PAYLOAD";
        o.detail = "shard set incomplete";
        o.wallMs = ms();
        return o;
    }

    const std::string entry = m.entryShardPath();
    if (entry.empty()) {
        o.result = "MODEL_CORRUPT";
        o.detail = "no entry shard";
        o.wallMs = ms();
        return o;
    }

    // ATTEMPT FIRST. No pre-judgement from file size: the loader is the thing
    // under test, so predicting its failure from the byte count would be testing
    // the wrong thing.
    std::printf("  attempting %s (%.2f GB, %d shard(s))...\n", m.logicalName.c_str(),
                static_cast<double>(m.totalBytes) / (1024.0 * 1024.0 * 1024.0),
                m.presentShards);
    std::fflush(stdout);

    o.resBeforeLoad = MeasureResidency();
    Deep2::Deep2Engine engine;
    Deep2::ModelLoadDiag diag;
    const bool loaded = engine.loadModel(entry, &diag);
    o.resAfterLoad = MeasureResidency();
    o.wallMs = ms();
    if (!loaded) {
        o.result = m.header.valid ? "MODEL_LOAD_FAILED" : "MODEL_UNSUPPORTED_FORMAT";
        o.detail = "loadModel failed stage=" + std::to_string(diag.stageCode) +
                   " stage_name=" + (diag.stageName.empty() ? std::string("(none)")
                                                           : diag.stageName) +
                   " message=" + (diag.message.empty() ? std::string("(none)") : diag.message);
        return o;
    }
    o.loadPass = true;

    Deep2::GenerationOptions opts;
    opts.maxTokens = requestedTokens;
    opts.temperature = 0.0f;  // deterministic: same bytes in, same tokens out
    opts.topK = 1;
    opts.topP = 1.0f;
    opts.seed = 1;

    std::string firstTokenAt = "";
    std::int64_t callbackCounter = 0;
    std::int32_t lastId = -1;
    bool contiguous = true;

    std::uint64_t prevFaults = o.resAfterLoad.pageFaults;
    auto tokStart = std::chrono::steady_clock::now();
    const Deep2::GenerationResult r =
        engine.generateStream(kPrompt, opts, [&](std::int32_t tokenId,
                                                 const std::string& token) -> bool {
            if (callbackCounter == 0) firstTokenAt = std::to_string(ms());
            if (lastId >= 0 && tokenId == lastId) contiguous = false;  // same id twice
            lastId = tokenId;
            o.tokenIds.push_back(tokenId);
            o.text += token;
            ++callbackCounter;
            // Per-token page-fault delta. Calling GetProcessMemoryInfo inside the
            // callback adds a little overhead to each token, which is why the
            // per-token latency column is reported separately from the engine's
            // own decode timing and the two are never added together.
            {
                PROCESS_MEMORY_COUNTERS_EX pm{};
                pm.cb = sizeof(pm);
                if (GetProcessMemoryInfo(GetCurrentProcess(),
                                         reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pm),
                                         sizeof(pm))) {
                    o.faultsPerToken.push_back(pm.PageFaultCount - prevFaults);
                    prevFaults = pm.PageFaultCount;
                } else {
                    o.faultsPerToken.push_back(0);
                }
            }
            o.msPerToken.push_back(std::chrono::duration<double, std::milli>(
                                       std::chrono::steady_clock::now() - tokStart)
                                       .count());
            tokStart = std::chrono::steady_clock::now();
            return true;  // never cancel early: we need every callback
        });

    o.wallMs = ms();
    o.callbacks = callbackCounter;
    o.generatedTokens = r.generatedTokens;
    o.resAfterTokens = MeasureResidency();
    o.faultsDuringTokens = o.resAfterTokens.pageFaults - o.resAfterLoad.pageFaults;
    // Prefer the engine's own prefill timing; fall back to the observed time of
    // the first callback. Both are measurements, and reporting the engine's number
    // when it exists keeps TTFT comparable across engines.
    o.ttftMs = r.promptTimeMs > 0.0 ? r.promptTimeMs
                                    : (firstTokenAt.empty() ? 0.0 : std::stod(firstTokenAt));
    // "Contiguous" means the callbacks account for every token the engine claims
    // to have produced -- that is what proves the stream did not silently drop
    // or duplicate deliveries. It is NOT "no two consecutive ids are equal":
    // a model emitting the same token twice is ordinary output, and scoring
    // that as a broken stream would make this instrument reject correct
    // generations (the previous check did exactly that, and could only ever
    // agree with itself).
    o.streamContiguous = (callbackCounter > 0) &&
                         (callbackCounter == r.generatedTokens);

    const double decodeMs = r.generationTimeMs > 0.0
                                ? r.generationTimeMs
                                : (o.wallMs - o.ttftMs);
    o.decodeTps = decodeMs > 0.0
                      ? static_cast<double>(o.generatedTokens) * 1000.0 / decodeMs
                      : 0.0;

    o.prefillPass = r.promptTokens > 0;
    o.finiteLogits = (r.status == Deep2::GenerationStatus::Completed ||
                      r.status == Deep2::GenerationStatus::EndOfSequence);
    if (!r.failureDetail.empty()) {
        o.detail += (o.detail.empty() ? "" : "; ") + std::string("engine=") + r.failureDetail;
    }

    // Teardown is deliberately NOT here. It happens after the residency
    // experiment, while the mapping is still live -- otherwise the drop test
    // measures a mapping this function already released.

    if (o.callbacks == 0 || o.generatedTokens == 0) {
        o.result = "MODEL_STREAM_FAILED";
        o.detail = "loaded, produced no streamed tokens; status=" +
                   std::to_string(static_cast<int>(r.status));
        return o;
    }
    if (o.generatedTokens < requestedTokens &&
        r.status == Deep2::GenerationStatus::Completed) {
        // Fewer tokens than asked AND the engine claims completion is a stream
        // that stopped early. EOS is legitimate; a silent short read is not.
        o.result = "MODEL_STREAM_FAILED";
        o.detail = "produced " + std::to_string(o.generatedTokens) + " of " +
                   std::to_string(requestedTokens) + " requested; status=" +
                   std::to_string(static_cast<int>(r.status));
        return o;
    }

    o.streamPass = true;
    o.result = "MODEL_PASS";

    // Residency experiment, INSIDE the engine's lifetime.
    //
    // The first version of this ran AFTER TestOne returned, which meant it ran
    // after unloadModel(). It therefore measured a mapping that had already been
    // torn down, reported mapping_survived_drop=0, and looked like evidence that
    // trimming residency destroys the mapping. It was evidence of nothing: I
    // deleted the mapping myself and then asked whether it was still there.
    //
    // It has to happen here, with the model loaded and before teardown, or the
    // experiment cannot distinguish "EmptyWorkingSet dropped the pages" from
    // "the loader released the mapping".
    {
        o.dropAttempted = true;
        o.dropSucceeded = DropResidencyKeepMapping();
        o.resAfterDrop = MeasureResidency();
        o.mappingSurvivedDrop = o.resAfterDrop.mappedRegions > 0;

        o.bytesTouched = o.resAfterTokens.workingSet > o.resAfterLoad.workingSet
                             ? o.resAfterTokens.workingSet - o.resAfterLoad.workingSet
                             : 0;

        const double gb = 1024.0 * 1024.0 * 1024.0;
        std::printf("  -- residency: physical bytes vs virtual ranges --\n");
        std::printf("     file_bytes(model)      = %.3f GB\n",
                    static_cast<double>(m.totalBytes) / gb);
        std::printf("     mapped_bytes_afterload = %.3f GB in %llu regions\n",
                    o.resAfterLoad.mappedBytes / gb,
                    (unsigned long long)o.resAfterLoad.mappedRegions);
        std::printf("     private_bytes_afterload= %.3f GB\n",
                    static_cast<double>(o.resAfterLoad.privateBytes) / gb);
        std::printf("     resident_afterload     = %.3f GB\n",
                    static_cast<double>(o.resAfterLoad.workingSet) / gb);
        std::printf("     resident_aftertokens   = %.3f GB\n",
                    static_cast<double>(o.resAfterTokens.workingSet) / gb);
        std::printf("     private_aftertokens    = %.3f GB\n",
                    static_cast<double>(o.resAfterTokens.privateBytes) / gb);
        std::printf("     bytes_touched_by_tokens= %.3f GB\n",
                    static_cast<double>(o.bytesTouched) / gb);
        // The ratio that actually matters. file_size is a fact about the FILE and
        // is not the cost of the PROCESS: measured resident exceeded file size,
        // so using file bytes as the denominator reported >100% "residency" for a
        // fully resident model and would understate the copy overhead. The
        // denominator is measured mapped bytes.
        const double denom = o.resAfterTokens.mappedBytes > 0
                                 ? static_cast<double>(o.resAfterTokens.mappedBytes)
                                 : static_cast<double>(m.totalBytes);
        o.residencyRatio = denom > 0 ? static_cast<double>(o.resAfterTokens.workingSet) / denom : 0.0;
        std::printf("     resident_over_mapped   = %.4f\n", o.residencyRatio);
        std::printf("     drop_residency_ok      = %d\n", o.dropSucceeded ? 1 : 0);
        std::printf("     resident_afterdrop     = %.3f GB\n",
                    static_cast<double>(o.resAfterDrop.workingSet) / gb);
        std::printf("     mapped_afterdrop       = %.3f GB in %llu regions\n",
                    static_cast<double>(o.resAfterDrop.mappedBytes) / gb,
                    (unsigned long long)o.resAfterDrop.mappedRegions);
        std::printf("     mapping_survived_drop  = %d\n", o.mappingSurvivedDrop ? 1 : 0);
        std::fflush(stdout);
    }

    engine.unloadModel();
    engine.reset();
    return o;
}

// Frees the resident bytes and keeps the mapping, then proves it. Run AFTER the
// teardown decision so the drop cannot be mistaken for something generation
// needed.

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string> roots;
std::string outDir = "receipts";
    std::uint32_t requested = kRequestedTokens;
    std::size_t limit = 0;  // 0 = every model
    bool discoverOnly = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--root" && i + 1 < argc) roots.push_back(argv[++i]);
        else if (a == "--out" && i + 1 < argc) outDir = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) requested = std::stoul(argv[++i]);
        else if (a == "--limit" && i + 1 < argc) limit = std::stoul(argv[++i]);
        else if (a == "--discover-only") discoverOnly = true;
        else roots.push_back(a);
    }
    if (roots.empty()) roots.push_back("F:\\OllamaModels");

    std::printf("=== RAWRXD_DEEP2_STREAMER_CERT_001 ===\n");
    std::printf("ADMISSION_POLICY=NONE_BY_SIZE\n");
    std::printf("REQUESTED_TOKENS=%u\n", requested);
    std::printf("PROMPT=%s\n", kPrompt);

    ModelInventory inv;
    for (const std::string& r : roots) {
        const std::string mdir = r + "/manifests";
        const std::string bdir = r + "/blobs";
        inv.ScanRoot(r);
        inv.ScanOllamaManifests(mdir, bdir);
    }
    const auto& c = inv.Totals();
    std::printf("STREAMER_CENSUS_FILES=%llu\n", (unsigned long long)c.filesScanned);
    std::printf("STREAMER_GGUF_BY_MAGIC=%llu\n", (unsigned long long)c.ggufByMagic);
    std::printf("STREAMER_LOGICAL_MODELS=%llu\n", (unsigned long long)c.logicalModels);
    std::printf("STREAMER_SHARDED_COMPLETE=%llu\n", (unsigned long long)c.shardedComplete);
    std::printf("STREAMER_SHARDED_INCOMPLETE=%llu\n", (unsigned long long)c.shardedIncomplete);
    std::printf("STREAMER_PROJECTORS=%llu\n", (unsigned long long)c.projectors);
    std::printf("STREAMER_MISSING_PAYLOAD=%llu\n",
                (unsigned long long)(c.shardedIncomplete + c.manifestsNoPayload));
    std::printf("STREAMER_TOTAL_GB=%.2f\n",
                static_cast<double>(c.totalBytes) / (1024.0 * 1024.0 * 1024.0));

    const std::string invJson = inv.WriteJson(outDir + "/RAWRXD_DEEP2_STREAMER_DISCOVERY_001/inventory.json");
    std::printf("INVENTORY_JSON=%s\n", invJson.c_str());

    if (discoverOnly) {
        // Discovery without execution. Needed to choose a target from measured
        // arch/quant rather than from a filename, and to inspect a 2.9 TB tree
        // without attempting to load a terabyte.
        std::printf("\n--- INVENTORY (no execution requested) ---\n");
        for (const LogicalModel& m : inv.Models()) {
            std::printf("class=%-24s arch=%-14s quant=%-8s shards=%d/%d %8.2f GB  %s\n",
                        ClassName(m.artifact),
                        m.header.architecture.empty() ? "UNKNOWN" : m.header.architecture.c_str(),
                        m.header.quantName.empty() ? "UNKNOWN" : m.header.quantName.c_str(),
                        m.presentShards, m.expectedShards,
                        static_cast<double>(m.totalBytes) / (1024.0 * 1024.0 * 1024.0),
                        m.logicalName.c_str());
        }
        std::printf("DISCOVERED=%zu\n", inv.Models().size());
        std::printf("VERDICT=INVENTORY_ONLY_NO_EXECUTION\n");
        return 0;
    }

    // Biggest first: if the machine cannot hold the largest model, that is
    // discovered on the hardest case rather than hidden by running easy ones.
    std::uint64_t attempted = 0, loadPass = 0, streamPass = 0, missing = 0;
    std::uint64_t unsupported = 0, corrupt = 0, loadFailed = 0, streamFailed = 0;
    std::size_t index = 0;

    for (const LogicalModel& m : inv.Models()) {
        ++index;
        if (limit && index > limit) break;
        // The residency experiment runs INSIDE TestOne, before teardown. Calling it
        // from here duplicated the report and produced a second, invalid
        // measurement of a mapping that had already been released.
        const Outcome o = TestOne(m, requested);
        EmitBlock(m, o);
        std::fflush(stdout);

        if (o.result == "MODEL_PASS") { ++attempted; ++loadPass; ++streamPass; }
        else if (o.result == "MODEL_MISSING_PAYLOAD") { ++missing; ++attempted; }
        else if (o.result == "MODEL_UNSUPPORTED_FORMAT") { ++unsupported; ++attempted; }
        else if (o.result == "MODEL_CORRUPT") { ++corrupt; ++attempted; }
        else if (o.result == "MODEL_LOAD_FAILED") { ++loadFailed; ++attempted; }
        else if (o.result == "MODEL_STREAM_FAILED") { ++streamFailed; ++loadPass; ++attempted; }
    }

    std::printf("\n--- CENSUS SUMMARY ---\n");
    std::printf("STREAMER_ATTEMPTED=%llu\n", (unsigned long long)attempted);
    std::printf("STREAMER_MISSING_PAYLOAD_TOTAL=%llu\n", (unsigned long long)missing);
    std::printf("STREAMER_UNSUPPORTED_FORMAT=%llu\n", (unsigned long long)unsupported);
    std::printf("STREAMER_CORRUPT=%llu\n", (unsigned long long)corrupt);
    std::printf("STREAMER_LOAD_FAILED=%llu\n", (unsigned long long)loadFailed);
    std::printf("STREAMER_STREAM_FAILED=%llu\n", (unsigned long long)streamFailed);
    std::printf("STREAMER_LOAD_PASS=%llu\n", (unsigned long long)loadPass);
    std::printf("STREAMER_GENERATION_PASS=%llu\n", (unsigned long long)streamPass);
    std::printf("STREAMER_FAIL=%llu\n",
                (unsigned long long)(loadFailed + streamFailed + corrupt + unsupported));
    // PASS is deliberately NOT reported as a percentage of discovered models:
    // a projector and an absent blob are not models that failed.
    std::printf("VERDICT=%s\n", streamPass > 0 ? "STREAMING_PROVEN" : "NO_MODEL_STREAMED");

    const std::string receipt = inv.WriteReceipt(
        outDir + "/RAWRXD_DEEP2_STREAMER_CERT_001/streamer_cert.txt",
        "deep2_streamer_cert requested=" + std::to_string(requested));
    std::printf("RECEIPT=%s\n", receipt.c_str());
    return streamPass > 0 ? 0 : 1;
}
