// ============================================================================
// reap_convert_cli.cpp -- production REAP MoE conversion driver.
//
// Wraps Deep2::transformMoEGGUF (ReapMoETransformer.cpp) with strict
// argument validation, source integrity checks, disk preflight, and JSON
// receipts. Fail-closed: no source modification, no silent fallback.
//
// Usage:
// REAP conversion driver: wraps Deep2::transformMoEGGUF with validation.
#include "deep2/ReapMoETransformer.hpp"
#include "deep2/GGUFLoader.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static void usage() {
    std::fprintf(stderr,
        "reap_convert_cli --source <first-shard.gguf> --output <dir>\n"
        "  [--experts N] [--target-bytes N] [--manifest <path>] [--dry-run]\n");
}

int main(int argc, char** argv) {
    std::string source, output, manifest;
    uint32_t experts = 0;
    uint64_t targetBytes = 0;
    bool dryRun = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", a.c_str());
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--source")        source = next();
        else if (a == "--output")   output = next();
        else if (a == "--manifest") manifest = next();
        else if (a == "--experts")  experts = static_cast<uint32_t>(std::stoul(next()));
        else if (a == "--target-bytes") targetBytes = std::stoull(next());
        else if (a == "--dry-run")  dryRun = true;
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); usage(); return 2; }
    }

    if (source.empty() || output.empty() || !experts) {
        usage();
        return 2;
    }

    // Phase 1: source integrity check via GGUFLoader (validates all shards).
    Deep2::GGUFLoader loader;
    if (!loader.load(source)) {
        std::fprintf(stderr, "SOURCE_LOAD_FAIL: %s\n", loader.error().c_str());
        return 4;
    }
    std::fprintf(stderr,
        "[reap] source ok: shards=%u tensors=%llu mapped=%llu bytes\n",
        loader.shardCount(),
        static_cast<unsigned long long>(loader.tensorCount()),
        static_cast<unsigned long long>(loader.mappedBytes()));

    if (dryRun) {
        std::printf("{\"status\":\"DRY_RUN_OK\",\"source\":\"%s\",\"shards\":%u,"
                    "\"tensors\":%llu,\"experts\":%u,\"target_bytes\":%llu}\n",
                    source.c_str(), loader.shardCount(),
                    static_cast<unsigned long long>(loader.tensorCount()),
                    experts, static_cast<unsigned long long>(targetBytes));
        return 0;
    }

    // Phase 2: run the real transform.
    Deep2::ReapMoETransformRequest req;
    req.sourceFirstShard = source;
    req.outputDirectory = output;
    req.selectionManifest = manifest;
    req.activeExperts = experts;
    req.targetSizeBytes = targetBytes;

    const Deep2::ReapMoETransformResult r = Deep2::transformMoEGGUF(req);
    std::printf("{\"success\":%s,\"error\":\"%s\",\"output\":\"%s\","
                "\"source_bytes\":%llu,\"output_bytes\":%llu,"
                "\"source_tensors\":%llu,\"output_tensors\":%llu,"
                "\"transformed\":%llu,\"selected_slices\":%llu,"
                "\"source_shards\":%u,\"output_shards\":%u}\n",
                r.success ? "true" : "false",
                r.error.c_str(), r.outputFirstShard.c_str(),
                static_cast<unsigned long long>(r.sourceBytes),
                static_cast<unsigned long long>(r.outputBytes),
                static_cast<unsigned long long>(r.sourceTensors),
                static_cast<unsigned long long>(r.outputTensors),
                static_cast<unsigned long long>(r.transformedTensors),
                static_cast<unsigned long long>(r.selectedExpertSlices),
                r.sourceShardCount, r.outputShardCount);
    return r.success ? 0 : 1;
}