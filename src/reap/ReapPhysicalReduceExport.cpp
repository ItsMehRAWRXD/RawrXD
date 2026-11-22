#include "reap/ReapPhysicalReduceExport.hpp"
#include "deep2/ReapMoETransformer.hpp"

#include <cstdlib>

namespace RawrXD::Reap {

bool TryExportReducedSidecar(const std::string& sourceFirstShard,
                             const std::string& outputDir,
                             uint32_t retainedExperts,
                             uint64_t targetBytes,
                             PhysicalExportResult& out) {
    out = {};
    out.status = "NOT_RUN";
    (void)sourceFirstShard;
    if (outputDir.empty()) {
        out.reason = "MISSING_INPUT:RAWR_REAP_EXPORT_DIR";
        return false;
    }
    if (!retainedExperts) {
        out.reason = "EXPORT_RETAINED_ZERO";
        return false;
    }
    const char* manifest = std::getenv("RAWR_REAP_SELECTION_MANIFEST");
    if (!manifest || !manifest[0]) {
        out.reason =
            "MISSING_INPUT:RAWR_REAP_SELECTION_MANIFEST;"
            "transformMoEGGUF_ADMISSION_REQUIRES_AUTHORIZED_MANIFEST;"
            "ORIGINAL_GGUF_INTACT=1;USE_rawr-reap_FOR_SIDECAR";
        return false;
    }
    Deep2::ReapMoETransformRequest request;
    request.sourceFirstShard = sourceFirstShard;
    request.outputDirectory = outputDir;
    request.selectionManifest = manifest;
    request.activeExperts = retainedExperts;
    request.targetSizeBytes = targetBytes;

    // The transformer owns source immutability, manifest validation, physical
    // GGUF writing, shard sizing and post-write reload verification. Propagate
    // its failure rather than reporting a proxy plan as an export.
    const Deep2::ReapMoETransformResult result =
        Deep2::transformMoEGGUF(request);
    out.status = result.success ? "PASS" : "FAIL";
    out.reason = result.success ? "NATIVE_MOE_TRANSFORM_VERIFIED"
                                : result.error;
    out.outputFirstShard = result.outputFirstShard;
    out.outputBytes = result.outputBytes;
    return result.success;
}

} // namespace RawrXD::Reap
