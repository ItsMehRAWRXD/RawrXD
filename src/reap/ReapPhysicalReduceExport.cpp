#include "reap/ReapPhysicalReduceExport.hpp"

#include <cstdlib>

namespace RawrXD::Reap {

bool TryExportReducedSidecar(const std::string& sourceFirstShard,
                             const std::string& outputDir,
                             uint32_t retainedExperts,
                             uint64_t /*targetBytes*/,
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
    /* Full transformMoEGGUF lives on rawr-reap (ReapMoETransformer). Live
     * --reap stream path stays source-immutable; do not silently rewrite. */
    out.reason =
        "EXPORT_DEFERRED_TO_rawr-reap_transformMoEGGUF;"
        "MANIFEST_PRESENT_BUT_STREAM_PATH_DOES_NOT_REWRITE";
    return false;
}

} // namespace RawrXD::Reap
