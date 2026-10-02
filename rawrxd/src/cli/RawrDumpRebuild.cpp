// Rawr dump rebuild implementation
// RawrXD RawrDumpRebuild - Rebuilds model catalog from scratch
//
// RAWRXD_UNSIMULATE_001
//
// This file previously assigned its entire result from literals:
//
//     g_rebuildState.rootsScanned           = 6;    // Example: 6 roots scanned
//     g_rebuildState.filesScanned           = 150;  // Example: 150 files scanned
//     g_rebuildState.ollamaManifestsScanned = 161;  // Example: 161 manifests scanned
//     g_rebuildState.aliasesScanned         = 10;   // Example: 10 aliases scanned
//     g_rebuildState.catalogRebuilt         = true; // unconditional
//     verdict = (catalogRebuilt && filesScanned > 0) ? "PASS" : "FAIL";
//
// Every field was a constant, so the verdict was decided before the first
// filesystem call and no outcome could change it. This is the model-TRUTH
// surface: it is the command that claims to enumerate what models exist, and it
// answered with numbers invented at authoring time. It was compiled into the
// `rawr` target alongside the real catalog authority, which made a fabricated
// catalog and a real one reachable from the same binary.
//
// The real implementation already existed and was already used by
// RawrDumpAuthority (`rawr dump`, `rawr dump --rebuild`):
// rawrxd::models::buildCatalogFromScratch() scans the filesystem, probes GGUF
// headers, classifies, and computes its verdict as
// (modelsDiscovered > 0 && modelsWithPath > 0). This file now delegates to it
// instead of restating it, so there is one implementation and it is the one
// that touches the disk.

#include "cli/RawrDumpRebuild.h"

#include <cstdio>
#include <string>

#include "models/ModelCatalogAuthority.h"

namespace rawrxd::cli {
    namespace {
        struct RawrDumpRebuildState {
            bool entered = false;
            bool oldCatalogUsed = false;
            int rootsScanned = 0;
            int rootsSkippedMissing = 0;
            int filesScanned = 0;
            int ollamaManifestsScanned = 0;
            int aliasesScanned = 0;
            int modelsDiscovered = 0;
            int modelsWithPath = 0;
            bool catalogRebuilt = false;
            std::string verdict = "INVALID";
        };

        RawrDumpRebuildState g_rebuildState;

        void emit(const char* banner) {
            std::printf("[%s]\n", banner);
            std::printf("  RAWRXD_RAWR_DUMP_REBUILD_001=ENTERED\n");
            // OLD_CATALOG_USED is a claim about provenance, and the rebuild
            // genuinely does not read the previous generated catalog. It is
            // stated as a constant because it is a property of the code path,
            // not a measurement -- but it is separated from the counts below
            // for exactly that reason.
            std::printf("  OLD_CATALOG_USED=%d\n", g_rebuildState.oldCatalogUsed ? 1 : 0);
            std::printf("  ROOTS_SCANNED=%d\n", g_rebuildState.rootsScanned);
            std::printf("  ROOTS_SKIPPED_MISSING=%d\n", g_rebuildState.rootsSkippedMissing);
            std::printf("  FILES_SCANNED=%d\n", g_rebuildState.filesScanned);
            std::printf("  OLLAMA_MANIFESTS_SCANNED=%d\n", g_rebuildState.ollamaManifestsScanned);
            std::printf("  ALIASES_SCANNED=%d\n", g_rebuildState.aliasesScanned);
            std::printf("  MODELS_DISCOVERED=%d\n", g_rebuildState.modelsDiscovered);
            std::printf("  MODELS_WITH_PATH=%d\n", g_rebuildState.modelsWithPath);
            std::printf("  CATALOG_REBUILT=%d\n", g_rebuildState.catalogRebuilt ? 1 : 0);
            std::printf("  VERDICT=%s\n", g_rebuildState.verdict.c_str());
        }
    }  // namespace

    // Rebuild dump catalog.
    //
    // Every field below is returned by the scan. None of them is a constant, and
    // the verdict is the scan's own verdict, computed by ModelCatalogAuthority
    // from modelsDiscovered and modelsWithPath.
    void rebuildDumpCatalog() {
        g_rebuildState.entered = true;
        g_rebuildState.oldCatalogUsed = false;

        const rawrxd::models::CatalogStats stats =
            rawrxd::models::buildCatalogFromScratch();

        g_rebuildState.rootsScanned           = stats.rootsScanned;
        g_rebuildState.rootsSkippedMissing    = stats.rootsSkippedMissing;
        g_rebuildState.filesScanned           = stats.ggufFilesScanned;
        g_rebuildState.ollamaManifestsScanned = stats.ollamaManifestsScanned;
        g_rebuildState.aliasesScanned         = stats.aliasesScanned;
        g_rebuildState.modelsDiscovered       = stats.modelsDiscovered;
        g_rebuildState.modelsWithPath         = stats.modelsWithPath;
        g_rebuildState.catalogRebuilt         = true;  // the scan ran; see verdict
        g_rebuildState.verdict                = stats.verdict;

        emit("RawrDumpRebuild");
    }

    // Write rebuild receipt.
    //
    // This repeats the state rather than writing anything new, so it cannot
    // disagree with rebuildDumpCatalog. It prints the same fields in the same
    // place; there is no second source of truth to drift.
    void writeRebuildReceipt() {
        if (!g_rebuildState.entered) {
            // Printing a receipt without having rebuilt would print zeros that
            // look like a measurement. Say the rebuild did not run.
            std::printf("[RawrDumpRebuild] receipt requested without a rebuild\n");
            std::printf("  RAWRXD_RAWR_DUMP_REBUILD_001=NOT_ENTERED\n");
            std::printf("  VERDICT=INVALID\n");
            std::printf("  REASON=rebuildDumpCatalog was not called; there is nothing to report\n");
            return;
        }
        emit("RawrDumpRebuild receipt");
    }
}  // namespace rawrxd::cli
