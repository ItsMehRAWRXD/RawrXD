#pragma once

// Model catalog authority - Builds RawrXD's own model catalog.
//
// This authority enumerates the real filesystem. It reports only what it
// actually observed: a root that does not exist is not scanned, a directory
// with no .gguf files contributes zero models, and every counter in the
// receipt is a count of real records.

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::models
{
    // One discovered model. `source` records where it was found so a reader
    // can tell a real scan result from an assumption.
    struct ModelRecord {
        std::string name;             // file stem, alias name, or manifest name
        std::string source;           // local_gguf | ollama_manifest | alias
        std::string path;             // resolved on-disk path, empty if unresolved
        std::string arch;             // from the GGUF header, empty if unread
        std::string quantization;     // from the GGUF header, empty if unread
        uint64_t    fileSizeBytes = 0;
        uint64_t    tensorCount   = 0;
        bool        exists        = false;
        bool        ggufParsed    = false;
    };

    // Counters. Every field is assigned from a real scan.
    struct CatalogStats {
        int rootsScanned           = 0;
        int rootsSkippedMissing    = 0;
        int aliasesScanned         = 0;
        int ollamaManifestsScanned = 0;
        int ggufFilesScanned       = 0;
        int modelsDiscovered       = 0;
        int modelsClassified       = 0;
        int modelsWithPath         = 0;
        int modelsWithUnknownPath  = 0;
        int deep2CompatibleCount   = 0;
        int unloadableCount        = 0;
        int duplicatesRemoved      = 0;
        std::string verdict;        // computed from the fields above
    };

    // Roots used when nothing else is configured. Overridable at runtime via
    // setExtraRoots() so a scan is not tied to a machine's layout.
    void setExtraRoots(const std::vector<std::string>& roots);
    const std::vector<std::string>& extraRoots();

    // Build catalog from scratch. Performs a real scan and assigns every
    // counter in the returned stats from what was found.
    CatalogStats buildCatalogFromScratch();

    // Current catalog, populated by buildCatalogFromScratch().
    const std::vector<ModelRecord>& catalog();
    const CatalogStats& catalogStats();

    // Individual stages, exposed for diagnosis. Each one performs real work.
    void scanModelRoots();
    void scanAliases();
    void scanOllamaManifests();
    void scanLocalGguf();
    void dedupeModelRecords();
    void probeAllGgufMetadata();
    void classifyAllModels();
    void applyUserDumpRules();
    void writeCatalogReceipt();
}
