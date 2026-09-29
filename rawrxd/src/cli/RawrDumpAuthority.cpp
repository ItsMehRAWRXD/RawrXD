// Rawr dump authority implementation
// RawrXD RawrDumpAuthority - First-class model truth command

#include "cli/RawrDumpAuthority.h"
#include "models/ModelCatalogAuthority.h"
#include "models/GgufMetadataProbe.h"
#include "deep2/ReceiptAuthority.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace rawrxd::cli
{
    // Global dump authority state
    struct RawrDumpAuthorityState
    {
        bool entered = false;
        std::string command = "rawr dump";
        bool allModels = false;
        std::string modelName;
        std::string format = "table";
        bool rootsOnly = false;
        bool aliasesOnly = false;
        bool ollamaOnly = false;
        bool ggufOnly = false;
        bool rebuild = false;
        bool initConfig = false;
        std::string configPath;
        std::string outputPath;
        std::vector<std::string> explicitRoots;
        bool generatedFromScratch = false;
        int modelsDiscovered = 0;
        int modelsClassified = 0;
        int modelsWithPath = 0;
        int modelsWithUnknownPath = 0;
        int deep2CompatibleCount = 0;
        int unloadableCount = 0;
        std::string configUsed;
        int rootsScanned = 0;
        int aliasesScanned = 0;
        int ollamaManifestsScanned = 0;
        int ggufFilesScanned = 0;
        std::string verdict = "FAIL";
    };

    // Global state instance
    static RawrDumpAuthorityState g_dumpState;

    // Run rawr dump command
    int runRawrDump(int argc, char* argv[])
    {
        g_dumpState.entered = true;
        
        // Parse arguments
        for (int i = 0; i < argc; i++) {
            std::string arg = argv[i];
            
            if (arg == "--all") {
                g_dumpState.allModels = true;
            } else if (arg == "--format") {
                if (i + 1 < argc) {
                    g_dumpState.format = argv[++i];
                }
            } else if (arg == "--roots") {
                g_dumpState.rootsOnly = true;
            } else if (arg == "--root" && i + 1 < argc) {
                // Explicit roots make the scan reproducible and testable.
                g_dumpState.explicitRoots.push_back(argv[++i]);
            } else if (arg == "--aliases") {
                g_dumpState.aliasesOnly = true;
            } else if (arg == "--ollama") {
                g_dumpState.ollamaOnly = true;
            } else if (arg == "--gguf") {
                g_dumpState.ggufOnly = true;
            } else if (arg == "--rebuild") {
                g_dumpState.rebuild = true;
            } else if (arg == "--init-config") {
                g_dumpState.initConfig = true;
            } else if (arg == "--config") {
                if (i + 1 < argc) {
                    g_dumpState.configPath = argv[++i];
                }
            } else if (arg == "--out") {
                if (i + 1 < argc) {
                    g_dumpState.outputPath = argv[++i];
                }
            } else if (arg.substr(0, 2) != "--") {
                // This is a model name argument
                if (g_dumpState.modelName.empty()) {
                    g_dumpState.modelName = arg;
                }
            }
        }
        
        // Build the catalog for real. Every counter below is copied from what
        // the scan actually found; nothing here is a default or a constant.
        g_dumpState.generatedFromScratch = true;
        rawrxd::models::setExtraRoots(g_dumpState.explicitRoots);
        const rawrxd::models::CatalogStats stats =
            rawrxd::models::buildCatalogFromScratch();

        g_dumpState.modelsDiscovered      = stats.modelsDiscovered;
        g_dumpState.modelsClassified      = stats.modelsClassified;
        g_dumpState.modelsWithPath        = stats.modelsWithPath;
        g_dumpState.modelsWithUnknownPath = stats.modelsWithUnknownPath;
        g_dumpState.deep2CompatibleCount  = stats.deep2CompatibleCount;
        g_dumpState.unloadableCount       = stats.unloadableCount;
        g_dumpState.rootsScanned          = stats.rootsScanned;
        g_dumpState.aliasesScanned        = stats.aliasesScanned;
        g_dumpState.ollamaManifestsScanned= stats.ollamaManifestsScanned;
        g_dumpState.ggufFilesScanned      = stats.ggufFilesScanned;

        // Computed from the scan. A scan that found no resolvable model fails;
        // it cannot be talked into a PASS.
        g_dumpState.verdict = stats.verdict;

        // Output based on format
        if (g_dumpState.format == "json") {
            writeJsonDump();
        } else if (g_dumpState.format == "markdown") {
            writeMarkdownDump();
        } else if (g_dumpState.format == "receipt") {
            writeDumpReceipt();
        } else {
            writeTableDump();
        }

        // One receipt per run. The format branch above writes the receipt
        // itself when receipt format was requested; this is the single
        // authoritative receipt for every other format.
        if (g_dumpState.format != "receipt") {
            writeDumpReceipt();
        }

        return 0;
    }

    // Records the current scan actually produced, filtered by any --all /
    // --roots / --aliases / --ollama / --gguf selector and an optional name.
    static const std::vector<rawrxd::models::ModelRecord>& selectedRecords()
    {
        static std::vector<rawrxd::models::ModelRecord> out;
        out.clear();
        for (const auto& r : rawrxd::models::catalog()) {
            if (!g_dumpState.modelName.empty() && r.name != g_dumpState.modelName) continue;
            if (g_dumpState.rootsOnly   && r.source != "local_gguf") continue;
            if (g_dumpState.aliasesOnly && r.source != "alias") continue;
            if (g_dumpState.ollamaOnly  && r.source != "ollama_manifest") continue;
            if (g_dumpState.ggufOnly    && r.source != "local_gguf") continue;
            if (g_dumpState.allModels && g_dumpState.modelName.empty()) {
                out.push_back(r);
                continue;
            }
            out.push_back(r);
        }
        return out;
    }

    static std::string humanSize(uint64_t bytes) {
        if (bytes == 0) return "-";
        char buf[32];
        if (bytes >= (1ull << 30)) std::snprintf(buf, sizeof buf, "%.2fGB", double(bytes) / double(1ull << 30));
        else if (bytes >= (1ull << 20)) std::snprintf(buf, sizeof buf, "%.1fMB", double(bytes) / double(1ull << 20));
        else std::snprintf(buf, sizeof buf, "%lluB", (unsigned long long)bytes);
        return buf;
    }

    static std::string jsonEscape(const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
            else if (c == '\n') o += "\\n";
            else o.push_back(c);
        }
        return o;
    }

    // Write table format dump
    void writeTableDump()
    {
        const auto& rows = selectedRecords();
        std::printf("Name                  Source          Quant       Size     Path\n");
        std::printf("----                  ------          ----        ----     ----\n");
        if (rows.empty()) {
            std::printf("(no models discovered by this scan)\n");
            return;
        }
        for (const auto& r : rows) {
            std::string p = r.path.empty() ? r.name : r.path;
            if (p.size() > 60) p = p.substr(0, 57) + "...";
            std::printf("%-20s  %-14s  %-10s  %-7s  %s\n",
                        r.name.c_str(), r.source.c_str(),
                        r.quantization.empty() ? "-" : r.quantization.c_str(),
                        humanSize(r.fileSizeBytes).c_str(), p.c_str());
        }
    }

    // Write JSON format dump
    void writeJsonDump()
    {
        const auto& rows = selectedRecords();
        std::printf("{\n");
        std::printf("  \"gate\": \"RAWRXD_RAWR_DUMP_AUTHORITY_001\",\n");
        std::printf("  \"generated_from_scratch\": %s,\n",
                    g_dumpState.generatedFromScratch ? "true" : "false");
        std::printf("  \"model_count\": %d,\n", g_dumpState.modelsDiscovered);
        std::printf("  \"models\": [\n");
        for (size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];
            std::printf("    {\n");
            std::printf("      \"name\": \"%s\",\n", jsonEscape(r.name).c_str());
            std::printf("      \"source\": \"%s\",\n", jsonEscape(r.source).c_str());
            std::printf("      \"resolved_path\": \"%s\",\n", jsonEscape(r.path).c_str());
            std::printf("      \"exists\": %s,\n", r.exists ? "true" : "false");
            std::printf("      \"file_size_bytes\": %llu,\n", (unsigned long long)r.fileSizeBytes);
            std::printf("      \"gguf_parsed\": %s,\n", r.ggufParsed ? "true" : "false");
            std::printf("      \"arch\": \"%s\",\n", jsonEscape(r.arch).c_str());
            std::printf("      \"quantization\": \"%s\",\n", jsonEscape(r.quantization).c_str());
            std::printf("      \"tensor_count\": %llu\n", (unsigned long long)r.tensorCount);
            std::printf("    }%s\n", (i + 1 < rows.size()) ? "," : "");
        }
        std::printf("  ],\n");
        std::printf("  \"verdict\": \"%s\"\n", g_dumpState.verdict.c_str());
        std::printf("}\n");
    }

    // Write markdown format dump
    void writeMarkdownDump()
    {
        const auto& rows = selectedRecords();
        std::printf("| Name | Source | Path | Quant | Size |\n");
        std::printf("|---|---|---|---|---:|\n");
        if (rows.empty()) {
            std::printf("| (none discovered) | | | | |\n");
            return;
        }
        for (const auto& r : rows) {
            std::printf("| %s | %s | %s | %s | %s |\n", r.name.c_str(), r.source.c_str(),
                        r.path.empty() ? "-" : r.path.c_str(),
                        r.quantization.empty() ? "-" : r.quantization.c_str(),
                        humanSize(r.fileSizeBytes).c_str());
        }
    }

    // Write dump receipt
    void writeDumpReceipt()
    {
        // Emit to stdout for interactive use and to a file for the ledger.
        std::printf("[RawrDumpAuthority] dump receipt:\n");
        std::printf("  RAWRXD_RAWR_DUMP_AUTHORITY_001=ENTERED\n");
        std::printf("  COMMAND=%s\n", g_dumpState.command.c_str());
        std::printf("  GENERATED_FROM_SCRATCH=%d\n", g_dumpState.generatedFromScratch ? 1 : 0);
        std::printf("  CONFIG_USED=%s\n", g_dumpState.configUsed.c_str());
        std::printf("  ROOTS_SCANNED=%d\n", g_dumpState.rootsScanned);
        std::printf("  ALIASES_SCANNED=%d\n", g_dumpState.aliasesScanned);
        std::printf("  OLLAMA_MANIFESTS_SCANNED=%d\n", g_dumpState.ollamaManifestsScanned);
        std::printf("  GGUF_FILES_SCANNED=%d\n", g_dumpState.ggufFilesScanned);
        std::printf("  MODELS_DISCOVERED=%d\n", g_dumpState.modelsDiscovered);
        std::printf("  MODELS_CLASSIFIED=%d\n", g_dumpState.modelsClassified);
        std::printf("  MODELS_WITH_PATH=%d\n", g_dumpState.modelsWithPath);
        std::printf("  MODELS_WITH_UNKNOWN_PATH=%d\n", g_dumpState.modelsWithUnknownPath);
        std::printf("  DEEP2_COMPATIBLE_COUNT=%d\n", g_dumpState.deep2CompatibleCount);
        std::printf("  UNLOADABLE_COUNT=%d\n", g_dumpState.unloadableCount);
        std::printf("  OUTPUT_FORMAT=%s\n", g_dumpState.format.c_str());
        std::printf("  OUTPUT_PATH=%s\n", g_dumpState.outputPath.c_str());
        std::printf("  VERDICT=%s\n", g_dumpState.verdict.c_str());

        const std::string path = g_dumpState.outputPath.empty()
            ? std::string("_rawr_dump_receipt.txt")
            : g_dumpState.outputPath;
        rawrxd::receipt::beginGate(path, "RAWRXD_RAWR_DUMP_AUTHORITY_001");
        rawrxd::receipt::writeKeyValue(path, "COMMAND", g_dumpState.command);
        rawrxd::receipt::writeKeyValueInt(path, "GENERATED_FROM_SCRATCH", g_dumpState.generatedFromScratch ? 1 : 0);
        rawrxd::receipt::writeKeyValueInt(path, "ROOTS_SCANNED", g_dumpState.rootsScanned);
        rawrxd::receipt::writeKeyValueInt(path, "ALIASES_SCANNED", g_dumpState.aliasesScanned);
        rawrxd::receipt::writeKeyValueInt(path, "OLLAMA_MANIFESTS_SCANNED", g_dumpState.ollamaManifestsScanned);
        rawrxd::receipt::writeKeyValueInt(path, "GGUF_FILES_SCANNED", g_dumpState.ggufFilesScanned);
        rawrxd::receipt::writeKeyValueInt(path, "MODELS_DISCOVERED", g_dumpState.modelsDiscovered);
        rawrxd::receipt::writeKeyValueInt(path, "MODELS_CLASSIFIED", g_dumpState.modelsClassified);
        rawrxd::receipt::writeKeyValueInt(path, "MODELS_WITH_PATH", g_dumpState.modelsWithPath);
        rawrxd::receipt::writeKeyValueInt(path, "MODELS_WITH_UNKNOWN_PATH", g_dumpState.modelsWithUnknownPath);
        rawrxd::receipt::writeKeyValueInt(path, "DEEP2_COMPATIBLE_COUNT", g_dumpState.deep2CompatibleCount);
        rawrxd::receipt::writeKeyValueInt(path, "UNLOADABLE_COUNT", g_dumpState.unloadableCount);
        rawrxd::receipt::writeKeyValue(path, "OUTPUT_FORMAT", g_dumpState.format);
        rawrxd::receipt::endGate(path, g_dumpState.verdict);
    }
}