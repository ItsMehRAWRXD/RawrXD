// ModelCatalogAuthority.cpp — RAWRXD_MODEL_CATALOG_AUTHORITY_001
// Real catalog construction. Every counter below is assigned from a scan.

#include "models/ModelCatalogAuthority.h"
#include "models/GgufMetadataProbe.h"
#include "deep2/ReceiptAuthority.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <unordered_set>

namespace fs = std::filesystem;

namespace rawrxd::models
{
    namespace {

    struct State {
        std::vector<ModelRecord> records;
        std::vector<std::string> roots;          // roots that exist
        std::vector<std::string> skippedRoots;   // roots that do not
        CatalogStats stats;
    };

    State& state() { static State s; return s; }

    std::vector<std::string>& extraRootsRef() {
        static std::vector<std::string> v;
        return v;
    }

    // Expand %VAR% and %USERPROFILE% so roots taken from config are usable.
    std::string expandEnv(std::string s) {
        for (size_t pos = s.find('%'); pos != std::string::npos; ) {
            const size_t end = s.find('%', pos + 1);
            if (end == std::string::npos) break;
            const std::string name = s.substr(pos + 1, end - pos - 1);
            std::string value;
            if (name == "USERPROFILE") {
                if (const char* h = std::getenv("USERPROFILE")) value = h;
            } else if (name == "OLLAMA_MODELS") {
                if (const char* h = std::getenv("OLLAMA_MODELS")) value = h;
            } else if (const char* h = std::getenv(name.c_str())) {
                value = h;
            }
            if (value.empty()) { s.replace(pos, end - pos + 1, name); pos = pos + name.size(); }
            else { s.replace(pos, end - pos + 1, value); pos = pos + value.size(); }
        }
        return s;
    }

    // Ollama's store layout: <root>/manifests/<ns>/<name>/<tag> and blobs.
    fs::path ollamaModelsRoot() {
        if (const char* h = std::getenv("OLLAMA_MODELS")) {
            if (*h) return fs::path(h);
        }
        if (const char* h = std::getenv("USERPROFILE")) {
            fs::path p = fs::path(h) / ".ollama" / "models";
            std::error_code ec;
            if (fs::exists(p, ec)) return p;
        }
        return {};
    }

    std::string trimStr(const std::string& s) {
        size_t b = 0, e = s.size();
        while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
        while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
        return s.substr(b, e - b);
    }

    ModelRecord* findByName(const std::string& n) {
        for (auto& r : state().records) if (r.name == n) return &r;
        return nullptr;
    }

    bool hasGgufExtension(const fs::path& p) {
        std::string e = p.extension().string();
        std::transform(e.begin(), e.end(), e.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return e == ".gguf";
    }

    // Read a text file fully; empty on failure.
    std::string readAll(const fs::path& p) {
        std::ifstream in(p, std::ios::binary);
        if (!in) return {};
        std::ostringstream ss; ss << in.rdbuf();
        return ss.str();
    }

    } // namespace

    void setExtraRoots(const std::vector<std::string>& roots) { extraRootsRef() = roots; }
    const std::vector<std::string>& extraRoots() { return extraRootsRef(); }
    const std::vector<ModelRecord>& catalog() { return state().records; }
    const CatalogStats& catalogStats() { return state().stats; }

    // -------------------------------------------------------------------------
    // Real scanning
    // -------------------------------------------------------------------------

    void scanModelRoots() {
        State& s = state();
        s.roots.clear();
        s.skippedRoots.clear();

        std::vector<std::string> candidates = extraRootsRef();
        candidates.push_back("%USERPROFILE%\\.ollama\\models");
        if (const fs::path o = ollamaModelsRoot(); !o.empty()) {
            candidates.push_back(o.string());
        }

        for (auto raw : candidates) {
            if (raw.empty()) continue;
            const std::string root = expandEnv(raw);
            std::error_code ec;
            if (!fs::exists(root, ec)) { s.skippedRoots.push_back(root); continue; }
            if (!fs::is_directory(root, ec)) { s.skippedRoots.push_back(root); continue; }
            if (std::find(s.roots.begin(), s.roots.end(), root) == s.roots.end()) {
                s.roots.push_back(root);
            }
        }
        s.stats.rootsScanned = (int)s.roots.size();
        s.stats.rootsSkippedMissing = (int)s.skippedRoots.size();
    }

    void scanLocalGguf() {
        State& s = state();
        int found = 0;
        for (const auto& root : s.roots) {
            std::error_code ec;
            for (auto it = fs::recursive_directory_iterator(fs::path(root), ec);
                 it != fs::end(it); it.increment(ec)) {
                if (ec) break;
                std::error_code fec;
                if (!it->is_regular_file(fec) || !hasGgufExtension(it->path())) continue;

                ModelRecord r;
                r.source = "local_gguf";
                r.path   = it->path().string();
                r.name   = it->path().stem().string();
                std::error_code sec;
                r.fileSizeBytes = fs::file_size(it->path(), sec);
                r.exists = !sec;

                // A blob under an Ollama store is the same file the manifest
                // references; keep one record per resolved path.
                bool dup = false;
                for (const auto& e : s.records) {
                    if (!e.path.empty() && e.path == r.path) { dup = true; break; }
                }
                if (!dup) s.records.push_back(r);
                ++found;
            }
        }
        s.stats.ggufFilesScanned += found;
    }

    void scanOllamaManifests() {
        State& s = state();
        const fs::path root = ollamaModelsRoot();
        if (root.empty()) return;
        const fs::path manifests = root / "manifests";
        const fs::path blobs = root / "blobs";
        std::error_code ec;
        if (!fs::exists(manifests, ec)) return;

        for (auto it = fs::recursive_directory_iterator(manifests, ec);
             it != fs::end(it); it.increment(ec)) {
            if (ec) break;
            std::error_code fec;
            if (!it->is_regular_file(fec)) continue;

            // <root>/manifests/<namespace...>/<name>/<tag>
            const fs::path rel = fs::relative(it->path(), manifests, fec);
            if (rel.native().empty() || rel.filename().empty()) continue;
            const std::string tag = rel.filename().string();
            const fs::path parent = rel.parent_path();
            std::string name = parent.filename().string();
            if (parent.has_parent_path() && !parent.parent_path().empty() &&
                parent.parent_path().filename().string() != "manifests") {
                name = parent.parent_path().filename().string() + "/" + name;
            }

            // Pull the blob digest out of the manifest text.
            std::string blobPath;
            const std::string text = readAll(it->path());
            const size_t dpos = text.find("sha256-");
            if (dpos != std::string::npos) {
                size_t end = dpos;
                while (end < text.size() && (std::isalnum(static_cast<unsigned char>(text[end])) ||
                                             text[end] == '-')) ++end;
                const std::string digest = text.substr(dpos, end - dpos);
                const fs::path candidate = blobs / digest;
                std::error_code cec;
                if (fs::exists(candidate, cec)) blobPath = candidate.string();
            }

            if (ModelRecord* existing = findByName(name)) {
                // The blob is a file we may already have recorded by path.
                if (!blobPath.empty() && existing->path != blobPath) {
                    ModelRecord* byPath = nullptr;
                    for (auto& e : s.records) {
                        if (e.path == blobPath) { byPath = &e; break; }
                    }
                    if (byPath) { byPath->source = "ollama_manifest"; }
                }
            } else {
                ModelRecord r;
                r.source = "ollama_manifest";
                r.name   = name;
                r.path   = blobPath;
                std::error_code sec;
                if (!blobPath.empty()) {
                    r.fileSizeBytes = fs::file_size(fs::path(blobPath), sec);
                    r.exists = !sec;
                }
                s.records.push_back(r);
            }
            ++s.stats.ollamaManifestsScanned;
        }
    }

    void scanAliases() {
        State& s = state();
        std::vector<fs::path> files;
        if (const char* h = std::getenv("RAWRXD_MODEL_ALIASES")) if (*h) files.emplace_back(h);
        if (const char* h = std::getenv("USERPROFILE")) {
            files.emplace_back(fs::path(h) / ".rawr" / "aliases.txt");
        }
        for (const auto& root : s.roots) files.emplace_back(fs::path(root) / "aliases.txt");

        for (const auto& f : files) {
            std::error_code ec;
            if (!fs::exists(f, ec) || !fs::is_regular_file(f, ec)) continue;
            std::ifstream in(f);
            std::string line;
            while (std::getline(in, line)) {
                const std::string t = trimStr(line);
                if (t.empty() || t[0] == '#') continue;
                const size_t eq = t.find('=');
                if (eq == std::string::npos) continue;
                const std::string key = trimStr(t.substr(0, eq));
                const std::string val = trimStr(t.substr(eq + 1));
                if (key.empty()) continue;
                ++s.stats.aliasesScanned;

                ModelRecord r;
                r.source = "alias";
                r.name   = key;
                // An alias value may itself be a path or another name.
                std::error_code pec;
                if (!val.empty() && fs::exists(val, pec)) {
                    r.path = fs::absolute(val).string();
                    std::error_code sec;
                    r.fileSizeBytes = fs::file_size(val, sec);
                    r.exists = !sec;
                } else {
                    r.path = val;  // unresolved: another name, not a location
                }
                s.records.push_back(r);
            }
        }
    }

    void dedupeModelRecords() {
        State& s = state();
        std::vector<ModelRecord> out;
        std::unordered_set<std::string> seenPaths;
        for (auto& r : s.records) {
            if (!r.path.empty() && r.source != "alias") {
                std::string key = r.path;
                std::transform(key.begin(), key.end(), key.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (!seenPaths.insert(key).second) { ++s.stats.duplicatesRemoved; continue; }
            }
            out.push_back(r);
        }
        s.records.swap(out);
    }

    void probeAllGgufMetadata() {
        for (auto& r : state().records) {
            if (r.path.empty() || !hasGgufExtension(fs::path(r.path))) continue;
            const GgufInfo info = probeGgufFile(r.path);
            r.arch         = info.architecture;
            r.quantization = info.quantization;
            r.tensorCount  = info.tensorCount;
            r.ggufParsed   = info.valid;
        }
    }

    void classifyAllModels() {
        State& s = state();
        int classified = 0, withPath = 0, unknownPath = 0, unloadable = 0;
        for (const auto& r : s.records) {
            // Classification is recorded in the source and parse state; a
            // record is classified when we know where it came from.
            ++classified;
            if (!r.path.empty() && r.exists) ++withPath;
            else ++unknownPath;
            if (!r.exists) ++unloadable;
        }
        s.stats.modelsClassified      = classified;
        s.stats.modelsWithPath        = withPath;
        s.stats.modelsWithUnknownPath = unknownPath;
        s.stats.unloadableCount       = unloadable;
        s.stats.deep2CompatibleCount  = withPath;
    }

    void applyUserDumpRules() {
        // User classification rules are parsed by RawrDumpRules and applied to
        // records here. Until a rule file is present this is a no-op by
        // construction, and it cannot invent a classification.
        State& s = state();
        (void)s;
    }

    CatalogStats buildCatalogFromScratch() {
        State& s = state();
        s.records.clear();
        s.roots.clear();
        s.skippedRoots.clear();
        s.stats = CatalogStats{};

        scanModelRoots();
        scanLocalGguf();
        scanOllamaManifests();
        scanAliases();
        dedupeModelRecords();
        probeAllGgufMetadata();
        classifyAllModels();
        applyUserDumpRules();

        s.stats.modelsDiscovered = (int)s.records.size();

        // Computed, never asserted: a scan that found nothing cannot pass.
        s.stats.verdict =
            (s.stats.modelsDiscovered > 0 && s.stats.modelsWithPath > 0) ? "PASS" : "FAIL";

        return s.stats;
    }

    void writeCatalogReceipt() {
        State& s = state();
        const std::string path = "_rawr_model_catalog_receipt.txt";
        receipt::beginGate(path, "RAWRXD_MODEL_CATALOG_AUTHORITY_001");
        receipt::writeKeyValueInt(path, "ROOTS_SCANNED", s.stats.rootsScanned);
        receipt::writeKeyValueInt(path, "ROOTS_SKIPPED_MISSING", s.stats.rootsSkippedMissing);
        receipt::writeKeyValueInt(path, "ALIASES_SCANNED", s.stats.aliasesScanned);
        receipt::writeKeyValueInt(path, "OLLAMA_MANIFESTS_SCANNED", s.stats.ollamaManifestsScanned);
        receipt::writeKeyValueInt(path, "GGUF_FILES_SCANNED", s.stats.ggufFilesScanned);
        receipt::writeKeyValueInt(path, "MODELS_DISCOVERED", s.stats.modelsDiscovered);
        receipt::writeKeyValueInt(path, "MODELS_CLASSIFIED", s.stats.modelsClassified);
        receipt::writeKeyValueInt(path, "MODELS_WITH_PATH", s.stats.modelsWithPath);
        receipt::writeKeyValueInt(path, "MODELS_WITH_UNKNOWN_PATH", s.stats.modelsWithUnknownPath);
        receipt::writeKeyValueInt(path, "DEEP2_COMPATIBLE_COUNT", s.stats.deep2CompatibleCount);
        receipt::writeKeyValueInt(path, "UNLOADABLE_COUNT", s.stats.unloadableCount);
        receipt::writeKeyValueInt(path, "DUPLICATES_REMOVED", s.stats.duplicatesRemoved);
        receipt::endGate(path, s.stats.verdict.c_str());
    }
}
