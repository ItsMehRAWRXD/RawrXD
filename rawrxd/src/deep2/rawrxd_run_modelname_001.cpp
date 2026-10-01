// rawrxd_run_modelname_001.cpp
// ONE_LOCAL_MODEL_AUTHORITY: resolve model by name or path, load through
// Deep2Engine, stream tokens to stdout, emit receipt to stderr.
#include "rawrxd_run_modelname_001.h"
#include "Deep2Engine.h"
#include "Deep2Diag.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <cstdarg>
#include <exception>
#include <typeinfo>

namespace fs = std::filesystem;

// RAWRXD_RAWR_CLI_RESOLVE_TRACE_001
//
// Resolution walks the filesystem: the Ollama store discovery sweeps drive
// roots, and the search-directory pass recurses without a depth bound. When
// that walk dies, the last thing printed was "MODEL_RESOLUTION: resolving
// 'x'" every single time, so "which stage failed" was unanswerable from the
// output. These checkpoints make the last surviving line the boundary, and the
// terminate handler turns the process-level abort into a named exception.
// Opt-in via RAWRXD_RESOLVE_TRACE=1; a failed resolution still reports its
// outcome without it.
static std::chrono::steady_clock::time_point g_traceT0;
static bool g_traceStarted = false;
static bool g_traceEnabled = false;

static void traceStart() {
    g_traceT0 = std::chrono::steady_clock::now();
    g_traceStarted = true;
    const char* on = std::getenv("RAWRXD_RESOLVE_TRACE");
    g_traceEnabled = on && on[0] && std::strcmp(on, "0") != 0;
}

static void trace(const char* fmt, ...) {
    if (!g_traceStarted || !g_traceEnabled) return;
    const double sec = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - g_traceT0).count();
    char    body[1024];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    std::fprintf(stderr, "[resolve t=%8.3fs] %s\n", sec, body);
    std::fflush(stderr);
}

// An escaped exception terminates the process through abort(), which on this
// CRT surfaces only as a bare 0xC0000409 with no indication of what was
// thrown. Naming it here is the difference between a diagnosis and a code.
static void resolveTerminateHandler() {
    std::fprintf(stderr, "[resolve] UNCAUGHT_EXCEPTION=YES\n");
    if (auto ep = std::current_exception()) {
        try {
            std::rethrow_exception(ep);
        } catch (const std::filesystem::filesystem_error& fe) {
            std::fprintf(stderr, "[resolve] EXCEPTION=std::filesystem::filesystem_error\n"
                                "[resolve] WHAT=%s\n",
                         fe.what());
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[resolve] EXCEPTION=%s\n[resolve] WHAT=%s\n",
                         typeid(e).name(), e.what());
        } catch (...) {
            std::fprintf(stderr, "[resolve] EXCEPTION=unknown-non-std\n");
        }
    }
    std::fflush(stderr);
}

// ---------------------------------------------------------------------------
// Small string helpers
// ---------------------------------------------------------------------------
static std::string trimStr(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}
static std::string toLowerStr(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ---------------------------------------------------------------------------
// Alias resolution
// ---------------------------------------------------------------------------
// Looks up a bare name (e.g. "modelname") in alias files, in priority order:
//   1. $RAWRXD_MODEL_ALIASES (explicit file path)
//   2. %USERPROFILE%\.rawr\aliases.txt
//   3. <RAWRXD_MODEL_DIR>\aliases.txt
// File format (one per line): alias = value   ('#' begins a comment)
// Returns the mapped value (a path or another name), or empty if no match.
static std::string lookupModelAlias(const std::string& name) {
    std::vector<fs::path> aliasFiles;
    if (const char* af = std::getenv("RAWRXD_MODEL_ALIASES"); af && af[0])
        aliasFiles.emplace_back(af);
    if (const char* home = std::getenv("USERPROFILE"); home && home[0])
        aliasFiles.emplace_back(fs::path(home) / ".rawr" / "aliases.txt");
    if (const char* md = std::getenv("RAWRXD_MODEL_DIR"); md && md[0])
        aliasFiles.emplace_back(fs::path(md) / "aliases.txt");

    const std::string want = toLowerStr(trimStr(name));
    if (want.empty()) return {};

    for (const fs::path& af : aliasFiles) {
        std::error_code ec;
        if (!fs::exists(af, ec)) continue;
        std::ifstream in(af.string());
        std::string line;
        while (std::getline(in, line)) {
            const size_t hash = line.find('#');
            if (hash != std::string::npos) line = line.substr(0, hash);
            const size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string k = toLowerStr(trimStr(line.substr(0, eq)));
            const std::string v = trimStr(line.substr(eq + 1));
            if (!k.empty() && k == want && !v.empty()) {
                std::fprintf(stderr, "[rawr run] MODEL_ALIAS: '%s' -> '%s'  (from %s)\n",
                             name.c_str(), v.c_str(), af.string().c_str());
                return v;
            }
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Ollama store resolution  (un-hardcoded model selection)
// ---------------------------------------------------------------------------
// Ollama keeps models under $OLLAMA_MODELS or %USERPROFILE%\.ollama\models,
// with JSON manifests at manifests\registry.ollama.ai\<ns>\<repo>\<tag> that
// reference GGUF blobs at blobs\sha256-<hex>. This lets `rawr run <any ollama
// model>` work for every entry shown by `ollama list`, with no hardcoding.
//
// The store is located by its STRUCTURAL SIGNATURE (a directory containing
// manifests\registry.ollama.ai) rather than by guessing directory names.
// Name-guessing fails on relocated stores: a store at F:\ollama\blobs matches
// none of the conventional names, and the old "first candidate that merely
// exists" fallback silently returned an empty ~/.ollama\models instead,
// masking the real store. A store that is not found must report as not found.
static bool hasOllamaLayout(const fs::path& p) {
    std::error_code ec;
    return !p.empty() && fs::exists(p / "manifests" / "registry.ollama.ai", ec);
}

static fs::path ollamaModelsRoot() {
    std::vector<fs::path> candidates;
    if (const char* om = std::getenv("OLLAMA_MODELS"); om && om[0])
        candidates.emplace_back(om);
    if (const char* rom = std::getenv("RAWRXD_OLLAMA_MODELS"); rom && rom[0])
        candidates.emplace_back(rom);
    if (const char* home = std::getenv("USERPROFILE"); home && home[0])
        candidates.emplace_back(fs::path(home) / ".ollama" / "models");

    // Conventional names first (cheap), for every mounted drive.
    for (char d = 'C'; d <= 'Z'; ++d) {
        const std::string root = std::string(1, d) + ":\\";
        std::error_code dec;
        if (!fs::exists(fs::path(root), dec)) continue;
        candidates.emplace_back(fs::path(root) / "OllamaModels");
        candidates.emplace_back(fs::path(root) / ".ollama" / "models");
        candidates.emplace_back(fs::path(root) / "ollama" / "blobs");
        candidates.emplace_back(fs::path(root) / "ollama");
        candidates.emplace_back(fs::path(root) / "models" / "blobs");
    }
    for (const auto& c : candidates) if (hasOllamaLayout(c)) {
        trace("ollama_store conventional_hit path=%s", c.string().c_str());
        return c;
    }

    // Structural discovery: bounded-depth sweep of each drive root for any
    // directory that actually carries the Ollama manifest layout. This is what
    // makes a relocated store discoverable at all.
    for (char d = 'C'; d <= 'Z'; ++d) {
        const fs::path drive = fs::path(std::string(1, d) + ":\\");
        std::error_code ec;
        if (!fs::exists(drive, ec)) continue;
        trace("ollama_store sweep_drive=%c", d);
        unsigned long long visited = 0;
        for (auto it = fs::recursive_directory_iterator(
                 drive, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (++visited % 20000 == 0) trace("ollama_store drive=%c visited=%llu",
                                             d, visited);
            if (ec) { ec.clear(); continue; }
            if (it.depth() > 3) { it.disable_recursion_pending(); continue; }
            if (!it->is_directory(ec)) continue;
            if (hasOllamaLayout(it->path())) {
                trace("ollama_store structural_hit path=%s", it->path().string().c_str());
                return it->path();
            }
        }
        trace("ollama_store drive=%c exhausted visited=%llu", d, visited);
    }

    // No store found. Reporting an arbitrary existing directory here is what
    // previously made a populated store look empty, so return nothing instead.
    trace("ollama_store not_found");
    return {};
}

// RAWRXD_RAWR_CLI_RESOLVE_BUDGET_001
//
// The fuzzy directory walk below has neither a depth nor a breadth bound, so
// resolving one unrecognised name descended whole source trees. Measured on
// this machine: 116,795 entries under F:\~dev and more than 950,000 under
// G:\~dev for a name that exists in none of them, before the walk died inside
// the filesystem layer. A budget makes that work bounded and reported; it
// cannot silently pass for "searched everywhere and found nothing".
static const unsigned long long kSearchVisitBudget = 400000;
static bool g_searchBudgetExhausted = false;

// Discovery is the same answer for every caller in a process, and the answer
// costs a drive sweep. Compute it once so the search ordering below can use it
// without paying for it a second time.
static const fs::path& ollamaModelsRootCached() {
    static const fs::path cached = ollamaModelsRoot();
    return cached;
}

// Reconstruct an "[ns/]repo:tag" name from a manifest path relative to
// manifests\registry.ollama.ai .
static std::string ollamaNameFromManifestRel(const fs::path& rel) {
    std::vector<std::string> comp;
    for (const auto& c : rel) comp.push_back(c.string());
    if (comp.size() < 2) return {};
    const std::string tag  = comp.back();
    const std::string repo = comp[comp.size() - 2];
    std::string ns;
    for (size_t i = 0; i + 2 < comp.size(); ++i) { if (!ns.empty()) ns += '/'; ns += comp[i]; }
    if (ns.empty() || ns == "library") return repo + ":" + tag;
    return ns + "/" + repo + ":" + tag;
}

// Resolve an Ollama model reference "[ns/]name[:tag]" to its GGUF blob path.
static std::string resolveOllamaModel(const std::string& refIn) {
    const fs::path root = ollamaModelsRootCached();
    if (root.empty()) return {};
    std::error_code ec;
    if (!fs::exists(root, ec)) return {};

    std::string ref = refIn, ns = "library", name, tag = "latest";
    if (const auto slash = ref.find('/'); slash != std::string::npos) {
        ns = ref.substr(0, slash);
        ref = ref.substr(slash + 1);
    }
    if (const auto colon = ref.find(':'); colon != std::string::npos) {
        name = ref.substr(0, colon);
        tag  = ref.substr(colon + 1);
    } else {
        name = ref;
    }
    if (name.empty()) return {};

    const fs::path manifest = root / "manifests" / "registry.ollama.ai" / ns / name / tag;
    if (!fs::exists(manifest, ec)) return {};

    std::ifstream in(manifest.string(), std::ios::binary);
    if (!in) return {};
    const std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    // Find the model layer object and its blob digest.
    const std::string marker = "application/vnd.ollama.image.model";
    const size_t mpos = data.find(marker);
    if (mpos == std::string::npos) return {};
    const size_t objStart = data.rfind('{', mpos);
    const size_t objEnd   = data.find('}', mpos);
    const size_t from = (objStart == std::string::npos) ? 0 : objStart;
    const size_t to   = (objEnd == std::string::npos) ? data.size() : objEnd;
    const std::string obj = data.substr(from, to - from);
    const std::string dkey = "\"digest\":\"";
    size_t dpos = obj.find(dkey);
    if (dpos == std::string::npos) return {};
    dpos += dkey.size();
    const size_t dend = obj.find('"', dpos);
    if (dend == std::string::npos) return {};
    std::string digest = obj.substr(dpos, dend - dpos);   // sha256:hex
    for (char& c : digest) if (c == ':') c = '-';          // blob filename form
    const fs::path blob = root / "blobs" / digest;
    if (fs::exists(blob, ec)) {
        std::fprintf(stderr, "[rawr run] OLLAMA_RESOLVE: '%s' -> %s\n",
                     refIn.c_str(), blob.string().c_str());
        return blob.string();
    }
    return {};
}

// ---------------------------------------------------------------------------
// Model resolution
// ---------------------------------------------------------------------------
// Accepts:
//   - a registered alias (resolved via alias files, see lookupModelAlias)
//   - any Ollama model name from `ollama list` (e.g. "qwen3:8b", "gpt-oss:20b")
//   - absolute path to a .gguf file
//   - relative path to a .gguf file (resolved from cwd)
//   - bare model name: searched in RAWRXD_MODEL_DIR env var, then common dirs
static std::string resolveModelPathImpl(const std::string& nameOrPath) {
    trace("resolve_model enter name=%s", nameOrPath.c_str());
    // Alias first: a matched alias may map directly to an existing file, or to
    // another bare name that continues through the normal search below.
    std::string effective = nameOrPath;
    const std::string aliasVal = lookupModelAlias(nameOrPath);
    if (!aliasVal.empty()) {
        std::error_code ec;
        fs::path ap(aliasVal);
        if (fs::exists(ap, ec) && fs::is_regular_file(ap, ec)) return ap.string();
        effective = aliasVal;
    }
    trace("resolve_model alias_stage_done effective=%s", effective.c_str());

    // Direct path
    if (effective.size() > 5 &&
        effective.substr(effective.size() - 5) == ".gguf") {
        std::error_code pec;
        fs::path p(effective);
        if (fs::exists(p, pec)) return p.string();
        // Try relative to cwd
        std::error_code cec;
        const fs::path cwd = fs::current_path(cec);
        if (!cec) {
            std::error_code rec;
            const fs::path rel = cwd / p;
            if (fs::exists(rel, rec)) return rel.string();
        }
    }

    // Ollama store: resolve any `ollama list` model by name/tag, unless this
    // looks like a filesystem path or an explicit .gguf.
    if (effective.find('\\') == std::string::npos &&
        !(effective.size() > 5 && effective.substr(effective.size() - 5) == ".gguf")) {
        trace("resolve_model ollama_store_stage_enter");
        std::string ollama = resolveOllamaModel(effective);
        trace("resolve_model ollama_store_stage_done hit=%d",
              ollama.empty() ? 0 : 1);
        if (!ollama.empty()) return ollama;
    }

    // Search directories — automatic discovery, no single hardcoded root
    std::vector<fs::path> searchDirs;

    // 1. RAWRXD_MODEL_DIR (if set)
    const char* modelDir = std::getenv("RAWRXD_MODEL_DIR");
    if (modelDir && modelDir[0]) searchDirs.emplace_back(modelDir);

    // 1b. The Ollama store that was just located structurally. It is a known
    // model location, and it has to come before the broad directory walks: as
    // ordered below, the walk of G:\~dev consumed more than five seconds and
    // over 950,000 visited entries before the store was even considered, so a
    // model that was present all along could lose to a tree that was not.
    {
        const fs::path& store = ollamaModelsRootCached();
        if (!store.empty()) {
            trace("resolve_model search_store_root path=%s", store.string().c_str());
            searchDirs.emplace_back(store);
            searchDirs.emplace_back(store / "blobs");
        }
    }

    // 2. Common local model locations (all drives, all common dirs)
    searchDirs.emplace_back("F:\\models");
    searchDirs.emplace_back("F:\\~dev");
    searchDirs.emplace_back("C:\\models");
    searchDirs.emplace_back("D:\\models");
    searchDirs.emplace_back("G:\\~dev");
    searchDirs.emplace_back("G:\\OllamaModels");
    searchDirs.emplace_back("F:\\OllamaModels");

    // 3. User profile model dirs
    const char* home = std::getenv("USERPROFILE");
    if (home) {
        searchDirs.emplace_back(fs::path(home) / ".cache" / "lm-studio" / "models");
        searchDirs.emplace_back(fs::path(home) / "models");
        searchDirs.emplace_back(fs::path(home) / ".ollama" / "models");
    }

    // 4. Ollama model store (from env or default)
    const char* ollamaModels = std::getenv("OLLAMA_MODELS");
    if (ollamaModels && ollamaModels[0]) searchDirs.emplace_back(ollamaModels);
    if (home) searchDirs.emplace_back(fs::path(home) / ".ollama");

    // 5. Current working directory
    {
        std::error_code cec;
        const fs::path cwd = fs::current_path(cec);
        if (!cec) searchDirs.emplace_back(cwd);
    }

    // 6. Walk all drive roots for .gguf files if nothing found yet
    // (covers G:\, F:\, D:\, C:\, E:\, H:\ — any mounted drive)
    std::vector<std::string> driveRoots = {
        "C:\\", "D:\\", "E:\\", "F:\\", "G:\\", "H:\\", "I:\\"
    };

    for (const fs::path& dir : searchDirs) {
        std::error_code dex;
        if (!fs::exists(dir, dex)) continue;
        trace("resolve_model search_dir_enter path=%s", dir.string().c_str());
        // Exact filename match
        fs::path exact = dir / (effective + ".gguf");
        {
            std::error_code dex2;
            if (fs::exists(exact, dex2)) return exact.string();
        }
        // Fuzzy: walk dir, find first .gguf whose stem contains effective
        std::error_code ec;
        unsigned long long visited = 0;
        for (const auto& entry : fs::recursive_directory_iterator(dir, ec)) {
            if (ec) break;
            if (visited >= kSearchVisitBudget) {
                g_searchBudgetExhausted = true;
                trace("resolve_model search_dir_budget_exhausted path=%s budget=%llu",
                      dir.string().c_str(), kSearchVisitBudget);
                break;
            }
            if (++visited % 50000 == 0) trace("resolve_model search_dir path=%s visited=%llu",
                                             dir.string().c_str(), visited);
            if (!entry.is_regular_file()) continue;
            const std::string stem = entry.path().stem().string();
            const std::string ext  = entry.path().extension().string();
            if (ext != ".gguf") continue;
            // Case-insensitive substring match
            std::string stemLow = stem, nameLow = effective;
            for (char& c : stemLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char& c : nameLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (stemLow.find(nameLow) != std::string::npos)
                return entry.path().string();
        }
        trace("resolve_model search_dir_done path=%s visited=%llu",
              dir.string().c_str(), visited);
    }

    // 6. Last resort: scan all drive roots for any .gguf matching the name.
    // This is the automatic discovery path — no hardcoded root required.
    // Only search top-level + one level deep to avoid multi-minute scans.
    for (const std::string& root : driveRoots) {
        fs::path rootPath(root);
        std::error_code ec;
        if (!fs::exists(rootPath, ec)) continue;
        trace("resolve_model drive_root_enter path=%s", root.c_str());
        // Check root level
        for (const auto& entry : fs::directory_iterator(rootPath, ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension().string() != ".gguf") continue;
            std::string stemLow = entry.path().stem().string();
            std::string nameLow = effective;
            for (char& c : stemLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (char& c : nameLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (stemLow.find(nameLow) != std::string::npos)
                return entry.path().string();
        }
        // Check one level deep
        for (const auto& dirEntry : fs::directory_iterator(rootPath, ec)) {
            if (ec) break;
            if (!dirEntry.is_directory()) continue;
            for (const auto& entry : fs::directory_iterator(dirEntry.path(), ec)) {
                if (ec) break;
                if (!entry.is_regular_file()) continue;
                if (entry.path().extension().string() != ".gguf") continue;
                std::string stemLow = entry.path().stem().string();
                std::string nameLow = effective;
                for (char& c : stemLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                for (char& c : nameLow) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (stemLow.find(nameLow) != std::string::npos)
                    return entry.path().string();
            }
        }
    }
    trace("resolve_model not_found");
    return {};
}

// RAWRXD_RAWR_CLI_RESOLVE_CONTAINMENT_001
//
// The filesystem layer throws. On this machine a single unresolved name walked
// G:\~dev until it entered a directory whose name has no representation in the
// active ANSI code page, at which point the walk raised
// std::system_error("No mapping for the Unicode character exists in the target
// multi-byte code page."). Nothing caught it: the exception left the resolver,
// left the run entry point, and left main, so the process died through
// std::terminate -> abort() and surfaced as a bare 0xC0000409 with a WER
// "BEX64" bucket that names neither the stage nor the cause. A name the user
// simply got wrong therefore killed the process instead of being reported as
// not found.
//
// The resolver is now sealed. A failed resolution is a reportable outcome, and
// it is reported as such.
static std::string resolveModelPath(const std::string& nameOrPath) {
    g_searchBudgetExhausted = false;
    std::string resolved;
    try {
        resolved = resolveModelPathImpl(nameOrPath);
    } catch (const std::filesystem::filesystem_error& fe) {
        trace("resolve_model sealed filesystem_error what=%s", fe.what());
        std::fprintf(stderr,
            "[rawr run] MODEL_RESOLUTION=FAIL  filesystem error while resolving '%s': %s\n",
            nameOrPath.c_str(), fe.what());
        std::fflush(stderr);
    } catch (const std::exception& e) {
        trace("resolve_model sealed exception=%s what=%s", typeid(e).name(), e.what());
        std::fprintf(stderr,
            "[rawr run] MODEL_RESOLUTION=FAIL  error while resolving '%s': %s\n",
            nameOrPath.c_str(), e.what());
        std::fflush(stderr);
    } catch (...) {
        trace("resolve_model sealed unknown_exception");
        std::fprintf(stderr,
            "[rawr run] MODEL_RESOLUTION=FAIL  unknown error while resolving '%s'\n",
            nameOrPath.c_str());
        std::fflush(stderr);
    }
    // Reported on both the thrown path and the plain "ran out of places to look"
    // path, because the two are indistinguishable from the exit code and the
    // truncated search must never read as an exhaustive one.
    if (resolved.empty() && g_searchBudgetExhausted) {
        std::fprintf(stderr,
            "[rawr run] MODEL_RESOLUTION=INCONCLUSIVE  per-directory search budget of %llu "
            "entries was reached; deeper locations were not examined. "
            "Set RAWRXD_MODEL_DIR or pass an absolute .gguf path.\n",
            kSearchVisitBudget);
        std::fflush(stderr);
    }
    return resolved;
}

// Expose the shared resolver so the agent core resolves models through exactly
// the same path the CLI uses, instead of a second, divergent heuristic. The rest
// of this translation unit is at global scope, so the exported wrapper is
// explicitly namespaced to match its declaration.
namespace rawrxd { namespace deep2 {
std::string resolveModelPathForAgent(const std::string& nameOrPath) {
    return resolveModelPath(nameOrPath);
}
}} // namespace rawrxd::deep2

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
int rawrxd_run_modelname_001(const char* modelNameOrPath,
                              const char* prompt,
                              uint32_t    maxTokens,
                              bool        vulkanEnabled,
                              bool        strictVulkan) {
    std::set_terminate(resolveTerminateHandler);
    traceStart();

    if (!modelNameOrPath || !modelNameOrPath[0]) {
        std::fprintf(stderr, "[rawr run] ERROR: no model specified\n");
        return 1;
    }
    if (!prompt || !prompt[0]) {
        std::fprintf(stderr, "[rawr run] ERROR: no prompt specified\n");
        return 1;
    }

    // --- Resolve ---
    std::fprintf(stderr, "[rawr run] MODEL_RESOLUTION: resolving '%s'\n", modelNameOrPath);
    std::fflush(stderr);

    const std::string ggufPath = resolveModelPath(modelNameOrPath);
    if (ggufPath.empty()) {
        std::fprintf(stderr,
            "[rawr run] MODEL_RESOLUTION=FAIL  could not locate '%s'\n"
            "  Set RAWRXD_MODEL_DIR or pass an absolute .gguf path.\n",
            modelNameOrPath);
        return 1;
    }
    std::fprintf(stderr, "[rawr run] MODEL_RESOLUTION=PASS  path=%s\n", ggufPath.c_str());
    std::fflush(stderr);
    // Populate the IDE-diag receipt MODEL field (no-op unless diag is enabled).
    Deep2::Deep2Diag::instance().setModel(modelNameOrPath);

    // --- Engine ---
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen   = 4096;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;
    cfg.numThreads  = 0; // auto

    if (!engine.initialize(cfg)) {
        std::fprintf(stderr, "[rawr run] ENGINE_INIT=FAIL\n");
        return 1;
    }

    // --- Vulkan ---
    if (vulkanEnabled) {
        engine.enableVulkan(true);
        std::fprintf(stderr, "[rawr run] VULKAN=ENABLED\n");
    }
    if (strictVulkan) {
        if (!engine.isVulkanInitialized()) {
            std::fprintf(stderr,
                "[rawr run] STRICT_GPU_VIOLATION "
                "enabled=%d initialized=%d\n",
                engine.isVulkanEnabled() ? 1 : 0,
                engine.isVulkanInitialized() ? 1 : 0);
            return 1;
        }
    }

    // --- Load ---
    std::fprintf(stderr, "[rawr run] MODEL_LOAD: loading...\n");
    std::fflush(stderr);

    Deep2::ModelLoadDiag diag{};
    const auto t0 = std::chrono::steady_clock::now();
    if (!engine.loadModel(ggufPath, &diag)) {
        std::fprintf(stderr,
            "[rawr run] MODEL_LOAD=FAIL  stage=%s  msg=%s\n",
            diag.stageName.c_str(), diag.message.c_str());
        return 1;
    }
    const double loadMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    std::fprintf(stderr, "[rawr run] MODEL_LOAD=PASS  %.0f ms\n", loadMs);
    std::fflush(stderr);

    // --- Generate ---
    std::fprintf(stderr, "[rawr run] GENERATE: streaming...\n");
    std::fflush(stderr);

    Deep2::GenerationOptions opts{};
    opts.maxTokens   = maxTokens ? maxTokens : 512;
    opts.temperature = 0.0f; // greedy
    opts.topK        = 1;

    uint64_t tokenCount = 0;
    const auto tGen0 = std::chrono::steady_clock::now();
    auto lastTick = tGen0;
    double peakTps = 0.0;

    // Live TPS tach: a throttled, in-place stderr readout that updates as tokens
    // stream. stdout carries the generated text; stderr carries the tach.
    Deep2::GenerationResult result = engine.generateStream(
        prompt, opts,
        [&](int32_t /*tokenId*/, const std::string& piece) -> bool {
            std::fputs(piece.c_str(), stdout);
            std::fflush(stdout);
            ++tokenCount;

            const auto now = std::chrono::steady_clock::now();
            const double sinceTickMs =
                std::chrono::duration<double, std::milli>(now - lastTick).count();
            if (sinceTickMs >= 150.0) {
                const double elapsed =
                    std::chrono::duration<double>(now - tGen0).count();
                const double liveTps = elapsed > 0.0 ? tokenCount / elapsed : 0.0;
                if (liveTps > peakTps) peakTps = liveTps;
                std::fprintf(stderr,
                    "\r\033[2m[TPS]\033[0m %6.2f tok/s | tokens=%-6llu | %6.1fs   ",
                    liveTps, static_cast<unsigned long long>(tokenCount), elapsed);
                std::fflush(stderr);
                lastTick = now;
            }
            return true; // continue
        });

    const double genMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - tGen0).count();

    // Final tach line (leaves the last reading visible, then a newline).
    {
        const double tpsFinal = genMs > 0.0 ? (tokenCount / (genMs / 1000.0)) : 0.0;
        if (tpsFinal > peakTps) peakTps = tpsFinal;
        std::fprintf(stderr,
            "\r[TPS] %6.2f tok/s | tokens=%-6llu | %6.1fs | peak %.2f tok/s\n",
            tpsFinal, static_cast<unsigned long long>(tokenCount),
            genMs / 1000.0, peakTps);
        std::fflush(stderr);
    }

    std::fputc('\n', stdout);
    std::fflush(stdout);

    // --- Receipt ---
    const double tps = genMs > 0.0 ? (tokenCount / (genMs / 1000.0)) : 0.0;
    std::fprintf(stderr,
        "\n[rawr run] RECEIPT\n"
        "  MODEL=%s\n"
        "  PROMPT_TOKENS=%llu\n"
        "  GENERATED_TOKENS=%llu\n"
        "  WALL_MS=%.1f\n"
        "  TPS=%.3f\n"
        "  PEAK_TPS=%.3f\n"
        "  COMPLETED=%s\n",
        ggufPath.c_str(),
        static_cast<unsigned long long>(result.promptTokens),
        static_cast<unsigned long long>(result.generatedTokens),
        genMs,
        tps,
        peakTps,
        result.completed ? "YES" : "NO");
    std::fflush(stderr);

    return result.completed ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Model listing  (full selection: `rawr list`)
// ---------------------------------------------------------------------------
int rawrxd_list_models_001() {
    std::fprintf(stdout,
        "Selectable models  (use: rawr run <name-or-alias-or-path> \"<prompt>\")\n\n");

    // 1) Ollama store models
    const fs::path oroot = ollamaModelsRootCached();
    std::error_code ec;
    const fs::path omanifests =
        oroot.empty() ? fs::path{} : (oroot / "manifests" / "registry.ollama.ai");
    if (!omanifests.empty() && fs::exists(omanifests, ec)) {
        std::vector<std::string> names;
        for (const auto& e : fs::recursive_directory_iterator(omanifests, ec)) {
            if (ec) break;
            if (!e.is_regular_file()) continue;
            const fs::path rel = fs::relative(e.path(), omanifests, ec);
            std::string n = ollamaNameFromManifestRel(rel);
            if (!n.empty()) names.push_back(std::move(n));
        }
        std::sort(names.begin(), names.end());
        std::fprintf(stdout, "Ollama models (%s)  [%zu]:\n",
                     oroot.string().c_str(), names.size());
        for (const auto& n : names) std::fprintf(stdout, "  %s\n", n.c_str());
        std::fputc('\n', stdout);
    } else {
        std::fprintf(stdout, "Ollama models: (none found; set OLLAMA_MODELS or install Ollama)\n\n");
    }

    // 2) Local .gguf files across the search directories
    std::vector<fs::path> searchDirs;
    if (const char* md = std::getenv("RAWRXD_MODEL_DIR"); md && md[0]) searchDirs.emplace_back(md);
    searchDirs.emplace_back("F:\\models");
    searchDirs.emplace_back("C:\\models");
    searchDirs.emplace_back("D:\\models");
    if (const char* home = std::getenv("USERPROFILE"); home) {
        searchDirs.emplace_back(fs::path(home) / ".cache" / "lm-studio" / "models");
        searchDirs.emplace_back(fs::path(home) / "models");
    }
    std::vector<std::string> ggufs;
    for (const fs::path& dir : searchDirs) {
        if (!fs::exists(dir, ec)) continue;
        for (const auto& e : fs::recursive_directory_iterator(dir, ec)) {
            if (ec) break;
            if (!e.is_regular_file()) continue;
            if (e.path().extension() == ".gguf")
                ggufs.push_back(e.path().string());
        }
    }
    std::sort(ggufs.begin(), ggufs.end());
    ggufs.erase(std::unique(ggufs.begin(), ggufs.end()), ggufs.end());
    std::fprintf(stdout, "Local .gguf files  [%zu]:\n", ggufs.size());
    for (const auto& g : ggufs) std::fprintf(stdout, "  %s\n", g.c_str());
    std::fputc('\n', stdout);

    // 3) Aliases
    std::vector<fs::path> aliasFiles;
    if (const char* af = std::getenv("RAWRXD_MODEL_ALIASES"); af && af[0]) aliasFiles.emplace_back(af);
    if (const char* home = std::getenv("USERPROFILE"); home && home[0])
        aliasFiles.emplace_back(fs::path(home) / ".rawr" / "aliases.txt");
    if (const char* md = std::getenv("RAWRXD_MODEL_DIR"); md && md[0])
        aliasFiles.emplace_back(fs::path(md) / "aliases.txt");
    bool anyAlias = false;
    for (const fs::path& af : aliasFiles) {
        if (!fs::exists(af, ec)) continue;
        std::ifstream in(af.string());
        std::string line;
        while (std::getline(in, line)) {
            const size_t hash = line.find('#');
            if (hash != std::string::npos) line = line.substr(0, hash);
            const size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string k = trimStr(line.substr(0, eq));
            const std::string v = trimStr(line.substr(eq + 1));
            if (k.empty() || v.empty()) continue;
            if (!anyAlias) { std::fprintf(stdout, "Aliases (%s):\n", af.string().c_str()); anyAlias = true; }
            std::fprintf(stdout, "  %-16s -> %s\n", k.c_str(), v.c_str());
        }
    }
    if (!anyAlias) std::fprintf(stdout, "Aliases: (none)\n");
    std::fflush(stdout);
    return 0;
}
