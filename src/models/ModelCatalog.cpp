// =============================================================================
// ModelCatalog.cpp — MODEL-CATALOG-001
// =============================================================================
#include "ModelCatalog.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace rawrxd {
namespace models {

namespace {

std::string toLower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool iequals(const std::string& a, const std::string& b) {
    return toLower(a) == toLower(b);
}

bool containsInsensitive(const std::string& hay, const std::string& needle) {
    return toLower(hay).find(toLower(needle)) != std::string::npos;
}

std::string getenvStr(const char* key) {
    const char* v = std::getenv(key);
    return v ? std::string(v) : std::string();
}

bool hasGgufMagicAt(const fs::path& path, uint64_t offset) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.seekg(static_cast<std::streamoff>(offset));
    char magic[4] = {};
    in.read(magic, 4);
    return in.good() && magic[0] == 'G' && magic[1] == 'G' && magic[2] == 'U' && magic[3] == 'F';
}

} // namespace

ModelCatalog& ModelCatalog::instance() {
    static ModelCatalog s;
    return s;
}

ModelCatalog::ModelCatalog() {
    refreshRoots();
}

std::vector<fs::path> ModelCatalog::defaultRoots() {
    std::vector<fs::path> roots;
    auto push = [&](const fs::path& p) {
        if (p.empty()) return;
        std::error_code ec;
        if (!fs::exists(p, ec)) return;
        for (const auto& existing : roots) {
            if (fs::equivalent(existing, p, ec)) return;
        }
        roots.push_back(fs::weakly_canonical(p, ec));
        if (ec) roots.back() = p;
    };

    // 1) RAWRXD_MODEL_ROOT (may be semicolon-separated on Windows)
    const std::string envRoot = getenvStr("RAWRXD_MODEL_ROOT");
    if (!envRoot.empty()) {
        std::stringstream ss(envRoot);
        std::string part;
        while (std::getline(ss, part, ';')) {
            while (!part.empty() && (part.front() == ' ' || part.front() == '\t')) part.erase(part.begin());
            while (!part.empty() && (part.back() == ' ' || part.back() == '\t')) part.pop_back();
            if (!part.empty()) push(fs::path(part));
        }
    }

    // 2–N) Built-in file-store roots (NOT Ollama daemon)
    push(R"(G:\OllamaModels)");
    push(R"(D:\OllamaModels)");
    push(R"(F:\~dev\OllamaModels)");

    const std::string home = getenvStr("USERPROFILE");
    if (!home.empty()) {
        push(fs::path(home) / ".ollama" / "models");
        push(fs::path(home) / ".ollama");
    }

    push(R"(C:\ProgramData\Ollama\models)");

    return roots;
}

void ModelCatalog::refreshRoots() {
    m_roots = defaultRoots();
    for (const auto& extra : m_extraRoots) {
        std::error_code ec;
        if (!fs::exists(extra, ec)) continue;
        bool dup = false;
        for (const auto& existing : m_roots) {
            if (fs::equivalent(existing, extra, ec)) { dup = true; break; }
        }
        if (!dup) m_roots.push_back(extra);
    }
}

void ModelCatalog::setAdditionalRoots(std::vector<fs::path> roots, bool replace) {
    if (replace) m_extraRoots = std::move(roots);
    else {
        for (auto& r : roots) m_extraRoots.push_back(std::move(r));
    }
    refreshRoots();
}

bool ModelCatalog::looksLikeSha256BlobName(const std::string& name) {
    // Ollama blob files: "sha256-<64 hex>" or bare 64-hex
    if (name.rfind("sha256-", 0) == 0 && name.size() >= 7 + 32) return true;
    if (name.size() == 64) {
        return std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
    }
    return false;
}

void ModelCatalog::syncPathAlias(ResolvedModel& m) {
    m.path = m.absolutePath;
}

bool ModelCatalog::hasGGUFMagic(const fs::path& path, std::uint64_t offset) {
    return hasGgufMagicAt(path, offset);
}

std::optional<std::uint64_t> ModelCatalog::findGGUFOffset(
    const fs::path& path,
    std::uint64_t maxScanBytes)
{
    (void)maxScanBytes; // detectGgufOffset currently caps at 1 MiB
    return detectGgufOffset(path);
}

std::optional<uint64_t> ModelCatalog::detectGgufOffset(const fs::path& path) {
    if (hasGgufMagicAt(path, 0)) return 0ull;
    // Common Ollama blob: scan first 1 MiB for GGUF magic (cheap, no daemon).
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    constexpr size_t kScan = 1u << 20;
    std::vector<char> buf(kScan);
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto n = static_cast<size_t>(in.gcount());
    for (size_t i = 0; i + 4 <= n; ++i) {
        if (buf[i] == 'G' && buf[i + 1] == 'G' && buf[i + 2] == 'U' && buf[i + 3] == 'F') {
            return static_cast<uint64_t>(i);
        }
    }
    return std::nullopt;
}

std::optional<ResolvedModel> ModelCatalog::resolveExistingPath(const fs::path& p) const {
    std::error_code ec;
    if (!fs::exists(p, ec)) return std::nullopt;

    ResolvedModel out;
    out.absolutePath = fs::weakly_canonical(p, ec);
    if (ec) out.absolutePath = fs::absolute(p, ec);
    out.displayName = out.absolutePath.filename().string(); out.name = out.displayName;

    if (fs::is_directory(out.absolutePath, ec)) {
        // Shard directory: prefer any *.gguf inside
        bool any = false;
        for (const auto& ent : fs::directory_iterator(out.absolutePath, ec)) {
            if (!ent.is_regular_file()) continue;
            auto ext = toLower(ent.path().extension().string());
            if (ext == ".gguf") {
                any = true;
                break;
            }
        }
        if (!any) return std::nullopt;
        out.storageKind = StorageKind::GgufShards;
        out.blobOffset = 0;
        syncPathAlias(out);
        return out;
    }

    if (!fs::is_regular_file(out.absolutePath, ec)) return std::nullopt;

    const auto name = out.absolutePath.filename().string();
    const auto ext = toLower(out.absolutePath.extension().string());

    if (ext == ".gguf") {
        out.storageKind = StorageKind::Gguf;
        out.blobOffset = 0;
        syncPathAlias(out);
        return out;
    }

    if (looksLikeSha256BlobName(name) || containsInsensitive(out.absolutePath.string(), "OllamaModels") ||
        containsInsensitive(out.absolutePath.string(), "blobs")) {
        auto off = detectGgufOffset(out.absolutePath);
        if (!off) return std::nullopt;
        out.storageKind = StorageKind::OllamaBlob;
        out.blobOffset = *off;
        if (name.rfind("sha256-", 0) == 0) out.sha256 = name.substr(7);
        else if (name.size() == 64) out.sha256 = name;
        syncPathAlias(out);
        return out;
    }

    // Unknown extension but GGUF magic at 0
    if (hasGgufMagicAt(out.absolutePath, 0)) {
        out.storageKind = StorageKind::Gguf;
        out.blobOffset = 0;
        syncPathAlias(out);
        return out;
    }
    return std::nullopt;
}

std::optional<ResolvedModel> ModelCatalog::searchRoots(const std::string& query) const {
    const std::string q = query;
    const std::string qLower = toLower(q);

    for (const auto& root : m_roots) {
        std::error_code ec;
        // Direct child match
        const fs::path direct = root / q;
        if (auto hit = resolveExistingPath(direct)) {
            hit->sourceRoot = root.string();
            hit->displayName = q; hit->name = q;
            return hit;
        }

        // Case-insensitive scan of root (depth 0) and one level of subdirs
        if (!fs::is_directory(root, ec)) continue;

        auto tryEnt = [&](const fs::directory_entry& ent) -> std::optional<ResolvedModel> {
            const auto name = ent.path().filename().string();
            const auto nameLower = toLower(name);
            const bool nameMatch =
                iequals(name, q) ||
                iequals(nameLower, qLower + ".gguf") ||
                (nameLower.size() > qLower.size() &&
                 nameLower.rfind(qLower, 0) == 0 &&
                 (nameLower[qLower.size()] == '-' || nameLower[qLower.size()] == '_' ||
                  nameLower[qLower.size()] == '.')) ||
                containsInsensitive(name, q);
            if (!nameMatch) return std::nullopt;
            auto hit = resolveExistingPath(ent.path());
            if (!hit) return std::nullopt;
            hit->sourceRoot = root.string();
            hit->displayName = q; hit->name = q;
            return hit;
        };

        for (const auto& ent : fs::directory_iterator(root, ec)) {
            if (auto hit = tryEnt(ent)) return hit;
        }

        // blobs/sha256-* under root
        const fs::path blobs = root / "blobs";
        if (fs::is_directory(blobs, ec)) {
            for (const auto& ent : fs::directory_iterator(blobs, ec)) {
                if (!ent.is_regular_file()) continue;
                if (!looksLikeSha256BlobName(ent.path().filename().string())) continue;
                // Only match blob if query looks like digest prefix
                if (qLower.rfind("sha256", 0) == 0 || qLower.size() >= 12) {
                    if (containsInsensitive(ent.path().filename().string(), q)) {
                        if (auto hit = resolveExistingPath(ent.path())) {
                            hit->sourceRoot = root.string();
                            hit->displayName = q; hit->name = q;
                            return hit;
                        }
                    }
                }
            }
        }
    }
    return std::nullopt;
}

std::optional<ResolvedModel> ModelCatalog::resolveManifestName(const std::string& friendly) const {
    // Best-effort: manifests/registry.ollama.ai/library/<name>/... → digest file → blobs
    for (const auto& root : m_roots) {
        std::error_code ec;
        const fs::path manifests = root / "manifests";
        if (!fs::is_directory(manifests, ec)) continue;

        // Walk a few known layouts without reading entire tree deeply.
        std::vector<fs::path> candidates = {
            manifests / "registry.ollama.ai" / "library" / friendly,
            manifests / friendly,
            root / "models" / "manifests" / "registry.ollama.ai" / "library" / friendly
        };

        for (const auto& dir : candidates) {
            if (!fs::is_directory(dir, ec)) continue;
            for (const auto& tagEnt : fs::directory_iterator(dir, ec)) {
                if (!tagEnt.is_regular_file()) continue;
                // Manifest JSON often contains "digest":"sha256:..."
                std::ifstream in(tagEnt.path());
                if (!in) continue;
                std::stringstream buffer;
                buffer << in.rdbuf();
                const std::string body = buffer.str();
                const std::string key = "\"digest\"";
                size_t pos = body.find(key);
                while (pos != std::string::npos) {
                    size_t colon = body.find(':', pos + key.size());
                    size_t quote1 = body.find('"', colon);
                    size_t quote2 = (quote1 == std::string::npos) ? std::string::npos
                                                                  : body.find('"', quote1 + 1);
                    if (quote1 == std::string::npos || quote2 == std::string::npos) break;
                    std::string digest = body.substr(quote1 + 1, quote2 - quote1 - 1);
                    // sha256:abcd → sha256-abcd
                    if (digest.rfind("sha256:", 0) == 0) {
                        digest = "sha256-" + digest.substr(7);
                    }
                    const fs::path blobPath = root / "blobs" / digest;
                    if (auto hit = resolveExistingPath(blobPath)) {
                        hit->sourceRoot = root.string();
                        hit->displayName = friendly;
                        return hit;
                    }
                    const fs::path blobPath2 = root / "models" / "blobs" / digest;
                    if (auto hit = resolveExistingPath(blobPath2)) {
                        hit->sourceRoot = root.string();
                        hit->displayName = friendly;
                        return hit;
                    }
                    pos = body.find(key, quote2);
                }
            }
        }
    }
    return std::nullopt;
}

std::optional<ResolvedModel> ModelCatalog::resolveQuery(const std::string& query) const {
    if (query.empty()) return std::nullopt;

    // 1) Absolute / relative existing path (--model)
    {
        std::error_code ec;
        fs::path p(query);
        if (p.is_absolute() || query.find('\\') != std::string::npos ||
            query.find('/') != std::string::npos ||
            toLower(p.extension().string()) == ".gguf") {
            if (auto hit = resolveExistingPath(p)) return hit;
        }
        // Also try as-is relative to CWD
        if (auto hit = resolveExistingPath(fs::absolute(p, ec))) return hit;
    }

    // 2) Search configured roots
    if (auto hit = searchRoots(query)) return hit;

    // 3) Friendly Ollama manifest name
    if (auto hit = resolveManifestName(query)) return hit;

    return std::nullopt;
}

std::vector<ResolvedModel> ModelCatalog::listModels(size_t maxCount) const {
    std::vector<ResolvedModel> out;
    std::error_code ec;
    for (const auto& root : m_roots) {
        if (!fs::is_directory(root, ec)) continue;
        for (const auto& ent : fs::directory_iterator(root, ec)) {
            if (out.size() >= maxCount) return out;
            auto hit = resolveExistingPath(ent.path());
            if (!hit) continue;
            hit->sourceRoot = root.string();
            out.push_back(*hit);
        }
        const fs::path blobs = root / "blobs";
        if (fs::is_directory(blobs, ec)) {
            for (const auto& ent : fs::directory_iterator(blobs, ec)) {
                if (out.size() >= maxCount) return out;
                if (!ent.is_regular_file()) continue;
                if (!looksLikeSha256BlobName(ent.path().filename().string())) continue;
                auto hit = resolveExistingPath(ent.path());
                if (!hit) continue;
                hit->sourceRoot = root.string();
                out.push_back(*hit);
            }
        }
    }
    return out;
}

} // namespace models
} // namespace rawrxd
