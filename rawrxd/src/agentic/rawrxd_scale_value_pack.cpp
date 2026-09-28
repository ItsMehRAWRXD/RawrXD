
/*
===============================================================================
 RawrXD Scale Value Pack
 File: src/agentic/rawrxd_scale_value_pack.cpp

 Purpose
 -------
 Close the high-value product-surface gap between the existing sovereign
 RawrXD/Deep2 agent runtime and modern agentic IDE orchestration surfaces.

 This translation unit contains REAL implementations for:
   - persistent local workspace code index with BM25-style ranking
   - durable user-visible checkpoints with restore
   - isolated agent sessions (copy-on-run workspace isolation)
   - RawrXD-Agentic child-process execution with captured logs
   - timeout containment on Windows using Job Objects
   - deterministic session change detection
   - conflict-safe merge from isolated sessions back to the real workspace
   - parallel multi-agent execution across isolated session workspaces
   - persisted run artifacts / receipts under .rawrxd/sessions

 It does NOT implement or substitute inference.
 RawrXD-Agentic.exe remains the authoritative Deep2-backed agent runtime.

 No cloud APIs. No Ollama. No llama.cpp. No external libraries.
 C++20 + OS APIs only.

 Standalone MSVC build:
   cl /std:c++20 /O2 /EHsc /DUNICODE /D_UNICODE ^
      src\agentic\rawrxd_scale_value_pack.cpp ^
      /Fe:RawrXD-Scale.exe

 Examples:
   RawrXD-Scale.exe index --workspace F:\~dev\rawrxd

   RawrXD-Scale.exe search --workspace F:\~dev\rawrxd ^
      --query "Deep2 chat stream callback" --top 12

   RawrXD-Scale.exe checkpoint-create --workspace F:\~dev\rawrxd ^
      --label before-chat-e2e

   RawrXD-Scale.exe checkpoint-list --workspace F:\~dev\rawrxd

   RawrXD-Scale.exe checkpoint-restore --workspace F:\~dev\rawrxd ^
      --id 20260928T120000Z-before-chat-e2e

   RawrXD-Scale.exe run-isolated ^
      --agent-exe F:\~dev\build\RawrXD-Agentic.exe ^
      --workspace F:\~dev\rawrxd ^
      --model G:\models\qwen.gguf ^
      --task "Wire Chat Send to Deep2, build, and verify." ^
      --merge

   RawrXD-Scale.exe run-many ^
      --agent-exe F:\~dev\build\RawrXD-Agentic.exe ^
      --workspace F:\~dev\rawrxd ^
      --model G:\models\qwen.gguf ^
      --tasks F:\~dev\tasks.txt ^
      --max-workers 2 ^
      --merge

===============================================================================
*/

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <charconv>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#endif

namespace rawrxd::scale {
namespace fs = std::filesystem;

// -----------------------------------------------------------------------------
// Basic utilities
// -----------------------------------------------------------------------------

static std::string trim(std::string s) {
    auto first = std::find_if_not(
        s.begin(), s.end(),
        [](unsigned char c) { return std::isspace(c) != 0; });
    auto last = std::find_if_not(
        s.rbegin(), s.rend(),
        [](unsigned char c) { return std::isspace(c) != 0; }).base();
    if (first >= last) return {};
    return std::string(first, last);
}

static std::string lower(std::string s) {
    std::transform(
        s.begin(), s.end(), s.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    return s;
}

static std::string jsonEscape(std::string_view s) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u"
                    << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<unsigned>(c)
                    << std::dec << std::setfill(' ');
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    out << '"';
    return out.str();
}

static std::string isoUtcNowCompact() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
    return out.str();
}

static std::uint64_t fnv1a64(std::string_view bytes) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : bytes) {
        h ^= static_cast<std::uint64_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

static std::string hex64(std::uint64_t value) {
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

static std::string readFile(
    const fs::path& path,
    std::uint64_t maxBytes = 64ull * 1024ull * 1024ull)
{
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec) {
        throw std::runtime_error(
            "file_size failed: " + path.string() + ": " + ec.message());
    }
    if (size > maxBytes) {
        throw std::runtime_error(
            "file exceeds read limit: " + path.string());
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open file: " + path.string());
    }

    std::string data;
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty()) {
        in.read(data.data(), static_cast<std::streamsize>(data.size()));
        if (!in) {
            throw std::runtime_error("failed reading: " + path.string());
        }
    }
    return data;
}

static void writeFileAtomic(
    const fs::path& path,
    std::string_view data)
{
    fs::create_directories(path.parent_path());
    const fs::path temp =
        path.parent_path() /
        (path.filename().string() + ".tmp." + isoUtcNowCompact());

    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("cannot write: " + temp.string());
        }
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
        out.flush();
        if (!out) {
            throw std::runtime_error("write failed: " + temp.string());
        }
    }

    std::error_code ec;
#ifdef _WIN32
    fs::remove(path, ec);
    ec.clear();
#endif
    fs::rename(temp, path, ec);
    if (ec) {
        fs::remove(temp);
        throw std::runtime_error(
            "atomic rename failed: " + path.string() + ": " + ec.message());
    }
}

static std::uint64_t hashFile(const fs::path& path) {
    return fnv1a64(readFile(path));
}

static bool pathStartsWith(
    const fs::path& candidate,
    const fs::path& root)
{
    std::error_code ec1, ec2;
    const auto c = fs::weakly_canonical(candidate, ec1);
    const auto r = fs::weakly_canonical(root, ec2);
    if (ec1 || ec2) return false;

    auto ci = c.begin();
    auto ri = r.begin();
    for (; ri != r.end(); ++ri, ++ci) {
        if (ci == c.end()) return false;
#ifdef _WIN32
        if (lower(ci->string()) != lower(ri->string())) return false;
#else
        if (*ci != *ri) return false;
#endif
    }
    return true;
}

static std::string sanitizeId(std::string s) {
    for (char& c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '-' || c == '_' || c == '.')) {
            c = '-';
        }
    }
    while (!s.empty() && s.front() == '-') s.erase(s.begin());
    while (!s.empty() && s.back() == '-') s.pop_back();
    if (s.empty()) s = "item";
    if (s.size() > 80) s.resize(80);
    return s;
}

static std::string quoteArg(std::string_view arg) {
#ifdef _WIN32
    // Windows CommandLineToArgvW-compatible quoting.
    if (arg.empty()) return "\"\"";
    bool needs = false;
    for (char c : arg) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == '"') {
            needs = true;
            break;
        }
    }
    if (!needs) return std::string(arg);

    std::string out = "\"";
    std::size_t slashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            ++slashes;
        } else if (c == '"') {
            out.append(slashes * 2 + 1, '\\');
            out.push_back('"');
            slashes = 0;
        } else {
            out.append(slashes, '\\');
            slashes = 0;
            out.push_back(c);
        }
    }
    out.append(slashes * 2, '\\');
    out.push_back('"');
    return out;
#else
    std::string out = "'";
    for (char c : arg) {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
#endif
}

// -----------------------------------------------------------------------------
// Workspace file policy
// -----------------------------------------------------------------------------

class WorkspacePolicy {
public:
    explicit WorkspacePolicy(fs::path root)
        : root_(fs::weakly_canonical(fs::absolute(std::move(root))))
    {
        if (root_.empty() || !fs::is_directory(root_)) {
            throw std::runtime_error("invalid workspace root");
        }
    }

    const fs::path& root() const { return root_; }

    bool excludedDirectoryName(std::string name) const {
        name = lower(std::move(name));
        static const std::unordered_set<std::string> exact = {
            ".git", ".svn", ".hg", ".rawrxd",
            "node_modules", ".venv", "venv",
            "__pycache__", ".vs", ".idea",
            "dist", "out", "target",
            "cmake-build-debug", "cmake-build-release",
            "build", "build_debug", "build_release",
            "build_v2", "build_v3", "build_v4",
            "build_p2", "build_clean_n1"
        };
        if (exact.count(name)) return true;
        if (name.rfind("build_", 0) == 0) return true;
        if (name.rfind("build-", 0) == 0) return true;
        return false;
    }

    bool textLike(const fs::path& path) const {
        const std::string ext = lower(path.extension().string());
        static const std::unordered_set<std::string> exts = {
            ".c", ".cc", ".cpp", ".cxx",
            ".h", ".hh", ".hpp", ".hxx", ".inl",
            ".asm", ".s", ".inc",
            ".cmake", ".ps1", ".bat", ".cmd",
            ".py", ".pyi",
            ".js", ".jsx", ".ts", ".tsx",
            ".json", ".jsonl", ".yaml", ".yml",
            ".toml", ".ini", ".cfg", ".conf",
            ".xml", ".html", ".htm", ".css", ".scss",
            ".md", ".txt", ".rst",
            ".rc", ".manifest",
            ".proto", ".sql",
            ".sh", ".zsh", ".fish"
        };
        if (exts.count(ext)) return true;
        const auto filename = lower(path.filename().string());
        return filename == "cmakelists.txt" ||
               filename == "makefile" ||
               filename == "agents.md" ||
               filename == "agent.md";
    }

    bool copyEligible(
        const fs::path& path,
        std::uint64_t maxBytes = 128ull * 1024ull * 1024ull) const
    {
        std::error_code ec;
        if (!fs::is_regular_file(path, ec) || ec) return false;
        const auto size = fs::file_size(path, ec);
        return !ec && size <= maxBytes;
    }

    template <typename Fn>
    void forEachFile(Fn&& fn) const {
        std::error_code ec;
        fs::recursive_directory_iterator it(
            root_,
            fs::directory_options::skip_permission_denied,
            ec);
        fs::recursive_directory_iterator end;

        for (; it != end; it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }

            const auto& entry = *it;
            if (entry.is_directory(ec)) {
                if (!ec &&
                    excludedDirectoryName(entry.path().filename().string())) {
                    it.disable_recursion_pending();
                }
                ec.clear();
                continue;
            }

            if (!entry.is_regular_file(ec) || ec) {
                ec.clear();
                continue;
            }

            fn(entry.path());
        }
    }

    fs::path relative(const fs::path& path) const {
        std::error_code ec;
        const auto rel = fs::relative(path, root_, ec);
        if (ec || rel.empty() || rel.string().rfind("..", 0) == 0) {
            throw std::runtime_error(
                "path is outside workspace: " + path.string());
        }
        return rel;
    }

private:
    fs::path root_;
};

// -----------------------------------------------------------------------------
// Persistent local code index
// -----------------------------------------------------------------------------

struct IndexedDocument {
    std::string relativePath;
    std::uint64_t fileSize = 0;
    std::int64_t mtimeTicks = 0;
    std::uint64_t contentHash = 0;
    std::uint32_t length = 0;
    std::unordered_map<std::string, std::uint32_t> tf;
};

static std::vector<std::string> tokenizeSearch(std::string_view text) {
    std::vector<std::string> tokens;
    std::string current;

    auto flush = [&]() {
        if (current.size() >= 2) {
            tokens.push_back(lower(current));
        }
        current.clear();
    };

    char previous = '\0';
    for (char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        const bool word = std::isalnum(u) || c == '_';

        if (!word) {
            flush();
            previous = c;
            continue;
        }

        // CamelCase boundary: "Deep2Engine" -> deep2, engine plus full token
        if (!current.empty() &&
            std::isupper(u) &&
            std::islower(static_cast<unsigned char>(previous))) {
            const std::string prefix = lower(current);
            if (prefix.size() >= 2) tokens.push_back(prefix);
            current.clear();
        }

        current.push_back(c);
        previous = c;
    }
    flush();

    // Also index path-ish punctuation-separated terms naturally via the above.
    std::sort(tokens.begin(), tokens.end());
    tokens.erase(std::unique(tokens.begin(), tokens.end()), tokens.end());
    return tokens;
}

static std::unordered_map<std::string, std::uint32_t>
termFrequency(std::string_view text, std::uint32_t& lengthOut)
{
    std::unordered_map<std::string, std::uint32_t> tf;
    std::string current;
    lengthOut = 0;

    auto flush = [&]() {
        if (current.size() >= 2) {
            std::string token = lower(current);
            ++tf[token];
            ++lengthOut;
        }
        current.clear();
    };

    for (char c : text) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalnum(u) || c == '_') {
            current.push_back(c);
        } else {
            flush();
        }
    }
    flush();
    return tf;
}

class WorkspaceIndex {
public:
    explicit WorkspaceIndex(fs::path workspace)
        : policy_(std::move(workspace)),
          indexPath_(policy_.root() / ".rawrxd" / "index" / "workspace.rxidx")
    {
    }

    struct BuildStats {
        std::size_t discovered = 0;
        std::size_t reused = 0;
        std::size_t reindexed = 0;
        std::size_t removed = 0;
    };

    BuildStats buildIncremental() {
        std::unordered_map<std::string, IndexedDocument> previous;
        if (fs::exists(indexPath_)) {
            try {
                previous = loadMap();
            } catch (...) {
                previous.clear();
            }
        }

        std::unordered_map<std::string, IndexedDocument> next;
        BuildStats stats;

        policy_.forEachFile([&](const fs::path& path) {
            if (!policy_.textLike(path)) return;

            std::error_code ec;
            const auto size = fs::file_size(path, ec);
            if (ec || size > 4ull * 1024ull * 1024ull) return;

            ++stats.discovered;
            const std::string rel = policy_.relative(path).generic_string();

            const auto ftime = fs::last_write_time(path, ec);
            const std::int64_t ticks =
                ec ? 0 : static_cast<std::int64_t>(
                    ftime.time_since_epoch().count());

            auto old = previous.find(rel);
            if (old != previous.end() &&
                old->second.fileSize == size &&
                old->second.mtimeTicks == ticks) {
                next.emplace(rel, std::move(old->second));
                ++stats.reused;
                return;
            }

            const std::string content = readFile(path, 4ull * 1024ull * 1024ull);

            IndexedDocument doc;
            doc.relativePath = rel;
            doc.fileSize = size;
            doc.mtimeTicks = ticks;
            doc.contentHash = fnv1a64(content);
            doc.tf = termFrequency(content, doc.length);

            // Add path terms with a modest fixed boost.
            for (const auto& t : tokenizeSearch(rel)) {
                doc.tf[t] += 3;
                doc.length += 3;
            }

            next.emplace(rel, std::move(doc));
            ++stats.reindexed;
        });

        if (previous.size() > next.size()) {
            stats.removed = previous.size() - next.size();
        }

        documents_.clear();
        documents_.reserve(next.size());
        for (auto& [_, doc] : next) {
            documents_.push_back(std::move(doc));
        }
        std::sort(
            documents_.begin(), documents_.end(),
            [](const auto& a, const auto& b) {
                return a.relativePath < b.relativePath;
            });

        save();
        return stats;
    }

    void load() {
        if (!fs::exists(indexPath_)) {
            buildIncremental();
            return;
        }

        const auto map = loadMap();
        documents_.clear();
        documents_.reserve(map.size());
        for (const auto& [_, doc] : map) {
            documents_.push_back(doc);
        }
    }

    struct Hit {
        std::string path;
        double score = 0.0;
        std::vector<std::string> matchedTerms;
    };

    std::vector<Hit> search(
        const std::string& query,
        std::size_t topK = 20)
    {
        if (documents_.empty()) load();
        const auto terms = tokenizeSearch(query);
        if (terms.empty()) return {};

        std::unordered_map<std::string, std::size_t> df;
        double avgdl = 0.0;
        for (const auto& doc : documents_) {
            avgdl += static_cast<double>(std::max<std::uint32_t>(1, doc.length));
            for (const auto& term : terms) {
                if (doc.tf.count(term)) ++df[term];
            }
        }
        if (!documents_.empty()) avgdl /= static_cast<double>(documents_.size());
        if (avgdl <= 0.0) avgdl = 1.0;

        constexpr double k1 = 1.5;
        constexpr double b = 0.75;
        std::vector<Hit> hits;

        for (const auto& doc : documents_) {
            double score = 0.0;
            std::vector<std::string> matched;

            for (const auto& term : terms) {
                auto it = doc.tf.find(term);
                if (it == doc.tf.end()) continue;

                const double tf = static_cast<double>(it->second);
                const double n = static_cast<double>(documents_.size());
                const double dfi = static_cast<double>(df[term]);
                const double idf = std::log(
                    1.0 + (n - dfi + 0.5) / (dfi + 0.5));

                const double dl =
                    static_cast<double>(std::max<std::uint32_t>(1, doc.length));
                const double denom =
                    tf + k1 * (1.0 - b + b * dl / avgdl);

                score += idf * (tf * (k1 + 1.0)) / denom;
                matched.push_back(term);
            }

            const std::string pathLower = lower(doc.relativePath);
            for (const auto& term : terms) {
                if (pathLower.find(term) != std::string::npos) {
                    score += 1.25;
                }
            }

            if (score > 0.0) {
                hits.push_back(Hit{doc.relativePath, score, std::move(matched)});
            }
        }

        std::sort(
            hits.begin(), hits.end(),
            [](const Hit& a, const Hit& b) {
                if (a.score != b.score) return a.score > b.score;
                return a.path < b.path;
            });

        if (hits.size() > topK) hits.resize(topK);
        return hits;
    }

    const fs::path& path() const { return indexPath_; }

private:
    WorkspacePolicy policy_;
    fs::path indexPath_;
    std::vector<IndexedDocument> documents_;

    static void writeU32(std::ostream& out, std::uint32_t v) {
        out.write(reinterpret_cast<const char*>(&v), sizeof(v));
    }
    static void writeU64(std::ostream& out, std::uint64_t v) {
        out.write(reinterpret_cast<const char*>(&v), sizeof(v));
    }
    static void writeI64(std::ostream& out, std::int64_t v) {
        out.write(reinterpret_cast<const char*>(&v), sizeof(v));
    }
    static std::uint32_t readU32(std::istream& in) {
        std::uint32_t v{};
        in.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!in) throw std::runtime_error("corrupt index");
        return v;
    }
    static std::uint64_t readU64(std::istream& in) {
        std::uint64_t v{};
        in.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!in) throw std::runtime_error("corrupt index");
        return v;
    }
    static std::int64_t readI64(std::istream& in) {
        std::int64_t v{};
        in.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!in) throw std::runtime_error("corrupt index");
        return v;
    }
    static void writeString(std::ostream& out, const std::string& s) {
        if (s.size() > 16ull * 1024ull * 1024ull)
            throw std::runtime_error("index string too large");
        writeU32(out, static_cast<std::uint32_t>(s.size()));
        out.write(s.data(), static_cast<std::streamsize>(s.size()));
    }
    static std::string readString(std::istream& in) {
        const auto n = readU32(in);
        if (n > 16u * 1024u * 1024u)
            throw std::runtime_error("corrupt index string");
        std::string s(n, '\0');
        if (n) in.read(s.data(), n);
        if (!in) throw std::runtime_error("corrupt index");
        return s;
    }

    void save() const {
        fs::create_directories(indexPath_.parent_path());
        const fs::path tmp = indexPath_.string() + ".tmp";
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create index");

        const char magic[8] = {'R','X','I','D','X','0','0','1'};
        out.write(magic, sizeof(magic));
        writeU32(out, static_cast<std::uint32_t>(documents_.size()));

        for (const auto& doc : documents_) {
            writeString(out, doc.relativePath);
            writeU64(out, doc.fileSize);
            writeI64(out, doc.mtimeTicks);
            writeU64(out, doc.contentHash);
            writeU32(out, doc.length);
            writeU32(out, static_cast<std::uint32_t>(doc.tf.size()));
            for (const auto& [term, count] : doc.tf) {
                writeString(out, term);
                writeU32(out, count);
            }
        }
        out.flush();
        if (!out) throw std::runtime_error("index write failed");
        out.close();

        std::error_code ec;
#ifdef _WIN32
        fs::remove(indexPath_, ec);
        ec.clear();
#endif
        fs::rename(tmp, indexPath_, ec);
        if (ec) {
            fs::remove(tmp);
            throw std::runtime_error("index replace failed: " + ec.message());
        }
    }

    std::unordered_map<std::string, IndexedDocument> loadMap() const {
        std::ifstream in(indexPath_, std::ios::binary);
        if (!in) throw std::runtime_error("cannot open index");

        char magic[8]{};
        in.read(magic, sizeof(magic));
        const std::string expected = "RXIDX001";
        if (!in || std::string(magic, sizeof(magic)) != expected) {
            throw std::runtime_error("unsupported/corrupt index");
        }

        const auto docs = readU32(in);
        if (docs > 2'000'000u) throw std::runtime_error("corrupt index count");

        std::unordered_map<std::string, IndexedDocument> map;
        map.reserve(docs);

        for (std::uint32_t i = 0; i < docs; ++i) {
            IndexedDocument doc;
            doc.relativePath = readString(in);
            doc.fileSize = readU64(in);
            doc.mtimeTicks = readI64(in);
            doc.contentHash = readU64(in);
            doc.length = readU32(in);
            const auto terms = readU32(in);
            if (terms > 2'000'000u) throw std::runtime_error("corrupt term count");
            for (std::uint32_t t = 0; t < terms; ++t) {
                const std::string term = readString(in);
                const auto count = readU32(in);
                doc.tf.emplace(term, count);
            }
            map.emplace(doc.relativePath, std::move(doc));
        }
        return map;
    }
};

// -----------------------------------------------------------------------------
// Workspace snapshots + durable checkpoints
// -----------------------------------------------------------------------------

struct FileState {
    std::uint64_t size = 0;
    std::uint64_t hash = 0;
};

using Manifest = std::map<std::string, FileState>;

static Manifest scanManifest(
    const WorkspacePolicy& policy,
    std::uint64_t maxBytes = 128ull * 1024ull * 1024ull)
{
    Manifest manifest;
    policy.forEachFile([&](const fs::path& path) {
        if (!policy.copyEligible(path, maxBytes)) return;

        const std::string rel = policy.relative(path).generic_string();
        std::error_code ec;
        const auto size = fs::file_size(path, ec);
        if (ec) return;

        try {
            manifest.emplace(
                rel,
                FileState{
                    static_cast<std::uint64_t>(size),
                    hashFile(path)
                });
        } catch (...) {
        }
    });
    return manifest;
}

static void copyWorkspace(
    const WorkspacePolicy& source,
    const fs::path& destination,
    std::uint64_t maxBytes = 128ull * 1024ull * 1024ull)
{
    fs::create_directories(destination);
    source.forEachFile([&](const fs::path& path) {
        if (!source.copyEligible(path, maxBytes)) return;

        const fs::path rel = source.relative(path);
        const fs::path dest = destination / rel;
        fs::create_directories(dest.parent_path());

        std::error_code ec;
        fs::copy_file(
            path,
            dest,
            fs::copy_options::overwrite_existing,
            ec);
        if (ec) {
            throw std::runtime_error(
                "copy failed " + path.string() + " -> " +
                dest.string() + ": " + ec.message());
        }
    });
}

class CheckpointStore {
public:
    explicit CheckpointStore(fs::path workspace)
        : policy_(std::move(workspace)),
          root_(policy_.root() / ".rawrxd" / "checkpoints")
    {
    }

    std::string create(const std::string& label) {
        const std::string id =
            isoUtcNowCompact() + "-" + sanitizeId(label.empty() ? "checkpoint" : label);

        const fs::path dir = root_ / id;
        const fs::path filesDir = dir / "files";
        if (fs::exists(dir)) {
            throw std::runtime_error("checkpoint already exists: " + id);
        }
        fs::create_directories(filesDir);

        Manifest manifest;
        std::size_t copied = 0;

        policy_.forEachFile([&](const fs::path& path) {
            if (!policy_.copyEligible(path)) return;
            const fs::path rel = policy_.relative(path);
            const fs::path dest = filesDir / rel;

            fs::create_directories(dest.parent_path());
            std::error_code ec;
            fs::copy_file(path, dest, fs::copy_options::overwrite_existing, ec);
            if (ec) {
                throw std::runtime_error(
                    "checkpoint copy failed: " + path.string() + ": " + ec.message());
            }

            const auto size = fs::file_size(path, ec);
            if (ec) throw std::runtime_error("checkpoint stat failed");
            manifest.emplace(
                rel.generic_string(),
                FileState{
                    static_cast<std::uint64_t>(size),
                    hashFile(path)
                });
            ++copied;
        });

        writeManifest(dir / "manifest.tsv", manifest);
        const std::string meta =
            "{\n"
            "  \"id\":" + jsonEscape(id) + ",\n"
            "  \"label\":" + jsonEscape(label) + ",\n"
            "  \"workspace\":" + jsonEscape(policy_.root().string()) + ",\n"
            "  \"files\":" + std::to_string(copied) + "\n"
            "}\n";
        writeFileAtomic(dir / "metadata.json", meta);
        return id;
    }

    std::vector<std::string> list() const {
        std::vector<std::string> ids;
        if (!fs::exists(root_)) return ids;
        for (const auto& entry : fs::directory_iterator(root_)) {
            if (entry.is_directory() &&
                fs::exists(entry.path() / "manifest.tsv")) {
                ids.push_back(entry.path().filename().string());
            }
        }
        std::sort(ids.begin(), ids.end(), std::greater<>());
        return ids;
    }

    void restore(const std::string& id) {
        const fs::path dir = root_ / sanitizeId(id);
        const fs::path manifestPath = dir / "manifest.tsv";
        const fs::path filesDir = dir / "files";

        if (!fs::is_regular_file(manifestPath) || !fs::is_directory(filesDir)) {
            throw std::runtime_error("checkpoint not found: " + id);
        }

        const Manifest wanted = readManifest(manifestPath);
        const Manifest current = scanManifest(policy_);

        // Delete managed files created after the checkpoint.
        for (const auto& [rel, _] : current) {
            if (wanted.count(rel)) continue;
            const fs::path target = policy_.root() / fs::path(rel);
            if (!pathStartsWith(target, policy_.root())) {
                throw std::runtime_error("restore path escape");
            }
            std::error_code ec;
            fs::remove(target, ec);
            if (ec) {
                throw std::runtime_error(
                    "restore could not remove " + rel + ": " + ec.message());
            }
        }

        // Restore every checkpointed file byte-for-byte.
        for (const auto& [rel, state] : wanted) {
            (void)state;
            const fs::path source = filesDir / fs::path(rel);
            const fs::path target = policy_.root() / fs::path(rel);

            if (!pathStartsWith(target, policy_.root()) ||
                !pathStartsWith(source, filesDir)) {
                throw std::runtime_error("restore path escape");
            }

            fs::create_directories(target.parent_path());
            std::error_code ec;
            fs::copy_file(
                source, target,
                fs::copy_options::overwrite_existing,
                ec);
            if (ec) {
                throw std::runtime_error(
                    "restore copy failed " + rel + ": " + ec.message());
            }
        }
    }

    static void writeManifest(
        const fs::path& path,
        const Manifest& manifest)
    {
        std::ostringstream out;
        for (const auto& [rel, state] : manifest) {
            if (rel.find('\t') != std::string::npos ||
                rel.find('\n') != std::string::npos ||
                rel.find('\r') != std::string::npos) {
                throw std::runtime_error(
                    "unsupported control character in path: " + rel);
            }
            out << rel << '\t'
                << state.size << '\t'
                << hex64(state.hash) << '\n';
        }
        writeFileAtomic(path, out.str());
    }

    static Manifest readManifest(const fs::path& path) {
        Manifest manifest;
        std::ifstream in(path);
        if (!in) throw std::runtime_error("cannot read manifest");
        std::string line;

        while (std::getline(in, line)) {
            const auto t1 = line.find('\t');
            const auto t2 = t1 == std::string::npos
                ? std::string::npos
                : line.find('\t', t1 + 1);
            if (t1 == std::string::npos || t2 == std::string::npos)
                throw std::runtime_error("corrupt manifest");

            const std::string rel = line.substr(0, t1);
            std::uint64_t size = 0;
            {
                const std::string s = line.substr(t1 + 1, t2 - t1 - 1);
                const auto r = std::from_chars(
                    s.data(), s.data() + s.size(), size);
                if (r.ec != std::errc{}) throw std::runtime_error("corrupt manifest size");
            }

            std::uint64_t hash = 0;
            {
                std::istringstream hs(line.substr(t2 + 1));
                hs >> std::hex >> hash;
                if (!hs) throw std::runtime_error("corrupt manifest hash");
            }

            manifest.emplace(rel, FileState{size, hash});
        }
        return manifest;
    }

private:
    WorkspacePolicy policy_;
    fs::path root_;
};

// -----------------------------------------------------------------------------
// Child process execution
// -----------------------------------------------------------------------------

struct ProcessResult {
    int exitCode = -1;
    bool timedOut = false;
    std::string output;
};

#ifdef _WIN32

static std::wstring widenUtf8(const std::string& s) {
    if (s.empty()) return {};
    const int needed = MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) throw std::runtime_error("UTF-8 conversion failed");
    std::wstring w(static_cast<std::size_t>(needed), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), needed);
    return w;
}

static ProcessResult runCaptured(
    const fs::path& executable,
    const std::vector<std::string>& arguments,
    const fs::path& workingDirectory,
    std::chrono::milliseconds timeout)
{
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
        throw std::runtime_error("CreatePipe failed");
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};

    std::string command = quoteArg(executable.string());
    for (const auto& arg : arguments) {
        command.push_back(' ');
        command += quoteArg(arg);
    }

    std::wstring wide = widenUtf8(command);
    std::vector<wchar_t> mutableCmd(wide.begin(), wide.end());
    mutableCmd.push_back(L'\0');

    const std::wstring cwd = workingDirectory.wstring();

    const BOOL created = CreateProcessW(
        executable.wstring().c_str(),
        mutableCmd.data(),
        nullptr, nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        cwd.c_str(),
        &si, &pi);

    CloseHandle(writePipe);
    writePipe = nullptr;

    if (!created) {
        CloseHandle(readPipe);
        throw std::runtime_error(
            "CreateProcessW failed: " + std::to_string(GetLastError()));
    }

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info,
            sizeof(info));
        AssignProcessToJobObject(job, pi.hProcess);
    }

    ProcessResult result;
    std::thread reader([&] {
        std::array<char, 8192> buffer{};
        for (;;) {
            DWORD got = 0;
            const BOOL ok = ReadFile(
                readPipe,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &got,
                nullptr);
            if (!ok || got == 0) break;
            result.output.append(buffer.data(), got);
        }
    });

    DWORD waitMs = INFINITE;
    if (timeout.count() > 0 &&
        timeout.count() <= static_cast<long long>(std::numeric_limits<DWORD>::max())) {
        waitMs = static_cast<DWORD>(timeout.count());
    }

    const DWORD wait = WaitForSingleObject(pi.hProcess, waitMs);
    if (wait == WAIT_TIMEOUT) {
        result.timedOut = true;
        if (job) {
            TerminateJobObject(job, 124);
        } else {
            TerminateProcess(pi.hProcess, 124);
        }
        WaitForSingleObject(pi.hProcess, 5000);
    }

    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    result.exitCode = static_cast<int>(code);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (job) CloseHandle(job);

    if (reader.joinable()) reader.join();
    CloseHandle(readPipe);
    return result;
}

#else

static ProcessResult runCaptured(
    const fs::path& executable,
    const std::vector<std::string>& arguments,
    const fs::path& workingDirectory,
    std::chrono::milliseconds)
{
    std::string command =
        "cd " + quoteArg(workingDirectory.string()) +
        " && " + quoteArg(executable.string());
    for (const auto& arg : arguments) {
        command += " " + quoteArg(arg);
    }
    command += " 2>&1";

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen failed");

    ProcessResult result;
    std::array<char, 8192> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        result.output += buffer.data();
    }
    const int rc = pclose(pipe);
    if (WIFEXITED(rc)) result.exitCode = WEXITSTATUS(rc);
    else result.exitCode = rc;
    return result;
}

#endif

// -----------------------------------------------------------------------------
// Isolated session + conflict-safe merge
// -----------------------------------------------------------------------------

enum class ChangeKind {
    Added,
    Modified,
    Deleted
};

struct FileChange {
    ChangeKind kind = ChangeKind::Modified;
    std::string relativePath;
    std::uint64_t beforeHash = 0;
    std::uint64_t afterHash = 0;
};

static const char* changeKindName(ChangeKind k) {
    switch (k) {
    case ChangeKind::Added: return "added";
    case ChangeKind::Modified: return "modified";
    case ChangeKind::Deleted: return "deleted";
    }
    return "unknown";
}

struct SessionResult {
    std::string id;
    bool success = false;
    bool timedOut = false;
    int exitCode = -1;
    fs::path sessionDirectory;
    fs::path isolatedWorkspace;
    std::vector<FileChange> changes;
    std::string output;
};

class AgentSession {
public:
    AgentSession(
        fs::path baseWorkspace,
        fs::path agentExecutable,
        fs::path modelPath,
        std::string task,
        int maxSteps,
        int maxTokens,
        std::chrono::milliseconds timeout)
        : basePolicy_(std::move(baseWorkspace)),
          agentExecutable_(std::move(agentExecutable)),
          modelPath_(std::move(modelPath)),
          task_(std::move(task)),
          maxSteps_(maxSteps),
          maxTokens_(maxTokens),
          timeout_(timeout)
    {
        static std::atomic<std::uint64_t> sessionNonce{0};
        const std::string now = isoUtcNowCompact();
        const auto ticks = std::chrono::high_resolution_clock::now()
                               .time_since_epoch().count();
        const std::string fingerprint =
            hex64(fnv1a64(
                task_ + now + std::to_string(ticks) +
                std::to_string(sessionNonce.fetch_add(1))));
        id_ = now + "-" + fingerprint.substr(0, 8);

        sessionDir_ =
            basePolicy_.root() / ".rawrxd" / "sessions" / id_;
        isolated_ = sessionDir_ / "workspace";
    }

    SessionResult run() {
        if (!fs::is_regular_file(agentExecutable_)) {
            throw std::runtime_error(
                "agent executable not found: " + agentExecutable_.string());
        }
        if (!fs::exists(modelPath_)) {
            throw std::runtime_error(
                "model path not found: " + modelPath_.string());
        }
        if (fs::exists(sessionDir_)) {
            throw std::runtime_error("session id collision: " + id_);
        }

        fs::create_directories(sessionDir_);
        copyWorkspace(basePolicy_, isolated_);
        const WorkspacePolicy isolatedPolicy(isolated_);

        baseline_ = scanManifest(isolatedPolicy);
        CheckpointStore::writeManifest(
            sessionDir_ / "baseline.tsv",
            baseline_);

        writeFileAtomic(
            sessionDir_ / "request.json",
            "{\n"
            "  \"id\":" + jsonEscape(id_) + ",\n"
            "  \"task\":" + jsonEscape(task_) + ",\n"
            "  \"model\":" + jsonEscape(modelPath_.string()) + ",\n"
            "  \"base_workspace\":" + jsonEscape(basePolicy_.root().string()) + "\n"
            "}\n");

        std::vector<std::string> args = {
            "--model", modelPath_.string(),
            "--workspace", isolated_.string(),
            "--task", task_,
            "--max-steps", std::to_string(maxSteps_),
            "--max-tokens", std::to_string(maxTokens_)
        };

        const auto started = std::chrono::steady_clock::now();
        ProcessResult process = runCaptured(
            agentExecutable_,
            args,
            isolated_,
            timeout_);
        const auto finished = std::chrono::steady_clock::now();

        writeFileAtomic(sessionDir_ / "stdout.log", process.output);

        const Manifest after = scanManifest(isolatedPolicy);
        const auto changes = diff(baseline_, after);
        writeChanges(sessionDir_ / "changes.tsv", changes);

        const auto durationMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                finished - started).count();

        const bool success = !process.timedOut && process.exitCode == 0;

        writeFileAtomic(
            sessionDir_ / "result.json",
            "{\n"
            "  \"id\":" + jsonEscape(id_) + ",\n"
            "  \"success\":" + std::string(success ? "true" : "false") + ",\n"
            "  \"timed_out\":" + std::string(process.timedOut ? "true" : "false") + ",\n"
            "  \"exit_code\":" + std::to_string(process.exitCode) + ",\n"
            "  \"duration_ms\":" + std::to_string(durationMs) + ",\n"
            "  \"changed_files\":" + std::to_string(changes.size()) + "\n"
            "}\n");

        return SessionResult{
            id_,
            success,
            process.timedOut,
            process.exitCode,
            sessionDir_,
            isolated_,
            changes,
            process.output
        };
    }

    struct MergeResult {
        bool success = false;
        std::string checkpointId;
        std::vector<std::string> merged;
        std::vector<std::string> conflicts;
    };

    MergeResult merge(const SessionResult& result) {
        if (!result.success) {
            throw std::runtime_error(
                "refusing to merge unsuccessful session: " + result.id);
        }

        // Re-read baseline from disk so a merge remains possible in a later process.
        const Manifest baseline =
            CheckpointStore::readManifest(result.sessionDirectory / "baseline.tsv");

        CheckpointStore checkpoints(basePolicy_.root());
        const std::string checkpoint =
            checkpoints.create("pre-merge-" + result.id);

        MergeResult mr;
        mr.checkpointId = checkpoint;

        for (const auto& change : result.changes) {
            const fs::path basePath =
                basePolicy_.root() / fs::path(change.relativePath);
            const fs::path sessionPath =
                result.isolatedWorkspace / fs::path(change.relativePath);

            const auto before = baseline.find(change.relativePath);

            bool baseUnchanged = false;
            if (before == baseline.end()) {
                baseUnchanged = !fs::exists(basePath);
            } else {
                if (fs::is_regular_file(basePath)) {
                    try {
                        baseUnchanged =
                            hashFile(basePath) == before->second.hash;
                    } catch (...) {
                        baseUnchanged = false;
                    }
                }
            }

            if (!baseUnchanged) {
                mr.conflicts.push_back(change.relativePath);
                continue;
            }

            try {
                if (change.kind == ChangeKind::Deleted) {
                    std::error_code ec;
                    fs::remove(basePath, ec);
                    if (ec) {
                        throw std::runtime_error(ec.message());
                    }
                } else {
                    fs::create_directories(basePath.parent_path());
                    std::error_code ec;
                    fs::copy_file(
                        sessionPath,
                        basePath,
                        fs::copy_options::overwrite_existing,
                        ec);
                    if (ec) {
                        throw std::runtime_error(ec.message());
                    }
                }
                mr.merged.push_back(change.relativePath);
            } catch (const std::exception&) {
                mr.conflicts.push_back(change.relativePath);
            }
        }

        mr.success = mr.conflicts.empty();

        std::ostringstream json;
        json << "{\n"
             << "  \"session\":" << jsonEscape(result.id) << ",\n"
             << "  \"checkpoint\":" << jsonEscape(checkpoint) << ",\n"
             << "  \"success\":" << (mr.success ? "true" : "false") << ",\n"
             << "  \"merged\":[";
        for (std::size_t i = 0; i < mr.merged.size(); ++i) {
            if (i) json << ",";
            json << jsonEscape(mr.merged[i]);
        }
        json << "],\n  \"conflicts\":[";
        for (std::size_t i = 0; i < mr.conflicts.size(); ++i) {
            if (i) json << ",";
            json << jsonEscape(mr.conflicts[i]);
        }
        json << "]\n}\n";
        writeFileAtomic(result.sessionDirectory / "merge.json", json.str());
        return mr;
    }

    static std::vector<FileChange> diff(
        const Manifest& before,
        const Manifest& after)
    {
        std::vector<FileChange> changes;

        for (const auto& [rel, state] : after) {
            const auto it = before.find(rel);
            if (it == before.end()) {
                changes.push_back(
                    FileChange{ChangeKind::Added, rel, 0, state.hash});
            } else if (it->second.hash != state.hash) {
                changes.push_back(
                    FileChange{
                        ChangeKind::Modified,
                        rel,
                        it->second.hash,
                        state.hash});
            }
        }

        for (const auto& [rel, state] : before) {
            if (!after.count(rel)) {
                changes.push_back(
                    FileChange{ChangeKind::Deleted, rel, state.hash, 0});
            }
        }

        std::sort(
            changes.begin(), changes.end(),
            [](const auto& a, const auto& b) {
                return a.relativePath < b.relativePath;
            });
        return changes;
    }

    static void writeChanges(
        const fs::path& path,
        const std::vector<FileChange>& changes)
    {
        std::ostringstream out;
        for (const auto& c : changes) {
            out << changeKindName(c.kind) << '\t'
                << hex64(c.beforeHash) << '\t'
                << hex64(c.afterHash) << '\t'
                << c.relativePath << '\n';
        }
        writeFileAtomic(path, out.str());
    }

private:
    WorkspacePolicy basePolicy_;
    fs::path agentExecutable_;
    fs::path modelPath_;
    std::string task_;
    int maxSteps_ = 32;
    int maxTokens_ = 4096;
    std::chrono::milliseconds timeout_{30 * 60 * 1000};

    std::string id_;
    fs::path sessionDir_;
    fs::path isolated_;
    Manifest baseline_;
};

// -----------------------------------------------------------------------------
// Fixed-size worker pool for parallel isolated sessions
// -----------------------------------------------------------------------------

template <typename T>
class BlockingQueue {
public:
    void push(T value) {
        {
            std::lock_guard lock(mutex_);
            queue_.push(std::move(value));
        }
        cv_.notify_one();
    }

    bool pop(T& value) {
        std::unique_lock lock(mutex_);
        cv_.wait(lock, [&] { return closed_ || !queue_.empty(); });
        if (queue_.empty()) return false;
        value = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    void close() {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        cv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<T> queue_;
    bool closed_ = false;
};

struct MultiTaskResult {
    std::size_t index = 0;
    std::string task;
    std::optional<SessionResult> session;
    std::string error;
};

static std::vector<MultiTaskResult> runMany(
    const fs::path& workspace,
    const fs::path& agentExe,
    const fs::path& model,
    const std::vector<std::string>& tasks,
    int maxWorkers,
    int maxSteps,
    int maxTokens,
    std::chrono::milliseconds timeout)
{
    BlockingQueue<std::size_t> queue;
    for (std::size_t i = 0; i < tasks.size(); ++i) queue.push(i);
    queue.close();

    std::vector<MultiTaskResult> results(tasks.size());
    std::mutex resultsMutex;

    const int workers =
        std::max(1, std::min<int>(
            maxWorkers,
            static_cast<int>(tasks.size())));

    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int w = 0; w < workers; ++w) {
        threads.emplace_back([&] {
            std::size_t index = 0;
            while (queue.pop(index)) {
                MultiTaskResult r;
                r.index = index;
                r.task = tasks[index];

                try {
                    AgentSession session(
                        workspace,
                        agentExe,
                        model,
                        tasks[index],
                        maxSteps,
                        maxTokens,
                        timeout);
                    r.session = session.run();
                } catch (const std::exception& ex) {
                    r.error = ex.what();
                }

                std::lock_guard lock(resultsMutex);
                results[index] = std::move(r);
            }
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    return results;
}

// -----------------------------------------------------------------------------
// CLI parser
// -----------------------------------------------------------------------------

struct Args {
    std::string command;
    std::unordered_map<std::string, std::string> values;
    std::unordered_set<std::string> flags;
};

static Args parseArgs(int argc, char** argv) {
    if (argc < 2) {
        throw std::runtime_error("missing command; use --help");
    }

    Args a;
    a.command = argv[1];

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind("--", 0) != 0) {
            throw std::runtime_error("unexpected positional argument: " + arg);
        }

        if (arg == "--merge" ||
            arg == "--json" ||
            arg == "--help") {
            a.flags.insert(arg.substr(2));
            continue;
        }

        if (i + 1 >= argc) {
            throw std::runtime_error("missing value for " + arg);
        }
        a.values[arg.substr(2)] = argv[++i];
    }

    return a;
}

static std::string required(const Args& a, const std::string& key) {
    const auto it = a.values.find(key);
    if (it == a.values.end() || it->second.empty()) {
        throw std::runtime_error("--" + key + " is required");
    }
    return it->second;
}

static std::string valueOr(
    const Args& a,
    const std::string& key,
    const std::string& fallback)
{
    const auto it = a.values.find(key);
    return it == a.values.end() ? fallback : it->second;
}

static int intValue(
    const Args& a,
    const std::string& key,
    int fallback,
    int minimum,
    int maximum)
{
    const auto it = a.values.find(key);
    if (it == a.values.end()) return fallback;

    int value = 0;
    const auto& s = it->second;
    const auto r = std::from_chars(
        s.data(), s.data() + s.size(), value);
    if (r.ec != std::errc{} ||
        value < minimum ||
        value > maximum) {
        throw std::runtime_error("invalid --" + key);
    }
    return value;
}

static std::vector<std::string> readTaskFile(const fs::path& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open tasks file: " + path.string());

    std::vector<std::string> tasks;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(std::move(line));
        if (line.empty() || line[0] == '#') continue;
        tasks.push_back(std::move(line));
    }
    if (tasks.empty()) {
        throw std::runtime_error("tasks file contains no tasks");
    }
    return tasks;
}

static void printHelp() {
    std::cout <<
R"(RawrXD Scale Value Pack

Commands:

  index
    --workspace PATH

  search
    --workspace PATH
    --query TEXT
    [--top N]

  checkpoint-create
    --workspace PATH
    [--label TEXT]

  checkpoint-list
    --workspace PATH

  checkpoint-restore
    --workspace PATH
    --id CHECKPOINT_ID

  run-isolated
    --agent-exe PATH
    --workspace PATH
    --model PATH
    --task TEXT
    [--max-steps 32]
    [--max-tokens 4096]
    [--timeout-minutes 30]
    [--merge]

  run-many
    --agent-exe PATH
    --workspace PATH
    --model PATH
    --tasks FILE
    [--max-workers 2]
    [--max-steps 32]
    [--max-tokens 4096]
    [--timeout-minutes 30]
    [--merge]

All session artifacts are written below:
  <workspace>\.rawrxd\sessions\<session-id>\

Merge behavior:
  - every merge creates a durable pre-merge checkpoint
  - a file is merged only when the live workspace still matches the
    session's original baseline
  - conflicting files are NOT overwritten
)";
}

} // namespace rawrxd::scale

int main(int argc, char** argv) {
    using namespace rawrxd::scale;

    try {
        if (argc == 1 ||
            (argc >= 2 &&
             (std::string(argv[1]) == "--help" ||
              std::string(argv[1]) == "-h" ||
              std::string(argv[1]) == "help"))) {
            printHelp();
            return 0;
        }

        const Args args = parseArgs(argc, argv);

        if (args.command == "index") {
            WorkspaceIndex index(required(args, "workspace"));
            const auto stats = index.buildIncremental();
            std::cout
                << "GATE=RAWRXD_LOCAL_INDEX_001\n"
                << "INDEX_PATH=" << index.path().string() << "\n"
                << "DISCOVERED=" << stats.discovered << "\n"
                << "REUSED=" << stats.reused << "\n"
                << "REINDEXED=" << stats.reindexed << "\n"
                << "REMOVED=" << stats.removed << "\n"
                << "VERDICT=PASS\n";
            return 0;
        }

        if (args.command == "search") {
            WorkspaceIndex index(required(args, "workspace"));
            const auto stats = index.buildIncremental();
            (void)stats;
            const std::string query = required(args, "query");
            const auto hits = index.search(
                query,
                static_cast<std::size_t>(
                    intValue(args, "top", 20, 1, 200)));

            for (std::size_t i = 0; i < hits.size(); ++i) {
                std::cout
                    << (i + 1) << "\t"
                    << std::fixed << std::setprecision(4)
                    << hits[i].score << "\t"
                    << hits[i].path << "\t";
                for (std::size_t j = 0; j < hits[i].matchedTerms.size(); ++j) {
                    if (j) std::cout << ",";
                    std::cout << hits[i].matchedTerms[j];
                }
                std::cout << "\n";
            }
            return 0;
        }

        if (args.command == "checkpoint-create") {
            CheckpointStore store(required(args, "workspace"));
            const std::string id =
                store.create(valueOr(args, "label", "manual"));
            std::cout
                << "GATE=RAWRXD_CHECKPOINT_CREATE_001\n"
                << "CHECKPOINT_ID=" << id << "\n"
                << "VERDICT=PASS\n";
            return 0;
        }

        if (args.command == "checkpoint-list") {
            CheckpointStore store(required(args, "workspace"));
            for (const auto& id : store.list()) {
                std::cout << id << "\n";
            }
            return 0;
        }

        if (args.command == "checkpoint-restore") {
            CheckpointStore store(required(args, "workspace"));
            const std::string id = required(args, "id");
            store.restore(id);
            std::cout
                << "GATE=RAWRXD_CHECKPOINT_RESTORE_001\n"
                << "CHECKPOINT_ID=" << id << "\n"
                << "VERDICT=PASS\n";
            return 0;
        }

        if (args.command == "run-isolated") {
            const fs::path workspace = required(args, "workspace");
            const fs::path agentExe = required(args, "agent-exe");
            const fs::path model = required(args, "model");
            const std::string task = required(args, "task");

            const int maxSteps =
                intValue(args, "max-steps", 32, 1, 256);
            const int maxTokens =
                intValue(args, "max-tokens", 4096, 1, 65536);
            const int timeoutMinutes =
                intValue(args, "timeout-minutes", 30, 1, 1440);

            AgentSession session(
                workspace,
                agentExe,
                model,
                task,
                maxSteps,
                maxTokens,
                std::chrono::minutes(timeoutMinutes));

            SessionResult result = session.run();

            std::cout
                << result.output
                << "\nGATE=RAWRXD_ISOLATED_AGENT_SESSION_001\n"
                << "SESSION_ID=" << result.id << "\n"
                << "EXIT_CODE=" << result.exitCode << "\n"
                << "TIMED_OUT=" << (result.timedOut ? 1 : 0) << "\n"
                << "CHANGED_FILES=" << result.changes.size() << "\n"
                << "SESSION_SUCCESS=" << (result.success ? 1 : 0) << "\n";

            if (args.flags.count("merge") && result.success) {
                auto merge = session.merge(result);
                std::cout
                    << "MERGE_CHECKPOINT=" << merge.checkpointId << "\n"
                    << "MERGED_FILES=" << merge.merged.size() << "\n"
                    << "MERGE_CONFLICTS=" << merge.conflicts.size() << "\n";
                for (const auto& conflict : merge.conflicts) {
                    std::cout << "CONFLICT=" << conflict << "\n";
                }
                std::cout
                    << "MERGE_VERDICT="
                    << (merge.success ? "PASS" : "HOLD") << "\n";
            }

            std::cout
                << "VERDICT=" << (result.success ? "PASS" : "FAIL") << "\n";
            return result.success ? 0 : 1;
        }

        if (args.command == "run-many") {
            const fs::path workspace = required(args, "workspace");
            const fs::path agentExe = required(args, "agent-exe");
            const fs::path model = required(args, "model");
            const auto tasks = readTaskFile(required(args, "tasks"));

            const int maxWorkers =
                intValue(args, "max-workers", 2, 1, 32);
            const int maxSteps =
                intValue(args, "max-steps", 32, 1, 256);
            const int maxTokens =
                intValue(args, "max-tokens", 4096, 1, 65536);
            const int timeoutMinutes =
                intValue(args, "timeout-minutes", 30, 1, 1440);

            auto results = runMany(
                workspace,
                agentExe,
                model,
                tasks,
                maxWorkers,
                maxSteps,
                maxTokens,
                std::chrono::minutes(timeoutMinutes));

            std::size_t succeeded = 0;
            std::size_t failed = 0;
            std::size_t merged = 0;
            std::size_t conflicts = 0;

            for (auto& item : results) {
                if (!item.session) {
                    ++failed;
                    std::cout
                        << "TASK[" << item.index << "] ERROR "
                        << item.error << "\n";
                    continue;
                }

                auto& sessionResult = *item.session;
                if (sessionResult.success) ++succeeded;
                else ++failed;

                std::cout
                    << "TASK[" << item.index << "] "
                    << "SESSION=" << sessionResult.id << " "
                    << "SUCCESS=" << (sessionResult.success ? 1 : 0) << " "
                    << "CHANGES=" << sessionResult.changes.size() << "\n";

                if (args.flags.count("merge") && sessionResult.success) {
                    // Reconstruct an AgentSession with identical base settings.
                    // merge() itself reads baseline from the completed session artifact,
                    // so the newly generated object's own id/session directory is irrelevant.
                    AgentSession merger(
                        workspace,
                        agentExe,
                        model,
                        item.task,
                        maxSteps,
                        maxTokens,
                        std::chrono::minutes(timeoutMinutes));

                    const auto mr = merger.merge(sessionResult);
                    merged += mr.merged.size();
                    conflicts += mr.conflicts.size();

                    std::cout
                        << "TASK[" << item.index << "] "
                        << "MERGED=" << mr.merged.size() << " "
                        << "CONFLICTS=" << mr.conflicts.size() << " "
                        << "CHECKPOINT=" << mr.checkpointId << "\n";
                    for (const auto& conflict : mr.conflicts) {
                        std::cout
                            << "TASK[" << item.index << "] "
                            << "CONFLICT=" << conflict << "\n";
                    }
                }
            }

            std::cout
                << "GATE=RAWRXD_MULTI_AGENT_ORCHESTRATION_001\n"
                << "TASKS=" << tasks.size() << "\n"
                << "SUCCEEDED=" << succeeded << "\n"
                << "FAILED=" << failed << "\n"
                << "MERGED_FILES=" << merged << "\n"
                << "MERGE_CONFLICTS=" << conflicts << "\n"
                << "VERDICT="
                << (failed == 0 && conflicts == 0 ? "PASS" : "HOLD")
                << "\n";

            return failed == 0 ? 0 : 1;
        }

        throw std::runtime_error("unknown command: " + args.command);
    }
    catch (const std::exception& ex) {
        std::cerr
            << "[RAWRXD_SCALE_FATAL] "
            << ex.what() << "\n";
        return 1;
    }
}
