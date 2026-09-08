// rawr_copilot_markov.cpp
// Dependency-free local code autocomplete using a sparse, trillion-slot logical
// Markov parameter space. C++17 standard library only.
//
// Build:
//   cl /std:c++17 /O2 /EHsc rawr_copilot_markov.cpp
//   g++ -std=c++17 -O3 -DNDEBUG rawr_copilot_markov.cpp -o rawr_copilot
//
// Commands:
//   rawr_copilot train model.rmc <path> [path ...] [--order 6] [--max-edges 48]
//   rawr_copilot complete model.rmc --text "std::vec" [--top 5] [--tokens 16]
//   rawr_copilot complete model.rmc --file main.cpp [--cursor 1234] [--top 5]
//   rawr_copilot repl model.rmc
//   rawr_copilot stdio model.rmc
//   rawr_copilot stats model.rmc
//
// stdio protocol:
//   request:  COMPLETE <top> <tokens> <bytes>\n<exactly bytes bytes of context>
//   response: RESULT <count>\n
//             SCORE <float> BYTES <n>\n<exactly n bytes>\n
//             ...
//             END\n
//
// The "1T parameters" are a logical address namespace. Only transitions actually
// observed in the user's corpus are materialized in RAM/disk.
//
// Product law: RawrCopilotMarkovLaw.hpp / LAW.txt / BOUNDARY.txt
// DEEP2_HOTPATH=0 — do not wire into lavapath / QKV / generateStream.

#include "RawrCopilotMarkovLaw.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace rawr {

static constexpr uint64_t LOGICAL_PARAMETER_SLOTS = 1'000'000'000'000ULL;
static constexpr uint32_t MODEL_VERSION = 1;
static constexpr uint32_t DEFAULT_ORDER = 6;
static constexpr uint32_t DEFAULT_MAX_EDGES = 48;
static constexpr uint32_t TOKEN_BOS = 0;
static constexpr uint32_t TOKEN_EOS = 1;
static constexpr uint32_t TOKEN_NL  = 2;
static constexpr const char* MAGIC = "RMC1";

static uint64_t mix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static uint64_t hash_bytes(std::string_view s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return mix64(h);
}

static bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

static bool is_ident_start(unsigned char c) {
    return std::isalpha(c) || c == '_' || c >= 128;
}
static bool is_ident_continue(unsigned char c) {
    return std::isalnum(c) || c == '_' || c >= 128;
}

static std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open: " + p.string());
    in.seekg(0, std::ios::end);
    const auto n = in.tellg();
    in.seekg(0, std::ios::beg);
    std::string s;
    if (n > 0) {
        s.resize(static_cast<size_t>(n));
        in.read(s.data(), static_cast<std::streamsize>(s.size()));
    }
    return s;
}

static bool code_extension(const fs::path& p) {
    static const std::unordered_set<std::string> exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".inl", ".ipp", ".ixx", ".m", ".mm", ".cs", ".java", ".kt",
        ".rs", ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".swift",
        ".zig", ".lua", ".rb", ".php", ".sh", ".ps1", ".asm", ".s",
        ".sql", ".html", ".htm", ".css", ".scss", ".json", ".toml",
        ".yaml", ".yml", ".xml", ".md", ".txt", ".cmake"
    };
    std::string e = p.extension().string();
    std::transform(e.begin(), e.end(), e.begin(), [](unsigned char c){ return char(std::tolower(c)); });
    return exts.count(e) != 0 || p.filename() == "CMakeLists.txt" || p.filename() == "Makefile";
}

struct Lexer {
    static std::vector<std::string> tokenize(std::string_view src) {
        std::vector<std::string> out;
        out.reserve(src.size() / 4 + 16);
        size_t i = 0;
        while (i < src.size()) {
            unsigned char c = static_cast<unsigned char>(src[i]);

            if (c == '\r') { ++i; continue; }
            if (c == '\n') { out.emplace_back("<NL>"); ++i; continue; }
            if (std::isspace(c)) { ++i; continue; }

            if (is_ident_start(c)) {
                size_t j = i + 1;
                while (j < src.size() && is_ident_continue(static_cast<unsigned char>(src[j]))) ++j;
                out.emplace_back(src.substr(i, j - i));
                i = j;
                continue;
            }

            if (std::isdigit(c)) {
                size_t j = i + 1;
                while (j < src.size()) {
                    unsigned char d = static_cast<unsigned char>(src[j]);
                    if (std::isalnum(d) || d == '_' || d == '.' || d == '+' || d == '-') ++j;
                    else break;
                }
                out.emplace_back(src.substr(i, j - i));
                i = j;
                continue;
            }

            if (c == '"' || c == '\'') {
                const char quote = char(c);
                size_t j = i + 1;
                bool esc = false;
                while (j < src.size()) {
                    char d = src[j++];
                    if (esc) { esc = false; continue; }
                    if (d == '\\') { esc = true; continue; }
                    if (d == quote) break;
                    if (d == '\n') break;
                }
                auto lit = src.substr(i, j - i);
                if (lit.size() <= 96) out.emplace_back(lit);
                else out.emplace_back(quote == '"' ? "<STR>" : "<CHAR>");
                i = j;
                continue;
            }

            if (i + 1 < src.size() && src[i] == '/' && src[i+1] == '/') {
                out.emplace_back("//");
                i += 2;
                continue;
            }
            if (i + 1 < src.size() && src[i] == '/' && src[i+1] == '*') {
                out.emplace_back("/*");
                i += 2;
                continue;
            }

            static const std::array<std::string_view, 30> ops = {
                "<<=", ">>=", "...", "->*", "<=>",
                "::", "->", "++", "--", "==", "!=", "<=", ">=", "&&", "||",
                "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>",
                "##", "?.", "??", "=>", "**"
            };
            bool matched = false;
            for (auto op : ops) {
                if (i + op.size() <= src.size() && src.substr(i, op.size()) == op) {
                    out.emplace_back(op);
                    i += op.size();
                    matched = true;
                    break;
                }
            }
            if (matched) continue;

            out.emplace_back(1, char(c));
            ++i;
        }
        return out;
    }

    static std::pair<std::string, std::string> detach_trailing_prefix(std::string_view src) {
        size_t end = src.size();
        size_t begin = end;
        while (begin > 0 && is_ident_continue(static_cast<unsigned char>(src[begin-1]))) --begin;
        if (begin < end && is_ident_start(static_cast<unsigned char>(src[begin]))) {
            return {std::string(src.substr(0, begin)), std::string(src.substr(begin, end - begin))};
        }
        return {std::string(src), {}};
    }
};

struct Vocabulary {
    std::vector<std::string> id_to_token;
    std::unordered_map<std::string, uint32_t> token_to_id;

    Vocabulary() {
        add_fixed("<BOS>");
        add_fixed("<EOS>");
        add_fixed("<NL>");
    }

    void clear() {
        id_to_token.clear();
        token_to_id.clear();
    }

    void add_fixed(const std::string& s) {
        uint32_t id = static_cast<uint32_t>(id_to_token.size());
        id_to_token.push_back(s);
        token_to_id.emplace(s, id);
    }

    uint32_t intern(const std::string& s) {
        auto it = token_to_id.find(s);
        if (it != token_to_id.end()) return it->second;
        uint32_t id = static_cast<uint32_t>(id_to_token.size());
        id_to_token.push_back(s);
        token_to_id.emplace(s, id);
        return id;
    }

    std::optional<uint32_t> lookup(std::string_view s) const {
        auto it = token_to_id.find(std::string(s));
        if (it == token_to_id.end()) return std::nullopt;
        return it->second;
    }
};

struct ContextKey {
    uint64_t slot = 0;
    uint64_t fingerprint = 0;
    uint8_t order = 0;

    bool operator==(const ContextKey& o) const {
        return slot == o.slot && fingerprint == o.fingerprint && order == o.order;
    }
};

struct ContextKeyHash {
    size_t operator()(const ContextKey& k) const noexcept {
        return static_cast<size_t>(mix64(k.slot ^ mix64(k.fingerprint) ^ (uint64_t(k.order) << 56)));
    }
};

struct Edge {
    uint32_t token = 0;
    uint32_t count = 0;
};

struct Node {
    uint64_t total = 0;
    std::vector<Edge> edges;
};

struct Candidate {
    uint32_t token = 0;
    double score = 0.0;
    uint64_t support = 0;
};

class MarkovModel {
public:
    uint32_t max_order = DEFAULT_ORDER;
    uint32_t max_edges = DEFAULT_MAX_EDGES;
    Vocabulary vocab;
    std::unordered_map<ContextKey, Node, ContextKeyHash> nodes;
    uint64_t training_tokens = 0;
    uint64_t training_files = 0;

    explicit MarkovModel(uint32_t order = DEFAULT_ORDER, uint32_t edge_cap = DEFAULT_MAX_EDGES)
        : max_order(std::max<uint32_t>(1, std::min<uint32_t>(order, 12))),
          max_edges(std::max<uint32_t>(4, std::min<uint32_t>(edge_cap, 256))) {}

    static ContextKey make_context(const std::vector<uint32_t>& seq, size_t end, uint32_t order) {
        uint64_t h = 0x84222325cbf29ce4ULL ^ order;
        size_t begin = end >= order ? end - order : 0;
        for (size_t i = begin; i < end; ++i) {
            h = mix64(h ^ (uint64_t(seq[i]) + 0x9e3779b97f4a7c15ULL + (i - begin) * 0x100000001b3ULL));
        }
        ContextKey k;
        k.slot = h % LOGICAL_PARAMETER_SLOTS;
        k.fingerprint = mix64(h ^ 0xd6e8feb86659fd93ULL);
        k.order = static_cast<uint8_t>(order);
        return k;
    }

    uint64_t logical_parameter_id(const ContextKey& ctx, uint32_t next) const {
        uint64_t h = mix64(ctx.fingerprint ^ (uint64_t(next) * 0x9e3779b97f4a7c15ULL));
        return h % LOGICAL_PARAMETER_SLOTS;
    }

    void observe(const ContextKey& key, uint32_t next) {
        Node& n = nodes[key];
        ++n.total;
        for (auto& e : n.edges) {
            if (e.token == next) {
                if (e.count != std::numeric_limits<uint32_t>::max()) ++e.count;
                return;
            }
        }
        if (n.edges.size() < max_edges) {
            n.edges.push_back({next, 1});
            return;
        }
        auto it = std::min_element(n.edges.begin(), n.edges.end(), [](const Edge& a, const Edge& b){
            return a.count < b.count;
        });
        if (it != n.edges.end() && it->count <= 1) *it = {next, 1};
    }

    void train_tokens(const std::vector<std::string>& toks) {
        std::vector<uint32_t> ids;
        ids.reserve(toks.size() + max_order + 2);
        for (uint32_t i = 0; i < max_order; ++i) ids.push_back(TOKEN_BOS);
        for (const auto& t : toks) ids.push_back(vocab.intern(t));
        ids.push_back(TOKEN_EOS);

        const size_t start = max_order;
        for (size_t pos = start; pos < ids.size(); ++pos) {
            uint32_t next = ids[pos];
            for (uint32_t order = 1; order <= max_order; ++order) {
                if (pos < order) break;
                observe(make_context(ids, pos, order), next);
            }
            ++training_tokens;
        }
    }

    void train_text(std::string_view text) {
        train_tokens(Lexer::tokenize(text));
        ++training_files;
    }

    void train_path(const fs::path& root) {
        std::error_code ec;
        if (fs::is_regular_file(root, ec)) {
            if (code_extension(root)) {
                try { train_text(read_file(root)); }
                catch (const std::exception& e) { std::cerr << "skip " << root << ": " << e.what() << "\n"; }
            }
            return;
        }
        if (!fs::is_directory(root, ec)) return;

        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end; it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            const auto& p = it->path();
            if (it->is_directory(ec)) {
                const std::string name = p.filename().string();
                if (name == ".git" || name == ".svn" || name == "node_modules" || name == "build" ||
                    name == "build-fd" || name == "dist" || name == ".vs") {
                    it.disable_recursion_pending();
                }
                continue;
            }
            if (!it->is_regular_file(ec) || !code_extension(p)) continue;
            try {
                auto s = read_file(p);
                if (s.size() > 16 * 1024 * 1024) continue;
                train_text(s);
                if ((training_files % 100) == 0) {
                    std::cerr << "trained files=" << training_files
                              << " tokens=" << training_tokens
                              << " nodes=" << nodes.size() << "\r" << std::flush;
                }
            } catch (...) {}
        }
        std::cerr << "\n";
    }

    std::vector<uint32_t> encode_known(const std::vector<std::string>& toks) const {
        std::vector<uint32_t> ids;
        ids.reserve(max_order + toks.size());
        for (uint32_t i = 0; i < max_order; ++i) ids.push_back(TOKEN_BOS);
        for (const auto& t : toks) {
            auto id = vocab.lookup(t);
            if (id) ids.push_back(*id);
            else ids.push_back(0x80000000u | uint32_t(hash_bytes(t) & 0x7fffffffu));
        }
        return ids;
    }

    std::vector<Candidate> next_candidates(const std::vector<uint32_t>& history,
                                           std::string_view prefix,
                                           size_t limit = 64) const {
        std::unordered_map<uint32_t, Candidate> merged;
        const uint32_t usable_order = std::min<uint32_t>(max_order, static_cast<uint32_t>(history.size()));

        for (uint32_t order = usable_order; order >= 1; --order) {
            ContextKey key = make_context(history, history.size(), order);
            auto it = nodes.find(key);
            if (it != nodes.end() && it->second.total) {
                const double order_weight = std::pow(2.15, double(order - 1));
                const double denom = double(it->second.total) + 0.25 * double(it->second.edges.size());
                for (const auto& e : it->second.edges) {
                    if (e.token >= vocab.id_to_token.size()) continue;
                    const auto& text = vocab.id_to_token[e.token];
                    if (!prefix.empty() && !starts_with(text, prefix)) continue;
                    double p = (double(e.count) + 0.25) / denom;
                    auto& c = merged[e.token];
                    c.token = e.token;
                    c.score += order_weight * p;
                    c.support += e.count;
                }
            }
            if (order == 1) break;
        }

        std::vector<Candidate> out;
        out.reserve(merged.size());
        for (auto& kv : merged) out.push_back(kv.second);
        std::sort(out.begin(), out.end(), [](const Candidate& a, const Candidate& b) {
            if (a.score != b.score) return a.score > b.score;
            return a.support > b.support;
        });
        if (out.size() > limit) out.resize(limit);
        return out;
    }

    struct Completion {
        std::vector<uint32_t> tokens;
        double log_score = 0.0;
    };

    std::vector<Completion> complete_ids(std::vector<uint32_t> history,
                                         std::string_view first_prefix,
                                         size_t top_k,
                                         size_t max_new_tokens) const {
        struct Beam {
            std::vector<uint32_t> history;
            std::vector<uint32_t> made;
            double score = 0.0;
            bool done = false;
        };

        const size_t beam_width = std::max<size_t>(top_k * 4, 12);
        std::vector<Beam> beam(1);
        beam[0].history = std::move(history);

        for (size_t step = 0; step < max_new_tokens; ++step) {
            std::vector<Beam> next;
            for (const auto& b : beam) {
                if (b.done) { next.push_back(b); continue; }
                auto cand = next_candidates(b.history, step == 0 ? first_prefix : std::string_view{}, 16);
                if (cand.empty()) {
                    Beam x = b; x.done = true; next.push_back(std::move(x));
                    continue;
                }
                const double norm = [&](){ double s=0; for (auto& c:cand) s += c.score; return s > 0 ? s : 1.0; }();
                const size_t branch = std::min<size_t>(cand.size(), step < 2 ? 8 : 4);
                for (size_t i = 0; i < branch; ++i) {
                    Beam x = b;
                    const auto& c = cand[i];
                    x.made.push_back(c.token);
                    x.history.push_back(c.token);
                    if (x.history.size() > max_order * 4) {
                        x.history.erase(x.history.begin(), x.history.end() - max_order * 2);
                    }
                    const double p = std::max(1e-12, c.score / norm);
                    x.score += std::log(p);
                    if (c.token == TOKEN_EOS) x.done = true;
                    if (x.made.size() >= 2 && c.token < vocab.id_to_token.size()) {
                        const auto& t = vocab.id_to_token[c.token];
                        if (t == ";" || t == "}" || t == "<NL>") x.done = true;
                    }
                    next.push_back(std::move(x));
                }
            }

            std::sort(next.begin(), next.end(), [](const Beam& a, const Beam& b) {
                double sa = a.score / std::pow(std::max<size_t>(1, a.made.size()), 0.60);
                double sb = b.score / std::pow(std::max<size_t>(1, b.made.size()), 0.60);
                return sa > sb;
            });
            if (next.size() > beam_width) next.resize(beam_width);
            beam.swap(next);
            bool all_done = true;
            for (auto& b : beam) all_done = all_done && b.done;
            if (all_done) break;
        }

        std::vector<Completion> out;
        std::unordered_set<std::string> dedup;
        for (auto& b : beam) {
            if (b.made.empty()) continue;
            std::string key;
            for (auto id : b.made) { key += std::to_string(id); key.push_back(','); }
            if (!dedup.insert(key).second) continue;
            out.push_back({std::move(b.made), b.score});
            if (out.size() >= top_k) break;
        }
        return out;
    }

    static bool wordish(std::string_view t) {
        if (t.empty()) return false;
        unsigned char c = static_cast<unsigned char>(t[0]);
        return is_ident_start(c) || std::isdigit(c) || t[0] == '"' || t[0] == '\'' || t == "<STR>" || t == "<CHAR>";
    }

    std::string render(const std::vector<uint32_t>& ids, std::string_view first_prefix = {}) const {
        std::string out;
        std::string prev;
        bool first = true;
        for (uint32_t id : ids) {
            if (id == TOKEN_EOS || id == TOKEN_BOS) continue;
            if (id >= vocab.id_to_token.size()) continue;
            std::string t = vocab.id_to_token[id];
            if (first && !first_prefix.empty() && starts_with(t, first_prefix)) {
                t.erase(0, first_prefix.size());
            }
            first = false;
            if (t == "<NL>") {
                out.push_back('\n');
                prev = t;
                continue;
            }
            bool no_space_before = (t == ";" || t == "," || t == "." || t == ")" || t == "]" || t == "}" ||
                                    t == "::" || t == "->" || t == "(" || t == "[" || t == ":" || t == "?");
            bool no_space_after_prev = (prev == "(" || prev == "[" || prev == "{" || prev == "." || prev == "::" ||
                                        prev == "->" || prev == "#" || prev == "@" || prev == "<NL>");
            bool need_space = !out.empty() && out.back() != '\n' && !no_space_before && !no_space_after_prev &&
                              (wordish(prev) || wordish(t) || prev == ")" || prev == "]");
            if (need_space) out.push_back(' ');
            out += t;
            prev = vocab.id_to_token[id];
        }
        return out;
    }

    struct TextCompletion { double score; std::string text; };

    std::vector<TextCompletion> complete_text(std::string_view context,
                                              size_t top_k = 5,
                                              size_t max_new_tokens = 16) const {
        auto [base, prefix] = Lexer::detach_trailing_prefix(context);
        auto toks = Lexer::tokenize(base);
        auto hist = encode_known(toks);
        auto cs = complete_ids(std::move(hist), prefix, top_k, max_new_tokens);
        std::vector<TextCompletion> out;
        out.reserve(cs.size());
        for (auto& c : cs) out.push_back({c.log_score, render(c.tokens, prefix)});
        return out;
    }

    template<class T>
    static void write_pod(std::ostream& o, const T& v) {
        o.write(reinterpret_cast<const char*>(&v), sizeof(v));
        if (!o) throw std::runtime_error("model write failed");
    }
    template<class T>
    static void read_pod(std::istream& i, T& v) {
        i.read(reinterpret_cast<char*>(&v), sizeof(v));
        if (!i) throw std::runtime_error("model read failed");
    }

    void save(const fs::path& p) const {
        fs::path tmp = p; tmp += ".tmp";
        std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
        if (!o) throw std::runtime_error("cannot create model: " + tmp.string());
        o.write(MAGIC, 4);
        write_pod(o, MODEL_VERSION);
        write_pod(o, max_order);
        write_pod(o, max_edges);
        write_pod(o, training_tokens);
        write_pod(o, training_files);
        uint64_t slots = LOGICAL_PARAMETER_SLOTS;
        write_pod(o, slots);
        uint64_t vc = vocab.id_to_token.size();
        uint64_t nc = nodes.size();
        write_pod(o, vc);
        write_pod(o, nc);

        for (const auto& s : vocab.id_to_token) {
            uint32_t n = static_cast<uint32_t>(s.size());
            write_pod(o, n);
            o.write(s.data(), n);
        }
        for (const auto& kv : nodes) {
            write_pod(o, kv.first.slot);
            write_pod(o, kv.first.fingerprint);
            write_pod(o, kv.first.order);
            write_pod(o, kv.second.total);
            uint32_t ec = static_cast<uint32_t>(kv.second.edges.size());
            write_pod(o, ec);
            for (const auto& e : kv.second.edges) {
                write_pod(o, e.token);
                write_pod(o, e.count);
            }
        }
        o.close();
        if (!o) throw std::runtime_error("model flush failed");
        std::error_code ec;
        fs::remove(p, ec);
        ec.clear();
        fs::rename(tmp, p, ec);
        if (ec) throw std::runtime_error("cannot finalize model: " + ec.message());
    }

    static MarkovModel load(const fs::path& p) {
        std::ifstream i(p, std::ios::binary);
        if (!i) throw std::runtime_error("cannot open model: " + p.string());
        char magic[4]{}; i.read(magic, 4);
        if (std::memcmp(magic, MAGIC, 4) != 0) throw std::runtime_error("bad model magic");
        uint32_t ver=0, order=0, edge_cap=0;
        uint64_t tt=0, tf=0, slots=0, vc=0, nc=0;
        read_pod(i, ver); read_pod(i, order); read_pod(i, edge_cap);
        read_pod(i, tt); read_pod(i, tf); read_pod(i, slots); read_pod(i, vc); read_pod(i, nc);
        if (ver != MODEL_VERSION || slots != LOGICAL_PARAMETER_SLOTS) throw std::runtime_error("incompatible model version");
        if (vc > 50'000'000ULL || nc > 2'000'000'000ULL) throw std::runtime_error("model header unreasonable");

        MarkovModel m(order, edge_cap);
        m.training_tokens = tt; m.training_files = tf;
        m.vocab.clear();
        m.vocab.id_to_token.reserve(static_cast<size_t>(vc));
        for (uint64_t n = 0; n < vc; ++n) {
            uint32_t len=0; read_pod(i, len);
            if (len > 1'048'576) throw std::runtime_error("token too large");
            std::string s(len, '\0'); i.read(s.data(), len);
            if (!i) throw std::runtime_error("truncated vocabulary");
            uint32_t id = static_cast<uint32_t>(m.vocab.id_to_token.size());
            m.vocab.id_to_token.push_back(s);
            m.vocab.token_to_id.emplace(std::move(s), id);
        }
        m.nodes.reserve(static_cast<size_t>(std::min<uint64_t>(nc * 5 / 4 + 1, size_t(-1))));
        for (uint64_t n = 0; n < nc; ++n) {
            ContextKey k; Node node; uint32_t ec=0;
            read_pod(i, k.slot); read_pod(i, k.fingerprint); read_pod(i, k.order);
            read_pod(i, node.total); read_pod(i, ec);
            if (ec > 4096) throw std::runtime_error("edge count unreasonable");
            node.edges.resize(ec);
            for (auto& e : node.edges) { read_pod(i, e.token); read_pod(i, e.count); }
            m.nodes.emplace(k, std::move(node));
        }
        return m;
    }

    uint64_t materialized_edges() const {
        uint64_t n=0; for (const auto& kv : nodes) n += kv.second.edges.size(); return n;
    }

    void print_stats(std::ostream& o) const {
        o << "logical_parameter_slots=" << LOGICAL_PARAMETER_SLOTS << "\n"
          << "materialized_contexts=" << nodes.size() << "\n"
          << "materialized_transitions=" << materialized_edges() << "\n"
          << "vocabulary=" << vocab.id_to_token.size() << "\n"
          << "max_order=" << max_order << "\n"
          << "max_edges_per_context=" << max_edges << "\n"
          << "training_files=" << training_files << "\n"
          << "training_tokens=" << training_tokens << "\n";
    }
};

static size_t arg_size(const std::vector<std::string>& a, const std::string& name, size_t fallback) {
    for (size_t i = 0; i + 1 < a.size(); ++i) if (a[i] == name) return static_cast<size_t>(std::stoull(a[i+1]));
    return fallback;
}
static std::optional<std::string> arg_value(const std::vector<std::string>& a, const std::string& name) {
    for (size_t i = 0; i + 1 < a.size(); ++i) if (a[i] == name) return a[i+1];
    return std::nullopt;
}

static void print_completions(const MarkovModel& m, std::string_view ctx, size_t top, size_t tokens) {
    auto out = m.complete_text(ctx, top, tokens);
    for (size_t i = 0; i < out.size(); ++i) {
        std::cout << "[" << (i+1) << "] score=" << std::fixed << std::setprecision(4) << out[i].score << "\n"
                  << out[i].text << "\n---\n";
    }
}

static int command_train(const std::vector<std::string>& a) {
    if (a.size() < 4) throw std::runtime_error("train requires model path and at least one corpus path");
    const fs::path model_path = a[2];
    uint32_t order = static_cast<uint32_t>(arg_size(a, "--order", DEFAULT_ORDER));
    uint32_t max_edges = static_cast<uint32_t>(arg_size(a, "--max-edges", DEFAULT_MAX_EDGES));
    MarkovModel m(order, max_edges);

    for (size_t i = 3; i < a.size(); ++i) {
        if (a[i] == "--order" || a[i] == "--max-edges") { ++i; continue; }
        m.train_path(fs::path(a[i]));
    }
    m.print_stats(std::cerr);
    m.save(model_path);
    std::cerr << "saved " << model_path << "\n";
    return 0;
}

static int command_complete(const std::vector<std::string>& a) {
    if (a.size() < 3) throw std::runtime_error("complete requires model path");
    auto m = MarkovModel::load(a[2]);
    size_t top = arg_size(a, "--top", 5);
    size_t tokens = arg_size(a, "--tokens", 16);
    std::string ctx;
    if (auto t = arg_value(a, "--text")) ctx = *t;
    else if (auto f = arg_value(a, "--file")) {
        ctx = read_file(*f);
        size_t cursor = arg_size(a, "--cursor", ctx.size());
        if (cursor < ctx.size()) ctx.resize(cursor);
    } else {
        std::ostringstream ss; ss << std::cin.rdbuf(); ctx = ss.str();
    }
    print_completions(m, ctx, top, tokens);
    return 0;
}

static int command_repl(const std::vector<std::string>& a) {
    if (a.size() < 3) throw std::runtime_error("repl requires model path");
    auto m = MarkovModel::load(a[2]);
    std::cerr << "rawr_copilot repl. Enter code prefix; blank line exits.\n";
    for (std::string line; std::getline(std::cin, line); ) {
        if (line.empty()) break;
        print_completions(m, line, 5, 16);
    }
    return 0;
}

static int command_stdio(const std::vector<std::string>& a) {
    if (a.size() < 3) throw std::runtime_error("stdio requires model path");
    auto m = MarkovModel::load(a[2]);
    std::string header;
    while (std::getline(std::cin, header)) {
        if (header == "QUIT") break;
        std::istringstream hs(header);
        std::string op; size_t top=0, toks=0, bytes=0;
        hs >> op >> top >> toks >> bytes;
        if (op != "COMPLETE" || !hs || bytes > 64 * 1024 * 1024) {
            std::cout << "ERROR bad_request\n" << std::flush;
            continue;
        }
        std::string ctx(bytes, '\0');
        std::cin.read(ctx.data(), static_cast<std::streamsize>(bytes));
        if (!std::cin) break;
        if (std::cin.peek() == '\n') std::cin.get();
        auto out = m.complete_text(ctx, std::max<size_t>(1, top), std::max<size_t>(1, toks));
        std::cout << "RESULT " << out.size() << "\n";
        for (auto& c : out) {
            std::cout << "SCORE " << std::setprecision(17) << c.score << " BYTES " << c.text.size() << "\n";
            std::cout.write(c.text.data(), static_cast<std::streamsize>(c.text.size()));
            std::cout << "\n";
        }
        std::cout << "END\n" << std::flush;
    }
    return 0;
}

static void usage() {
    std::cerr
      << "Rawr Copilot Markov - dependency-free local autocomplete\n"
      << "\n"
      << "train:    rawr_copilot train model.rmc <path> [path...] [--order 6] [--max-edges 48]\n"
      << "complete: rawr_copilot complete model.rmc --text \"std::vec\" [--top 5] [--tokens 16]\n"
      << "          rawr_copilot complete model.rmc --file x.cpp [--cursor byte_offset]\n"
      << "repl:     rawr_copilot repl model.rmc\n"
      << "stdio:    rawr_copilot stdio model.rmc\n"
      << "stats:    rawr_copilot stats model.rmc\n";
}

} // namespace rawr

int main(int argc, char** argv) {
    using namespace rawr;
    try {
        std::vector<std::string> a(argv, argv + argc);
        if (a.size() < 2) { usage(); return 2; }
        if (a[1] == "train") return command_train(a);
        if (a[1] == "complete") return command_complete(a);
        if (a[1] == "repl") return command_repl(a);
        if (a[1] == "stdio") return command_stdio(a);
        if (a[1] == "stats") {
            if (a.size() < 3) throw std::runtime_error("stats requires model path");
            auto m = MarkovModel::load(a[2]);
            m.print_stats(std::cout);
            return 0;
        }
        usage();
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
}
