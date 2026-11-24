// =============================================================================
// codebase_index.cpp — A3 BM25 codebase index implementation.
// =============================================================================
#include "codebase_index.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace rawrxd::rag {
namespace fs = std::filesystem;

std::vector<std::string> Tokenize(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : text) {
        if (std::isalnum((unsigned char)c) || c == '_') {
            cur += (char)std::tolower((unsigned char)c);
        } else if (!cur.empty()) {
            out.push_back(cur);
            cur.clear();
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

namespace {

bool IsSource(const std::string& ext) {
    static const std::set<std::string> ok = {
        ".c", ".cc", ".cpp", ".h", ".hpp", ".hxx", ".cs", ".js", ".ts",
        ".py", ".rs", ".go", ".java", ".ps1", ".md", ".txt", ".json",
        ".yml", ".yaml", ".cmake"};
    return ok.count(ext) > 0;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

}  // namespace

void CodebaseIndex::IndexPath(const std::string& path, int max_files) {
    std::error_code ec;
    std::vector<std::string> files;
    if (fs::is_directory(path, ec)) {
        fs::recursive_directory_iterator it(path,
            fs::directory_options::skip_permission_denied, ec), end;
        for (; it != end && (int)files.size() < max_files; it.increment(ec)) {
            if (ec) break;
            const std::string p = it->path().string();
            if (p.find("\\.git\\") != std::string::npos ||
                p.find("\\build") != std::string::npos ||
                p.find("\\node_modules\\") != std::string::npos)
                continue;
            if (it->is_regular_file(ec) && IsSource(it->path().extension().string()))
                files.push_back(p);
        }
    } else if (fs::is_regular_file(path, ec)) {
        files.push_back(path);
    }

    for (const auto& f : files) {
        std::ifstream in(f, std::ios::binary);
        if (!in) continue;
        std::ostringstream ss;
        ss << in.rdbuf();
        const std::string body = ss.str();
        if (body.size() > 4 * 1024 * 1024) continue;

        // Chunk by ~40-line windows on line boundaries.
        std::istringstream lines(body);
        std::string line;
        std::vector<std::string> buf;
        int line_no = 0, chunk_start = 1;
        auto flush = [&]() {
            if (buf.empty()) return;
            Chunk c;
            c.file = f;
            c.start_line = chunk_start;
            c.end_line = line_no;
            for (const auto& l : buf) { c.text += l; c.text += "\n"; }
            const size_t idx = chunks_.size();
            chunks_.push_back(std::move(c));
            const auto toks = Tokenize(chunks_.back().text);
            doc_lens_.push_back({idx, toks.size()});
            for (const auto& t : toks) {
                vocab_[t];
                postings_[t].push_back({idx, 1});
            }
            buf.clear();
            chunk_start = line_no + 1;
        };
        while (std::getline(lines, line)) {
            ++line_no;
            buf.push_back(line);
            if ((int)buf.size() >= 40) flush();
        }
        flush();
    }

    double total = 0.0;
    for (const auto& d : doc_lens_) total += (double)d.length;
    avgdl_ = doc_lens_.empty() ? 1.0 : (total / (double)doc_lens_.size());
}

std::vector<Hit> CodebaseIndex::Query(const std::string& query, int topK) const {
    std::vector<Hit> hits;
    const auto q = Tokenize(query);
    if (q.empty() || chunks_.empty()) return hits;

    const double k1 = 1.2, b = 0.75;
    const double N = (double)chunks_.size();
    std::unordered_map<size_t, double> scores;

    for (const auto& term : q) {
        auto it = postings_.find(term);
        if (it == postings_.end()) continue;
        const double df = (double)it->second.size();
        const double idf = std::log(1.0 + (N - df + 0.5) / (df + 0.5));
        for (const auto& p : it->second) {
            const size_t idx = p.first;
            const double dl = (double)doc_lens_[idx].length;
            const double denom = 1.0 - b + b * (dl / avgdl_);
            scores[idx] += idf * (1.0 + k1) / (denom + k1);
        }
    }

    std::vector<std::pair<double, size_t>> ranked;
    ranked.reserve(scores.size());
    for (const auto& s : scores) ranked.push_back({s.second, s.first});
    std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& c) {
        return a.first > c.first;
    });
    for (size_t i = 0; i < ranked.size() && (int)hits.size() < topK; ++i) {
        const auto& ch = chunks_[ranked[i].second];
        Hit h;
        h.file = ch.file;
        h.start_line = ch.start_line;
        h.end_line = ch.end_line;
        h.score = ranked[i].first;
        std::string snip = ch.text.substr(0, 160);
        h.snippet = snip;
        hits.push_back(std::move(h));
    }
    return hits;
}

std::string CodebaseIndex::ToJson(const std::vector<Hit>& hits) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < hits.size(); ++i) {
        const auto& h = hits[i];
        out << "{\"file\":\"" << JsonEscape(h.file) << "\",\"start_line\":"
            << h.start_line << ",\"end_line\":" << h.end_line
            << ",\"score\":" << h.score << ",\"snippet\":\""
            << JsonEscape(h.snippet) << "\"}";
        if (i + 1 < hits.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::rag