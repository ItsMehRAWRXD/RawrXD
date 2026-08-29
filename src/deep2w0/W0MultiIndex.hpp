// ============================================================================
// W0MultiIndex.hpp — exact + inverted text (no embeddings / no neural weights)
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_MULTI_INDEX_HPP
#define RAWRXD_DEEP2W0_W0_MULTI_INDEX_HPP

#include "deep2w0/W0GraphStore.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace RawrXD {
namespace W0 {

class MultiIndexEngine {
public:
    void rebuild(const GraphStore& g) {
        m_exact.clear();
        m_inv.clear();
        for (const auto& kv : g.nodes()) {
            const auto& n = kv.second;
            if (!n.name.empty()) m_exact[toLower(n.name)].insert(n.id);
            indexText(n.id, n.name);
            indexText(n.id, n.content);
        }
    }

    std::vector<uint64_t> exact(const std::string& term) const {
        auto it = m_exact.find(toLower(term));
        if (it == m_exact.end()) return {};
        return {it->second.begin(), it->second.end()};
    }

    /// Deterministic lexical retrieval: intersection-preferring term hits.
    std::vector<uint64_t> retrieve(const std::vector<std::string>& terms,
                                   size_t limit = 32) const {
        std::unordered_map<uint64_t, int> scores;
        for (const auto& t : terms) {
            if (t.size() < 2) continue;
            auto e = exact(t);
            for (uint64_t id : e) scores[id] += 10;
            auto it = m_inv.find(toLower(t));
            if (it != m_inv.end()) {
                for (uint64_t id : it->second) scores[id] += 1;
            }
        }
        std::vector<std::pair<int, uint64_t>> ranked;
        ranked.reserve(scores.size());
        for (const auto& kv : scores) ranked.push_back({kv.second, kv.first});
        std::sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first > b.first;
            return a.second < b.second;
        });
        std::vector<uint64_t> out;
        for (size_t i = 0; i < ranked.size() && i < limit; ++i)
            out.push_back(ranked[i].second);
        return out;
    }

private:
    std::unordered_map<std::string, std::unordered_set<uint64_t>> m_exact;
    std::unordered_map<std::string, std::unordered_set<uint64_t>> m_inv;

    static std::string toLower(std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    void indexText(uint64_t id, const std::string& text) {
        std::string tok;
        for (unsigned char ch : text) {
            if (std::isalnum(ch) || ch == '_' || ch == '-') {
                tok.push_back(static_cast<char>(std::tolower(ch)));
            } else if (!tok.empty()) {
                if (tok.size() >= 2) m_inv[tok].insert(id);
                tok.clear();
            }
        }
        if (tok.size() >= 2) m_inv[tok].insert(id);
    }
};

} // namespace W0
} // namespace RawrXD

#endif
