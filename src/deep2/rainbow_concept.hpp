#pragma once
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace rawrxd {
// A deterministic concept-index, NOT a cryptographic rainbow table.
// A fingerprint indexes observed concepts; collisions retain every candidate.
inline uint64_t fingerprint(const std::string& s) {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ull; }
    return h;
}
struct Concept {
    std::string text;
    std::string parent;
    uint64_t generation = 0;
    uint64_t key = 0;
};
struct Receipt {
    uint64_t generation = 0;
    size_t imagined = 0, conceived = 0, rejected = 0, collisions = 0;
};
class RainbowConceptLoop {
public:
    using Imagine = std::function<std::vector<std::string>(const Concept&)>;
    using Validate = std::function<bool(const std::string&)>;
    RainbowConceptLoop(Imagine imagine, Validate validate, size_t max_nodes = 10000)
        : imagine_(std::move(imagine)), validate_(std::move(validate)), max_nodes_(max_nodes) {}

    bool seed(const std::string& text) { return insert(text, "", 0); }
    Receipt step() {
        Receipt r; r.generation = ++generation_;
        std::vector<Concept> current;
        for (const auto& s : frontier_) current.push_back(nodes_.at(s));
        frontier_.clear();
        for (const auto& parent : current) {
            auto ideas = imagine_(parent);
            r.imagined += ideas.size();
            for (const auto& idea : ideas) {
                if (!validate_(idea)) { ++r.rejected; continue; }
                if (nodes_.size() >= max_nodes_) { ++r.rejected; continue; }
                const uint64_t k = fingerprint(idea);
                const auto hit = index_.find(k);
                if (hit != index_.end() && !hit->second.empty() && !hit->second.count(idea)) ++r.collisions;
                if (insert(idea, parent.text, generation_)) ++r.conceived;
            }
        }
        return r;
    }
    // Returns every matching candidate, then confirms exact text; a hash alone is not invertible.
    std::vector<Concept> lookup(uint64_t key) const {
        std::vector<Concept> out;
        auto it = index_.find(key);
        if (it != index_.end()) for (const auto& s : it->second) out.push_back(nodes_.at(s));
        return out;
    }
    bool contains(const std::string& s) const { return nodes_.count(s) != 0; }
    size_t size() const { return nodes_.size(); }
    size_t pending() const { return frontier_.size(); }
private:
    bool insert(const std::string& text, const std::string& parent, uint64_t generation) {
        if (text.empty() || nodes_.count(text) || nodes_.size() >= max_nodes_) return false;
        Concept c{text, parent, generation, fingerprint(text)};
        nodes_.emplace(text, c);
        index_[c.key].insert(text);
        frontier_.insert(text);
        return true;
    }
    Imagine imagine_;
    Validate validate_;
    size_t max_nodes_;
    uint64_t generation_ = 0;
    std::map<std::string, Concept> nodes_;
    std::map<uint64_t, std::set<std::string>> index_;
    std::set<std::string> frontier_;
};
} // namespace rawrxd
