#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace rawr::product {

enum class EvKind : uint8_t {
    Editor = 0,
    Index = 1,
    Infer = 2,
    Tool = 3,
    Agent = 4,
    Fail = 5
};

struct Ev {
    EvKind kind = EvKind::Editor;
    uint64_t gen = 0;
    std::string name;
    std::string detail;
};

struct EventBus {
    std::vector<Ev> q;
    void push(EvKind k, uint64_t gen, const char* n, const char* d) {
        q.push_back(Ev{k, gen, n ? n : "", d ? d : ""});
    }
    size_t size() const { return q.size(); }
    void clear() { q.clear(); }
};

} // namespace rawr::product
