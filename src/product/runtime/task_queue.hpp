#pragma once
#include <cstdint>
#include <deque>
#include <string>
namespace rawr::product {

enum class TaskPri : uint8_t { Low = 0, Normal = 1, High = 2, Urgent = 3 };

struct Task {
    uint64_t id = 0;
    TaskPri pri = TaskPri::Normal;
    uint64_t gen = 0;
    std::string kind;
    std::string payload;
    bool stale = false;
};

struct TaskQueue {
    std::deque<Task> items;
    uint64_t nextId = 1;
    uint64_t currentGen = 1;

    uint64_t bumpGen() { return ++currentGen; }

    uint64_t enqueue(TaskPri p, const char* kind, const char* payload) {
        Task t{};
        t.id = nextId++;
        t.pri = p;
        t.gen = currentGen;
        t.kind = kind ? kind : "";
        t.payload = payload ? payload : "";
        items.push_back(t);
        return t.id;
    }

    void dropStale(uint64_t liveGen) {
        for (auto& t : items)
            if (t.gen != liveGen) t.stale = true;
        std::deque<Task> keep;
        for (auto& t : items)
            if (!t.stale) keep.push_back(t);
        items.swap(keep);
    }

    bool pop(Task& out) {
        if (items.empty()) return false;
        size_t best = 0;
        for (size_t i = 1; i < items.size(); ++i)
            if ((int)items[i].pri > (int)items[best].pri) best = i;
        out = items[best];
        items.erase(items.begin() + (ptrdiff_t)best);
        return true;
    }
};

} // namespace rawr::product
