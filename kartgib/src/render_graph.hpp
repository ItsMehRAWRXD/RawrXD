#pragma once
#include <functional>
#include <string>
#include <vector>

struct RenderGraph {
    void add(const char* name, std::function<void()> record);
    void execute();
    uint32_t count() const { return static_cast<uint32_t>(passes_.size()); }

private:
    struct Pass {
        const char* name;
        std::function<void()> record;
    };
    std::vector<Pass> passes_;
};
