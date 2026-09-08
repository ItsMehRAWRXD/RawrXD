#pragma once
#include "tool_runtime.hpp"
#include <cstring>
#include <string>
#include <vector>
namespace rawr::product {

struct ToolEntry {
    const char* name = "";
    int (*run)(ToolRuntime&, const char*, std::string&) = nullptr;
};

struct ToolRegistry {
    ToolEntry tools[8]{};
    uint32_t n = 0;
    bool registerTool(const char* name, int (*run)(ToolRuntime&, const char*,
                                                    std::string&)) {
        if (!name || !run || n >= 8) return false;
        tools[n].name = name;
        tools[n].run = run;
        ++n;
        return true;
    }
    int dispatch(const char* name, ToolRuntime& rt, const char* arg,
                  std::string& out) {
        for (uint32_t i = 0; i < n; ++i) {
            if (std::strcmp(tools[i].name, name) == 0)
                return tools[i].run ? tools[i].run(rt, arg, out) : -1;
        }
        return -1;
    }
};

} // namespace rawr::product
