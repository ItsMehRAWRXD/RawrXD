#pragma once
#include <cstdio>
#include <string>
namespace rawr {
inline std::string ShowDiff(const std::string& before, const std::string& after) {
    char buf[160];
    snprintf(buf, sizeof(buf), "--- before (%zu)\n+++ after (%zu)\n",
             before.size(), after.size());
    return buf;
}
} // namespace rawr
