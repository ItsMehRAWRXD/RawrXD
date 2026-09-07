#pragma once
#include <string>
namespace rawr::product {

struct EvalCase {
    const char* id = "";
    const char* expect = "";
    int pass = 0;
};

inline int EvalMatch(const std::string& got, const char* expect) {
    if (!expect || !*expect) return 0;
    return got.find(expect) != std::string::npos ? 1 : 0;
}

} // namespace rawr::product
