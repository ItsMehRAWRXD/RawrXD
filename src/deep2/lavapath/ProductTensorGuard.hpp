#pragma once
#include <cstdint>
#include <cstring>
namespace rawr::product_run {

inline bool validateShape(uint32_t got, uint32_t expect) {
    return got > 0 && got == expect;
}

inline bool validateTensor(const char* name, uint32_t rows, uint32_t cols,
                            uint32_t expectRows, uint32_t expectCols) {
    if (!name || !name[0]) return false;
    if (!validateShape(rows, expectRows)) return false;
    if (!validateShape(cols, expectCols)) return false;
    return std::strlen(name) > 0;
}

inline int shapeMismatch(uint32_t a, uint32_t b) { return a == b ? 0 : 1; }

} // namespace rawr::product_run
