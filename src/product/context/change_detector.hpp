#pragma once
#include "../abi/runtime_abi.hpp"
#include <cstdint>
#include <string>
namespace rawr::product {

struct ChangeDet {
    std::string path;
    uint32_t lastHash = 0;
    uint32_t lastLine = 0;
    uint32_t lastCol = 0;

    bool note(const std::string& p, const std::string& body, uint32_t line,
              uint32_t col) {
        uint32_t h = RawrFnv1a32(body.data(), (uint32_t)body.size());
        bool ch = (p != path) || (h != lastHash) || (line != lastLine) ||
                  (col != lastCol);
        path = p;
        lastHash = h;
        lastLine = line;
        lastCol = col;
        return ch;
    }
};

} // namespace rawr::product
