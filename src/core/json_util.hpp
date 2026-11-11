// json_util.hpp — minimal helpers for Win32IDE theme/config loaders
#pragma once

#include <nlohmann/json.hpp>
#include <fstream>
#include <string>

namespace rawrxd {
namespace json_util {

inline bool load_file(const std::string& path, nlohmann::json& out) {
    std::ifstream in(path);
    if (!in) return false;
    try {
        in >> out;
        return true;
    } catch (...) {
        return false;
    }
}

inline bool save_file(const std::string& path, const nlohmann::json& j) {
    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return static_cast<bool>(out);
}

}  // namespace json_util
}  // namespace rawrxd
