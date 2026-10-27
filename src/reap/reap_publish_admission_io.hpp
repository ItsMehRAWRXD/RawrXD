#pragma once
#include <fstream>
#include <string>
#include <nlohmann/json.hpp>

inline bool ReapReadJson(const std::string& path, nlohmann::json& out,
                         std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { err = "open failed: " + path; return false; }
    try { in >> out; } catch (const std::exception& ex) {
        err = std::string("json: ") + ex.what(); return false;
    }
    return true;
}

inline bool ReapWriteJson(const std::string& path, const nlohmann::json& doc) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << doc.dump(2) << '\n';
    return static_cast<bool>(out);
}
