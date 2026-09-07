#pragma once
#include "../runtime/session_persist.hpp"
#include <fstream>
#include <string>
namespace rawr::product {

struct CrashJournal {
    std::string path = ProductSessionRoot() + "\\crash.journal";
    bool mark(const std::string& sessionId, const char* stage) {
        ProductSessionEnsure();
        std::ofstream out(path, std::ios::app);
        if (!out) return false;
        out << sessionId << "\t" << (stage ? stage : "") << "\n";
        return true;
    }
    bool last(std::string& sessionId, std::string& stage) {
        std::ifstream in(path);
        if (!in) return false;
        std::string line, keep;
        while (std::getline(in, line))
            if (!line.empty()) keep = line;
        if (keep.empty()) return false;
        auto t = keep.find('\t');
        sessionId = t == std::string::npos ? keep : keep.substr(0, t);
        stage = t == std::string::npos ? "" : keep.substr(t + 1);
        return true;
    }
};

} // namespace rawr::product
