// rawr_patch_engine.hpp — snapshot + journal + undo
#pragma once
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace rawr {

struct PatchRecord {
    std::string id;
    std::string path;
    std::string before;
    std::string after;
    std::string diff;
};

struct PatchEngine {
    std::string journalRoot = "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PATCH_JOURNAL";
    std::vector<PatchRecord> undo;

    void ensure() {
#ifdef _WIN32
        CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
        CreateDirectoryA(journalRoot.c_str(), nullptr);
#endif
    }

    static std::string ReadAll(const std::string& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) return {};
        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    static bool WriteAll(const std::string& path, const std::string& data) {
        std::ofstream out(path, std::ios::binary);
        if (!out) return false;
        out << data;
        return true;
    }

    static std::string MakeDiff(const std::string& before, const std::string& after) {
        // Minimal unified-ish summary (not full Myers).
        char buf[128];
        snprintf(buf, sizeof(buf), "--- before (%zu bytes)\n+++ after (%zu bytes)\n",
                 before.size(), after.size());
        return std::string(buf);
    }

    bool ApplyReplace(const std::string& path, const std::string& newText,
                      PatchRecord& out) {
        ensure();
        out = {};
        out.path = path;
        out.before = ReadAll(path);
        out.after = newText;
        out.diff = MakeDiff(out.before, out.after);
        char id[64];
        snprintf(id, sizeof(id), "patch_%zu", undo.size() + 1);
        out.id = id;
        if (!WriteAll(path, newText)) return false;
        WriteAll(journalRoot + "\\" + out.id + ".before", out.before);
        WriteAll(journalRoot + "\\" + out.id + ".after", out.after);
        WriteAll(journalRoot + "\\" + out.id + ".diff", out.diff);
        undo.push_back(out);
        return true;
    }

    bool UndoLast(std::string& restoredPath) {
        if (undo.empty()) return false;
        PatchRecord r = undo.back();
        undo.pop_back();
        if (!WriteAll(r.path, r.before)) return false;
        restoredPath = r.path;
        return true;
    }
};

} // namespace rawr
