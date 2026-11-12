// Agent edit rollback ledger (C15). One prior snapshot per path.
#pragma once
#include <cstdint>
#include <fstream>
#include <string>
#include <windows.h>

namespace rawr_edit_rb {

inline std::string snapPath(const std::string& abs) {
    return abs + ".rawrxd.rollback";
}

inline bool writeSnapshot(const std::string& abs, const std::string& content,
                          std::string* err) {
    const std::string snap = snapPath(abs);
    const std::string tmp = snap + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            if (err) *err = "cannot write rollback snapshot temp";
            return false;
        }
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        f.close();
        if (!f) {
            if (err) *err = "rollback snapshot write failed";
            DeleteFileA(tmp.c_str());
            return false;
        }
    }
    if (!MoveFileExA(tmp.c_str(), snap.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (err) *err = "rollback snapshot replace gle=" +
                        std::to_string(GetLastError());
        DeleteFileA(tmp.c_str());
        return false;
    }
    return true;
}

inline bool restoreSnapshot(const std::string& abs, std::string* outMsg) {
    const std::string snap = snapPath(abs);
    std::ifstream in(snap, std::ios::binary);
    if (!in) {
        if (outMsg) *outMsg = "ERROR: no rollback snapshot for path";
        return false;
    }
    std::string body((std::istreambuf_iterator<char>(in)),
                     std::istreambuf_iterator<char>());
    in.close();
    const std::string tmp = abs + ".rawrxd.rollback.apply.tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            if (outMsg) *outMsg = "ERROR: cannot write restore temp";
            return false;
        }
        f.write(body.data(), static_cast<std::streamsize>(body.size()));
        f.close();
        if (!f) {
            if (outMsg) *outMsg = "ERROR: restore temp write failed";
            DeleteFileA(tmp.c_str());
            return false;
        }
    }
    std::wstring wAbs(abs.begin(), abs.end());
    std::wstring wTmp(tmp.begin(), tmp.end());
    if (!ReplaceFileW(wAbs.c_str(), wTmp.c_str(), nullptr,
                      REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr) &&
        !MoveFileExW(wTmp.c_str(), wAbs.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (outMsg)
            *outMsg = "ERROR: rollback apply failed gle=" +
                      std::to_string(GetLastError());
        DeleteFileA(tmp.c_str());
        return false;
    }
    DeleteFileA(snap.c_str());
    if (outMsg)
        *outMsg = "ROLLED_BACK (" + std::to_string(body.size()) + " bytes)";
    return true;
}

}  // namespace rawr_edit_rb
