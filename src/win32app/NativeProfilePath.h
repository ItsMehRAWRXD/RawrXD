#pragma once

#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <string>
#include <vector>

namespace RawrXD::NativeProfile {

// Process-local override used by --user-data-dir. Do not infer isolation from
// LOCALAPPDATA: the Windows known-folder API does not use that environment value.
inline std::filesystem::path directory() {
    const DWORD size = GetEnvironmentVariableW(L"RAWRXD_USER_DATA_DIR", nullptr, 0);
    if (size > 1) {
        std::vector<wchar_t> value(size);
        const DWORD written = GetEnvironmentVariableW(
            L"RAWRXD_USER_DATA_DIR", value.data(), size);
        if (written && written < size) return std::filesystem::path(value.data());
    }
    PWSTR local = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local))) {
        const std::filesystem::path result = std::filesystem::path(local) / L"RawrXD";
        CoTaskMemFree(local);
        return result;
    }
    return std::filesystem::path(".rawrxd-profile");
}

} // namespace RawrXD::NativeProfile
