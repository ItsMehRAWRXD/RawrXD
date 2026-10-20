// Win32IDE_FileOps.cpp — file open/save dialogs and file I/O helpers
#include <windows.h>
#include <commdlg.h>
#include <algorithm>
#include <filesystem>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

namespace RawrXD::IDE {

namespace {

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return {};
    const int count = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0);
    if (count <= 0) return {};
    std::wstring result(static_cast<size_t>(count), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            result.data(), count) != count) {
        return {};
    }
    return result;
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int count = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string result(static_cast<size_t>(count), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
            result.data(), count, nullptr, nullptr) != count) {
        return {};
    }
    return result;
}

std::wstring DialogFilter(const std::string& filter) {
    // A string literal passed to std::string stops at its first NUL. The IDE
    // call sites therefore arrive here as a single display label unless the
    // caller explicitly constructed a length-aware multi-string. Restore the
    // intended common filters for that legacy call shape.
    std::string source = filter;
    if (source.find('\0') == std::string::npos) {
        if (source == "GGUF Models") {
            static constexpr char kGguf[] =
                "GGUF Models\0*.gguf\0All Files\0*.*\0";
            source.assign(kGguf, sizeof(kGguf) - 1);
        } else {
            static constexpr char kAll[] = "All Files\0*.*\0";
            source.assign(kAll, sizeof(kAll) - 1);
        }
    }
    std::wstring result = Utf8ToWide(source);
    if (result.empty()) {
        static constexpr wchar_t kAll[] = L"All Files\0*.*\0";
        result.assign(kAll, sizeof(kAll) / sizeof(kAll[0]) - 1);
    }
    if (result.back() != L'\0') result.push_back(L'\0');
    result.push_back(L'\0');
    return result;
}

} // namespace

std::string FileOps_OpenDialog(HWND parent, const std::string& filter)
{
    std::vector<wchar_t> buf(32768, L'\0');
    const std::wstring wideFilter = DialogFilter(filter);
    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = parent;
    ofn.lpstrFilter  = wideFilter.c_str();
    ofn.lpstrFile    = buf.data();
    ofn.nMaxFile     = static_cast<DWORD>(buf.size());
    ofn.Flags        = OFN_EXPLORER | OFN_FILEMUSTEXIST |
                       OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
    return GetOpenFileNameW(&ofn) ? WideToUtf8(buf.data()) : std::string();
}

std::string FileOps_SaveDialog(HWND parent, const std::string& defaultName, const std::string& filter)
{
    std::vector<wchar_t> buf(32768, L'\0');
    const std::wstring wideFilter = DialogFilter(filter);
    std::wstring initialDir;
    if (!defaultName.empty()) {
        const std::filesystem::path defaultPath(Utf8ToWide(defaultName));
        const std::wstring fileName = defaultPath.filename().wstring();
        if (!fileName.empty()) {
            std::copy(fileName.begin(), fileName.end(), buf.begin());
        }
        if (defaultPath.has_parent_path()) {
            initialDir = defaultPath.parent_path().wstring();
        }
    }
    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = parent;
    ofn.lpstrFilter  = wideFilter.c_str();
    ofn.lpstrFile    = buf.data();
    ofn.nMaxFile     = static_cast<DWORD>(buf.size());
    ofn.lpstrInitialDir = initialDir.empty() ? nullptr : initialDir.c_str();
    ofn.Flags        = OFN_EXPLORER | OFN_PATHMUSTEXIST |
                       OFN_NOCHANGEDIR | OFN_OVERWRITEPROMPT;
    return GetSaveFileNameW(&ofn) ? WideToUtf8(buf.data()) : std::string();
}

std::string FileOps_ReadFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool FileOps_WriteFile(const std::string& path, const std::string& content)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f << content;
    return f.good();
}

bool FileOps_Exists(const std::string& path)
{
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string FileOps_GetDirectory(const std::string& path)
{
    auto pos = path.find_last_of("/\\");
    return pos != std::string::npos ? path.substr(0, pos) : ".";
}

std::string FileOps_GetFilename(const std::string& path)
{
    auto pos = path.find_last_of("/\\");
    return pos != std::string::npos ? path.substr(pos + 1) : path;
}

} // namespace RawrXD::IDE
