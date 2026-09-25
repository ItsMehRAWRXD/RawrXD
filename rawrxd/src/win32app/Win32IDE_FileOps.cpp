// Win32IDE_FileOps.cpp — file open/save dialogs and file I/O helpers
#include <windows.h>
#include <string>
#include <fstream>
#include <sstream>

namespace RawrXD::IDE {

std::string FileOps_OpenDialog(HWND parent, const std::string& filter)
{
    char buf[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = parent;
    ofn.lpstrFilter  = filter.empty() ? "All Files\0*.*\0" : filter.c_str();
    ofn.lpstrFile    = buf;
    ofn.nMaxFile     = MAX_PATH;
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    return GetOpenFileNameA(&ofn) ? std::string(buf) : std::string();
}

std::string FileOps_SaveDialog(HWND parent, const std::string& defaultName, const std::string& filter)
{
    char buf[MAX_PATH] = {};
    if (!defaultName.empty()) strncpy_s(buf, defaultName.c_str(), MAX_PATH - 1);
    OPENFILENAMEA ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = parent;
    ofn.lpstrFilter  = filter.empty() ? "All Files\0*.*\0" : filter.c_str();
    ofn.lpstrFile    = buf;
    ofn.nMaxFile     = MAX_PATH;
    ofn.Flags        = OFN_OVERWRITEPROMPT;
    return GetSaveFileNameA(&ofn) ? std::string(buf) : std::string();
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
