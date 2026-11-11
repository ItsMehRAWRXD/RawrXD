// File Operations Implementation for Win32IDE
// 9 comprehensive file management features

#include "Win32IDE.h"
#include "IDELogger.h"
#include "NativeProfilePath.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <commdlg.h>
#include <commctrl.h>
#include <richedit.h>
#include <shlobj.h>
#include <algorithm>
#include <bcrypt.h>
#include <limits>
#include <string_view>
#include <filesystem>
#include <cstring>
#include <thread>
#include <atomic>
#include <nlohmann/json.hpp>
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// FILE OPERATIONS (9 Features)
// ============================================================================

namespace {

constexpr UINT_PTR kFileSafetyTimerId = 0x52584653; // "RXFS"
constexpr UINT kFileSafetyIntervalMs = 1500;

static std::string getRecentFilesPath() {
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
        std::filesystem::path dir(path);
        CoTaskMemFree(path);
        dir /= "RawrXD";
        dir /= "recent_files.ini";
        std::error_code ec;
        std::filesystem::create_directories(dir.parent_path(), ec);
        return dir.string();
    }
    char localAppData[MAX_PATH] = {};
    if (GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH)) {
        return std::string(localAppData) + "\\RawrXD\\recent_files.ini";
    }
    return "C:\\RawrXD\\recent_files.ini";
}

bool queryFileSafetyFingerprint(const std::string& path, bool& exists,
                                ULONGLONG& size, FILETIME& lastWriteTime,
                                DWORD& attributes) {
    exists = false;
    size = 0;
    lastWriteTime = {};
    attributes = INVALID_FILE_ATTRIBUTES;
    if (path.empty()) return false;

    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }

    exists = true;
    attributes = data.dwFileAttributes;
    lastWriteTime = data.ftLastWriteTime;
    size = (static_cast<ULONGLONG>(data.nFileSizeHigh) << 32) |
           static_cast<ULONGLONG>(data.nFileSizeLow);
    return true;
}

bool sameFileSafetyFingerprint(bool leftExists, ULONGLONG leftSize,
                               const FILETIME& leftTime, DWORD leftAttributes,
                               bool rightExists, ULONGLONG rightSize,
                               const FILETIME& rightTime, DWORD rightAttributes) {
    return leftExists == rightExists && leftSize == rightSize &&
           leftAttributes == rightAttributes &&
           leftTime.dwLowDateTime == rightTime.dwLowDateTime &&
           leftTime.dwHighDateTime == rightTime.dwHighDateTime;
}

bool isValidUtf8(std::string_view text) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(text.data());
    size_t i = 0;
    while (i < text.size()) {
        const unsigned char lead = bytes[i++];
        if (lead <= 0x7f) continue;

        size_t continuationCount = 0;
        uint32_t codePoint = 0;
        uint32_t minimum = 0;
        if ((lead & 0xe0) == 0xc0) {
            continuationCount = 1;
            codePoint = lead & 0x1f;
            minimum = 0x80;
        } else if ((lead & 0xf0) == 0xe0) {
            continuationCount = 2;
            codePoint = lead & 0x0f;
            minimum = 0x800;
        } else if ((lead & 0xf8) == 0xf0) {
            continuationCount = 3;
            codePoint = lead & 0x07;
            minimum = 0x10000;
        } else {
            return false;
        }

        if (continuationCount > text.size() - i) return false;
        for (size_t n = 0; n < continuationCount; ++n) {
            const unsigned char continuation = bytes[i++];
            if ((continuation & 0xc0) != 0x80) return false;
            codePoint = (codePoint << 6) | (continuation & 0x3f);
        }
        if (codePoint < minimum || codePoint > 0x10ffff ||
            (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
            return false;
        }
    }
    return true;
}

bool utf8ToWideForEditor(std::string_view text, std::wstring& wide) {
    wide.clear();
    if (text.empty()) return true;
    if (text.size() > static_cast<size_t>(INT_MAX)) return false;
    const int sourceLength = static_cast<int>(text.size());
    const int wideLength = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), sourceLength, nullptr, 0);
    if (wideLength <= 0) return false;
    wide.resize(static_cast<size_t>(wideLength));
    return MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), sourceLength,
        wide.data(), wideLength) == wideLength;
}

bool readBinaryFile(const std::string& path, std::string& bytes, std::string& error) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "open failed";
        return false;
    }
    file.seekg(0, std::ios::end);
    const std::streampos end = file.tellg();
    if (end < 0) {
        error = "size query failed";
        return false;
    }
    if (static_cast<unsigned long long>(end) >
        static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
        error = "file is too large for this process";
        return false;
    }
    const size_t size = static_cast<size_t>(end);
    file.seekg(0, std::ios::beg);
    bytes.assign(size, '\0');
    if (size != 0) {
        file.read(bytes.data(), static_cast<std::streamsize>(size));
        if (!file || static_cast<size_t>(file.gcount()) != size) {
            error = "read failed or file changed during read";
            bytes.clear();
            return false;
        }
    }
    return true;
}

bool writeBinaryFileAtomically(const std::string& path, const std::string& bytes,
                               std::string& error) {
    const std::string tempPath = path + ".rawrxd-tmp";
    {
        std::ofstream file(tempPath, std::ios::binary | std::ios::trunc);
        if (!file) {
            error = "temporary file open failed";
            return false;
        }
        if (!bytes.empty()) {
            file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        }
        file.flush();
        if (!file) {
            error = "temporary file write failed";
            file.close();
            DeleteFileA(tempPath.c_str());
            return false;
        }
    }
    if (!MoveFileExA(tempPath.c_str(), path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = "atomic replacement failed (Win32=" +
                std::to_string(static_cast<unsigned long>(GetLastError())) + ")";
        DeleteFileA(tempPath.c_str());
        return false;
    }
    return true;
}

} // namespace

bool Win32IDE::setEditorTextUtf8FromFile(const std::string& text) {
    if (!m_hwndEditor) return false;
    const bool wasSuppressed = m_suppressEditorDirty;
    m_suppressEditorDirty = true;

    // T07 RCA (55BE19B7): decoder→wide retains U+4F60, but RTF EM_STREAMIN with
    // `\uN?` ANSI fallback materializes U+003F ('?') at equal length. Drop RTF.
    // Load path = UTF-8→UTF-16 then Unicode SETTEXTEX (1200) / SetWindowTextW.
    auto appendTrace = [](const char* tag, const std::wstring& sample) {
        std::ofstream tr(
            "F:\\rawrxd\\evidence\\PROGRESSION_FINISH25_001\\RCA\\T07_UNICODE\\boundary_trace.txt",
            std::ios::app);
        if (!tr) return;
        tr << tag << " len=" << sample.size() << " has_4F60="
           << (sample.find(wchar_t(0x4F60)) != std::wstring::npos ? 1 : 0)
           << " has_003F="
           << (sample.find(wchar_t(0x003F)) != std::wstring::npos ? 1 : 0)
           << " cps=";
        for (size_t i = 0; i < sample.size() && i < 24; ++i) {
            char buf[8];
            sprintf_s(buf, "%04X ", static_cast<unsigned>(sample[i]));
            tr << buf;
        }
        tr << '\n';
        std::ofstream legacy(
            "F:\\rawrxd\\evidence\\PROGRESSION_FINISH25_001\\EDITOR\\t07_wide_trace.txt",
            std::ios::app);
        if (legacy) {
            legacy << tag << " has_4F60="
                   << (sample.find(wchar_t(0x4F60)) != std::wstring::npos ? 1 : 0)
                   << " len=" << sample.size() << '\n';
        }
    };
    auto readEditorWide = [this]() -> std::wstring {
        const int len = GetWindowTextLengthW(m_hwndEditor);
        if (len < 0) return {};
        std::wstring got(static_cast<size_t>(len) + 1, L'\0');
        const int n = GetWindowTextW(m_hwndEditor, got.data(), len + 1);
        if (n > 0) got.resize(static_cast<size_t>(n));
        else got.clear();
        return got;
    };

    bool ok = false;
    if (text.empty()) {
        ok = SetWindowTextW(m_hwndEditor, L"") != FALSE;
    } else {
        std::wstring wide;
        if (isValidUtf8(text)) {
            if (!utf8ToWideForEditor(text, wide)) {
                m_suppressEditorDirty = wasSuppressed;
                LOG_ERROR("UTF-8 editor load conversion failed");
                return false;
            }
        } else {
            const int n = MultiByteToWideChar(CP_ACP, 0, text.data(),
                static_cast<int>(text.size()), nullptr, 0);
            if (n <= 0) {
                m_suppressEditorDirty = wasSuppressed;
                return false;
            }
            wide.resize(static_cast<size_t>(n));
            MultiByteToWideChar(CP_ACP, 0, text.data(),
                static_cast<int>(text.size()), wide.data(), n);
        }
        appendTrace("decoder_wide", wide);
        const bool wantCjk = wide.find(wchar_t(0x4F60)) != std::wstring::npos;

        // A/B probe: pristine temporary RICHEDIT50W in the same process.
        if (wantCjk && m_hwndMain) {
            HWND temp = CreateWindowExW(0, MSFTEDIT_CLASS, L"", WS_CHILD, 0, 0, 8, 8,
                                        m_hwndMain, nullptr, m_hInstance, nullptr);
            if (temp) {
                SetWindowTextW(temp, wide.c_str());
                const int tl = GetWindowTextLengthW(temp);
                std::wstring tg(static_cast<size_t>(tl) + 1, L'\0');
                const int tn = GetWindowTextW(temp, tg.data(), tl + 1);
                if (tn > 0) tg.resize(static_cast<size_t>(tn)); else tg.clear();
                appendTrace("temp_richedit_setw", tg);
                std::ofstream tr(
                    "F:\\rawrxd\\evidence\\PROGRESSION_FINISH25_001\\RCA\\T07_UNICODE\\boundary_trace.txt",
                    std::ios::app);
                if (tr) {
                    tr << "temp_unicode=" << (IsWindowUnicode(temp) ? 1 : 0)
                       << " live_unicode=" << (IsWindowUnicode(m_hwndEditor) ? 1 : 0)
                       << " GetACP=" << GetACP() << '\n';
                }
                // If pristine control retains CJK, rebuild the live editor HWND
                // (theme CHARFORMAT state on the live control remaps → U+003F).
                if (tg.find(wchar_t(0x4F60)) != std::wstring::npos) {
                    RECT rc{};
                    GetWindowRect(m_hwndEditor, &rc);
                    MapWindowPoints(HWND_DESKTOP, m_hwndMain,
                                    reinterpret_cast<POINT*>(&rc), 2);
                    const HWND old = m_hwndEditor;
                    m_hwndEditor = CreateWindowExW(
                        WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
                        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                            WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL |
                            ES_AUTOHSCROLL | ES_WANTRETURN,
                        rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                        m_hwndMain, reinterpret_cast<HMENU>(1001), // IDC_EDITOR
                        m_hInstance, nullptr);
                    if (m_hwndEditor) {
                        SendMessageW(m_hwndEditor, EM_EXLIMITTEXT, 0, 64 * 1024 * 1024);
                        SendMessageW(m_hwndEditor, EM_SETEVENTMASK, 0, ENM_CHANGE);
                        const LRESULT lo = SendMessageW(m_hwndEditor, EM_GETLANGOPTIONS, 0, 0);
                        SendMessageW(m_hwndEditor, EM_SETLANGOPTIONS, 0,
                                     lo & ~(IMF_AUTOFONT | IMF_DUALFONT));
                        CHARFORMAT2W cf{};
                        cf.cbSize = sizeof(cf);
                        cf.dwMask = CFM_COLOR | CFM_CHARSET | CFM_SIZE;
                        cf.bCharSet = DEFAULT_CHARSET;
                        cf.crTextColor = RGB(220, 220, 220);
                        cf.yHeight = 200;
                        SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL,
                                     reinterpret_cast<LPARAM>(&cf));
                        DestroyWindow(old);
                        appendTrace("live_recreated", std::wstring());
                    } else {
                        m_hwndEditor = old;
                    }
                }
                DestroyWindow(temp);
            }
        }

        SetWindowTextW(m_hwndEditor, wide.c_str());
        std::wstring afterSet = readEditorWide();
        appendTrace("after_live_setw", afterSet);
        ok = !afterSet.empty() || wide.empty();
        if (wantCjk) {
            ok = afterSet.find(wchar_t(0x4F60)) != std::wstring::npos;
        }
    }

    m_suppressEditorDirty = wasSuppressed;
    if (!text.empty() && !ok) {
        LOG_ERROR("UTF-8 editor load failed");
        return false;
    }
    return true;
}

std::string Win32IDE::getEditorTextUtf8ForFile() const {
    if (!m_hwndEditor) return {};
    // Prefer EM_GETTEXTEX CP 1200 (UTF-16). GetWindowTextW is unreliable on
    // RICHEDIT50W and produced empty captures → T08 FAIL_PRESERVED_1.
    GETTEXTLENGTHEX wideLenInfo{};
    wideLenInfo.flags = GTL_USECRLF | GTL_NUMCHARS;
    wideLenInfo.codepage = 1200;
    const LRESULT wideChars = SendMessageW(
        m_hwndEditor, EM_GETTEXTLENGTHEX, reinterpret_cast<WPARAM>(&wideLenInfo), 0);
    if (wideChars > 0) {
        std::wstring wide(static_cast<size_t>(wideChars) + 1, L'\0');
        GETTEXTEX getWide{};
        getWide.cb = static_cast<DWORD>((wide.size()) * sizeof(wchar_t));
        getWide.flags = GT_USECRLF;
        getWide.codepage = 1200;
        const LRESULT got = SendMessageW(
            m_hwndEditor, EM_GETTEXTEX, reinterpret_cast<WPARAM>(&getWide),
            reinterpret_cast<LPARAM>(wide.data()));
        if (got > 0) {
            wide.resize(static_cast<size_t>(got));
            const int bytes = WideCharToMultiByte(
                CP_UTF8, 0, wide.data(), got, nullptr, 0, nullptr, nullptr);
            if (bytes > 0) {
                std::string utf8(static_cast<size_t>(bytes), '\0');
                WideCharToMultiByte(CP_UTF8, 0, wide.data(), got,
                                    utf8.data(), bytes, nullptr, nullptr);
                return utf8;
            }
        }
    }
    GETTEXTLENGTHEX lengthInfo{};
    lengthInfo.flags = GTL_USECRLF | GTL_NUMBYTES;
    lengthInfo.codepage = CP_UTF8;
    const LRESULT byteCount = SendMessageW(
        m_hwndEditor, EM_GETTEXTLENGTHEX, reinterpret_cast<WPARAM>(&lengthInfo), 0);
    if (byteCount <= 0) return {};
    GETTEXTEX getText{};
    getText.cb = static_cast<DWORD>(byteCount + 1);
    getText.flags = GT_USECRLF;
    getText.codepage = CP_UTF8;
    std::string result(static_cast<size_t>(byteCount) + 1, '\0');
    const LRESULT copied = SendMessageW(
        m_hwndEditor, EM_GETTEXTEX, reinterpret_cast<WPARAM>(&getText),
        reinterpret_cast<LPARAM>(result.data()));
    if (copied <= 0) return {};
    result.resize(static_cast<size_t>(copied));
    return result;
}

void Win32IDE::openFileDialog() {
    LOG_INFO("openFileDialog() called");
    OPENFILENAMEW ofn = {};
    wchar_t szFile[MAX_PATH] = {0};
    
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Text Files (*.txt;*.ps1;*.cpp;*.h;*.md;*.json)\0*.txt;*.ps1;*.cpp;*.h;*.md;*.json\0"
                      L"All Files (*.*)\0*.*\0"
                      L"PowerShell Scripts (*.ps1)\0*.ps1\0"
                      L"C++ Files (*.cpp;*.h)\0*.cpp;*.h\0"
                      L"GGUF Models (*.gguf)\0*.gguf\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    std::wstring initialDir;
    if (!m_currentDirectory.empty()) {
        int idLen = MultiByteToWideChar(CP_UTF8, 0, m_currentDirectory.c_str(),
                                        static_cast<int>(m_currentDirectory.size()),
                                        nullptr, 0);
        if (idLen > 0) {
            initialDir.resize(idLen);
            MultiByteToWideChar(CP_UTF8, 0, m_currentDirectory.c_str(),
                                static_cast<int>(m_currentDirectory.size()),
                                &initialDir[0], idLen);
        }
    }
    ofn.lpstrInitialDir = initialDir.empty() ? NULL : initialDir.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_ENABLESIZING;
    
    LOG_DEBUG("Opening file dialog");
    if (GetOpenFileNameW(&ofn)) {
        // Helper to convert wide string to UTF-8
        auto wideToUtf8 = [](const std::wstring& wstr) -> std::string {
            if (wstr.empty()) return "";
            int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                                           static_cast<int>(wstr.size()),
                                           nullptr, 0, nullptr, nullptr);
            if (size <= 0) return "";
            std::string result(size, '\0');
            WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                                static_cast<int>(wstr.size()),
                                &result[0], size, nullptr, nullptr);
            return result;
        };
        std::string filePath = wideToUtf8(szFile);
        LOG_INFO("File selected: " + filePath);
        
        // Check if it's a GGUF model file FIRST - DON'T load as text, bypass size limits!
        if (filePath.find(".gguf") != std::string::npos || filePath.find(".GGUF") != std::string::npos) {
            LOG_INFO("Detected GGUF file, loading as model");
            // GGUF files can be multi-GB, they use streaming loader
            // Add safety check to prevent crashes on corrupted/invalid files
            try {
                // This member is RawrXD::IGGUFLoader; the legacy global streaming\n                // loader has a different contract and cannot be cast safely.\n                m_ggufLoader = std::make_unique<RawrXD::GGUFLoader>();
                m_useStreamingLoader = true;
                if (loadGGUFModel(filePath)) {
                    std::string message = " Model loaded: " + filePath + "\n\n" + getModelInfo();
                    appendToOutput(message, "Output", OutputSeverity::Info);
                    MessageBoxA(m_hwndMain, "Model loaded successfully! Check Output panel and Copilot Chat for agentic features.", "Model Loaded", MB_OK | MB_ICONINFORMATION);
                    LOG_INFO("GGUF model loaded successfully");
                } else {
                    LOG_ERROR("Failed to load GGUF model: " + filePath);
                    MessageBoxA(m_hwndMain, "Failed to load GGUF model. Check Output/Errors panel for details.", "Model Load Failed", MB_OK | MB_ICONERROR);
                }
            } catch (const std::exception& e) {
                std::string error = "Exception while loading GGUF: " + std::string(e.what());
                LOG_ERROR(error);
                appendToOutput(error, "Errors", OutputSeverity::Error);
                MessageBoxA(m_hwndMain, error.c_str(), "Model Load Error", MB_OK | MB_ICONERROR);
            } catch (...) {
                LOG_ERROR("Unknown exception while loading GGUF file");
                appendToOutput("Unknown exception while loading GGUF file", "Errors", OutputSeverity::Error);
                MessageBoxA(m_hwndMain, "Unknown error loading GGUF file.", "Model Load Error", MB_OK | MB_ICONERROR);
            }
            return;  // Exit early - GGUF files never load into editor
        }
        
        // For text files only: check for unsaved changes
        if (m_fileModified && !promptSaveChanges()) {
            return;
        }
        
        // Load text file with size check (10MB limit for editor display only)
        try {
            std::string content;
            std::string readError;
            if (readBinaryFile(filePath, content, readError)) {
                // T07: reject binary/NUL-bearing files before they enter the
                // editor. Delegates to the shared Win32IDE::rejectBinaryFile()
                // helper to avoid duplicating the NUL-byte check.
                if (rejectBinaryFile(filePath, content)) {
                    return;
                }

                const size_t fileSize = content.size();
                if (fileSize > 10 * 1024 * 1024) {
                    MessageBoxA(m_hwndMain,
                        "Text file too large to open in editor (>10MB).\n"
                        "GGUF models use the streaming loader automatically.",
                        "File Too Large", MB_OK | MB_ICONWARNING);
                    return;
                }

                // Single open path: loadFileIntoEditor owns UTF-8 decode,
                // binary reject (already done), and T08 tab accumulation.
                if (!loadFileIntoEditor(filePath)) {
                    MessageBoxA(m_hwndMain, "Failed to load file text", "Error",
                                MB_OK | MB_ICONERROR);
                    return;
                }
                updateRecentFiles(filePath);
            } else {
                MessageBoxA(m_hwndMain, ("Failed to open file: " + readError).c_str(),
                            "Error", MB_OK | MB_ICONERROR);
            }
        }
        catch (const std::exception& e) {
            std::string error = "Error opening file: " + std::string(e.what());
            MessageBoxA(m_hwndMain, error.c_str(), "Error", MB_OK | MB_ICONERROR);
        }
    }
}

void Win32IDE::openRecentFile(int index) {
    if (index >= 0 && index < m_recentFiles.size()) {
        const std::string& filePath = m_recentFiles[index];
        
        // Check for unsaved changes
        if (m_fileModified && !promptSaveChanges()) {
            return;
        }
        
        // Load the file as exact bytes, then cross the RichEdit boundary as
        // UTF-8 rather than allowing the process ANSI code page to reinterpret
        // CJK, emoji, or accented characters.
        std::string content;
        std::string readError;
        if (readBinaryFile(filePath, content, readError)) {
                // T07: reject binary/NUL-bearing files before they enter the editor.
                if (content.find('\0') != std::string::npos) {
                    appendToOutput("Recent file rejected: binary file (NUL bytes present): " + filePath + "\n",
                                   "Errors", OutputSeverity::Error);
                    MessageBoxA(m_hwndMain,
                                ("RawrXD IDE refuses to open binary files into the editor.\n\n" +
                                 filePath).c_str(),
                                "Binary file rejected", MB_OK | MB_ICONSTOP);
                    // Remove from recent files so it cannot be re-selected.
                    m_recentFiles.erase(m_recentFiles.begin() + index);
                    saveRecentFiles();
                    return;
                }

                if (!setEditorTextUtf8FromFile(content)) return;
            
            m_currentFile = filePath;
            m_fileModified = false;
            if (m_hwndEditor) SendMessageW(m_hwndEditor, EM_SETMODIFY, FALSE, 0);
            setCurrentDirectoryFromFile(m_currentFile);
            updateTitleBarText();
            
            // Move to top of recent files
            updateRecentFiles(filePath);
            
            // Update window title
            std::string title = "RawrXD IDE - " + m_currentFile;
            SetWindowTextA(m_hwndMain, title.c_str());
            
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Recent file opened");
        } else {
            MessageBoxA(m_hwndMain, 
                       ("File not found: " + filePath + " (" + readError + ")").c_str(),
                       "Error", MB_OK | MB_ICONERROR);
            
            // Remove from recent files
            m_recentFiles.erase(m_recentFiles.begin() + index);
            saveRecentFiles();
        }
    }
}

std::string Win32IDE::getFileDialogPath(bool isSave) {
    // Helper to convert wide string to UTF-8
    auto wideToUtf8 = [](const std::wstring& wstr) -> std::string {
        if (wstr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                                       static_cast<int>(wstr.size()),
                                       nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(),
                            static_cast<int>(wstr.size()),
                            &result[0], size, nullptr, nullptr);
        return result;
    };

    OPENFILENAMEW ofn = {};
    wchar_t szFile[MAX_PATH] = {0};
    
    if (!m_currentFile.empty()) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, m_currentFile.c_str(),
                                       static_cast<int>(m_currentFile.size()),
                                       szFile, MAX_PATH - 1);
        szFile[wlen] = L'\0';
    }
    
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0"
                      L"PowerShell Scripts (*.ps1)\0*.ps1\0"
                      L"C++ Files (*.cpp;*.h)\0*.cpp;*.h\0"
                      L"Text Files (*.txt)\0*.txt\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    // Initial directory as wide string
    std::wstring initialDir;
    if (!m_currentDirectory.empty()) {
        int idLen = MultiByteToWideChar(CP_UTF8, 0, m_currentDirectory.c_str(),
                                        static_cast<int>(m_currentDirectory.size()),
                                        nullptr, 0);
        if (idLen > 0) {
            initialDir.resize(idLen);
            MultiByteToWideChar(CP_UTF8, 0, m_currentDirectory.c_str(),
                                static_cast<int>(m_currentDirectory.size()),
                                &initialDir[0], idLen);
        }
    }
    ofn.lpstrInitialDir = initialDir.empty() ? NULL : initialDir.c_str();
    std::wstring defExt;
    if (!m_defaultFileExtension.empty()) {
        int deLen = MultiByteToWideChar(CP_UTF8, 0, m_defaultFileExtension.c_str(),
                                        static_cast<int>(m_defaultFileExtension.size()),
                                        nullptr, 0);
        if (deLen > 0) {
            defExt.resize(deLen);
            MultiByteToWideChar(CP_UTF8, 0, m_defaultFileExtension.c_str(),
                                static_cast<int>(m_defaultFileExtension.size()),
                                &defExt[0], deLen);
        }
    }
    ofn.lpstrDefExt = defExt.empty() ? NULL : defExt.c_str();
    
    if (isSave) {
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_EXPLORER | OFN_ENABLESIZING;
        if (GetSaveFileNameW(&ofn)) {
            return wideToUtf8(szFile);
        }
    } else {
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_ENABLESIZING;
        if (GetOpenFileNameW(&ofn)) {
            return wideToUtf8(szFile);
        }
    }
    return "";
}

bool Win32IDE::hasUnsavedBuffers() const {
    for (const auto& buf : m_documentBuffers) {
        if (buf.modified) {
            return true;
        }
    }
    return false;
}

bool Win32IDE::promptSaveAllChanges() {
    // Collect indices of all modified buffers
    std::vector<int> modifiedIndices;
    for (size_t i = 0; i < m_documentBuffers.size(); ++i) {
        if (m_documentBuffers[i].modified) {
            modifiedIndices.push_back(static_cast<int>(i));
        }
    }

    if (modifiedIndices.empty()) {
        return true; // Nothing to save
    }

    // Item10 harness: modal YES/NO/CANCEL blocked WM_CLOSE → FORCE_KILL EXIT=-1.
    // RAWRXD_SMOKE_DISCARD_UNSAVED=1 discards without UI (not a promote path).
    char smokeDiscard[8] = {};
    if (GetEnvironmentVariableA("RAWRXD_SMOKE_DISCARD_UNSAVED", smokeDiscard,
                                static_cast<DWORD>(sizeof(smokeDiscard))) > 0 &&
        smokeDiscard[0] == '1') {
        for (int idx : modifiedIndices) {
            if (idx >= 0 &&
                idx < static_cast<int>(m_documentBuffers.size())) {
                m_documentBuffers[static_cast<size_t>(idx)].modified = false;
            }
        }
        m_fileModified = false;
        return true;
    }

    // Build a summary message listing all modified files
    std::string message = "The following documents have unsaved changes:\n\n";
    for (int idx : modifiedIndices) {
        message += "- " + m_documentBuffers[idx].label + "\n";
    }
    message += "\nDo you want to save all changes?\n\n"
               "YES = Save all\n"
               "NO = Discard all\n"
               "CANCEL = Abort close";

    int result = MessageBoxA(m_hwndMain,
                             message.c_str(),
                             "Unsaved Changes",
                             MB_YESNOCANCEL | MB_ICONWARNING);

    if (result == IDCANCEL) {
        return false;
    }

    if (result == IDYES) {
        saveAll();
        return true;
    }

    return true; // IDNO - discard all changes
}

void Win32IDE::saveAll() {
    bool anySaved = false;
    // Save every modified document buffer, not just the active one.
    for (size_t i = 0; i < m_documentBuffers.size(); ++i) {
        if (m_documentBuffers[i].modified && !m_openDocuments[i].empty()) {
            switchDocumentTab(static_cast<int>(i));
            saveFile();
            anySaved = true;
        }
    }
    // Ensure the current file is saved if modified.
    if (m_fileModified && !m_currentFile.empty()) {
        saveFile();
        anySaved = true;
    }
    if (anySaved) {
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"All files saved");
    }
}

void Win32IDE::closeFile() {
    if (hasUnsavedBuffers() && !promptSaveAllChanges()) {
        return;
    }

    // Remove the document tab for the file being closed so the tab control
    // and the document buffer list stay in sync with the editor state.
    if (m_activeDocument >= 0) {
        removeDocumentTab(m_activeDocument);
    }

    // Clear editor
    setEditorText("");

    // Reset state
    m_currentFile.clear();
    m_fileModified = false;
    updateTitleBarText();

    // Update window title
    SetWindowTextA(m_hwndMain, "RawrXD IDE - New File");

    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File closed");
}

bool Win32IDE::promptSaveChanges() {
    int result = MessageBoxA(m_hwndMain, 
                            "The current file has unsaved changes.\n\nDo you want to save them?",
                            "Unsaved Changes", 
                            MB_YESNOCANCEL | MB_ICONWARNING);
    
    if (result == IDCANCEL) {
        return false;
    }
    
    if (result == IDYES) {
        return saveFile();
    }
    
    return true; // IDNO - discard changes
}

void Win32IDE::updateRecentFiles(const std::string& filePath) {
    // Remove if already exists
    auto it = std::find(m_recentFiles.begin(), m_recentFiles.end(), filePath);
    if (it != m_recentFiles.end()) {
        m_recentFiles.erase(it);
    }
    
    // Add to front
    m_recentFiles.insert(m_recentFiles.begin(), filePath);
    
    // Limit size
    if (m_recentFiles.size() > MAX_RECENT_FILES) {
        m_recentFiles.resize(MAX_RECENT_FILES);
    }
    
    // Save to disk
    saveRecentFiles();
}

void Win32IDE::loadRecentFiles() {
    m_recentFiles.clear();
    
    std::ifstream file(getRecentFilesPath());
    if (file) {
        std::string line;
        while (std::getline(file, line) && m_recentFiles.size() < MAX_RECENT_FILES) {
            // Recent-file state is advisory.  Do not rehydrate dead entries
            // into the menu; this also prevents a stale path from becoming
            // the active document during session restoration.
            if (!line.empty() && GetFileAttributesA(line.c_str()) != INVALID_FILE_ATTRIBUTES) {
                m_recentFiles.push_back(line);
            }
        }
        file.close();
    }
}

void Win32IDE::saveRecentFiles() {
    std::ofstream file(getRecentFilesPath());
    if (file) {
        for (const auto& path : m_recentFiles) {
            file << path << "\n";
        }
        file.close();
    }
}

void Win32IDE::clearRecentFiles() {
    m_recentFiles.clear();
    saveRecentFiles();
    MessageBoxA(m_hwndMain, "Recent files list cleared", "Recent Files", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::armFileSafetyMonitor() {
    if (!m_hwndMain || !IsWindow(m_hwndMain)) {
        LOG_WARNING("[FILE_SAFETY] arm skipped: main window is not valid");
        return;
    }
    // Re-arm on every document/session transition.  The first call can occur
    // while the document-tab controls are still being created during WM_CREATE;
    // resetting the owner-window timer after the editor is materialized makes
    // the monitor independent of that startup ordering.
    if (m_fileSafetyTimerArmed) {
        KillTimer(m_hwndMain, kFileSafetyTimerId);
    }
    // Route the timer through the IDE's normal main-window message loop.  A
    // callback timer can run through a different user32 delivery path and is
    // difficult to correlate with the UI lifecycle that owns the decision.
    m_fileSafetyTimerArmed = SetTimer(
        m_hwndMain, kFileSafetyTimerId, kFileSafetyIntervalMs,
        nullptr) != 0;
    if (m_fileSafetyTimerArmed) {
        LOG_INFO("[FILE_SAFETY] external-change monitor armed for " +
                 (m_currentFile.empty() ? std::string("<untitled>") : m_currentFile));
    } else {
        LOG_ERROR("[FILE_SAFETY] failed to arm external-change monitor");
    }
    captureFileSafetyBaseline();
}

void Win32IDE::disarmFileSafetyMonitor() {
    if (m_hwndMain && IsWindow(m_hwndMain) && m_fileSafetyTimerArmed) {
        KillTimer(m_hwndMain, kFileSafetyTimerId);
    }
    m_fileSafetyTimerArmed = false;
    m_fileSafetyBaselinePath.clear();
    m_fileSafetyBaselineValid = false;
    m_fileSafetyPromptActive = false;
}

void Win32IDE::captureFileSafetyBaseline() {
    if (m_currentFile.empty()) {
        m_fileSafetyBaseline = {};
        m_fileSafetyBaselinePath.clear();
        m_fileSafetyBaselineValid = false;
        return;
    }
    m_fileSafetyBaselinePath = m_currentFile;
    m_fileSafetyBaseline.exists = queryFileSafetyFingerprint(
        m_currentFile, m_fileSafetyBaseline.exists, m_fileSafetyBaseline.size,
        m_fileSafetyBaseline.lastWriteTime, m_fileSafetyBaseline.attributes);
    m_fileSafetyBaselineValid = true;
}

void Win32IDE::pollFileSafety() {
    if (m_fileSafetyAutosaveInProgress) return;

    // The timer also provides crash recovery: modified buffers are journaled
    // through the existing atomic session writer while the process is alive.
    bool hasUnsavedBuffer = m_fileModified;
    for (const auto& buffer : m_documentBuffers) {
        if (buffer.modified) {
            hasUnsavedBuffer = true;
            break;
        }
    }
    if (hasUnsavedBuffer) {
        m_fileSafetyAutosaveInProgress = true;
        saveIdeSession();
        m_fileSafetyAutosaveInProgress = false;
        LOG_INFO("[FILE_SAFETY] unsaved buffers checkpointed for recovery");
    }

    if (m_currentFile.empty() || !m_fileSafetyBaselineValid || m_fileSafetyPromptActive) {
        return;
    }
    if (m_fileSafetyBaselinePath != m_currentFile) {
        // File open/tab switching lives outside this file-operations unit.
        // Re-baseline on the next main-thread tick instead of comparing the
        // newly active document with the previous document's fingerprint.
        captureFileSafetyBaseline();
        return;
    }

    FileSafetyFingerprint current{};
    current.exists = queryFileSafetyFingerprint(
        m_currentFile, current.exists, current.size, current.lastWriteTime,
        current.attributes);
    if (sameFileSafetyFingerprint(
            current.exists, current.size, current.lastWriteTime, current.attributes,
            m_fileSafetyBaseline.exists, m_fileSafetyBaseline.size,
            m_fileSafetyBaseline.lastWriteTime, m_fileSafetyBaseline.attributes)) {
        return;
    }

    // A save performed by this process changes the on-disk fingerprint too.
    // Compare bytes before warning so ordinary Save does not produce a false
    // external-change prompt.
    std::string diskBytes;
    std::string readError;
    const bool diskReadable = current.exists &&
        readBinaryFile(m_currentFile, diskBytes, readError);
    const std::string editorBytes = getEditorTextUtf8ForFile();
    if (diskReadable && diskBytes == editorBytes) {
        m_fileSafetyBaseline = current;
        m_fileSafetyBaselineValid = true;
        return;
    }

    m_fileSafetyBaseline = current;
    m_fileSafetyBaselineValid = true;
    m_fileSafetyPromptActive = true;
    LOG_WARNING("[FILE_SAFETY] external change detected: " + m_currentFile);

    if (m_fileModified) {
        MessageBoxA(m_hwndMain,
            "The file changed outside RawrXD while this buffer has unsaved edits.\n\n"
            "Your in-memory edits were preserved in the recovery snapshot.\n"
            "Save As or compare the file before overwriting the external change.",
            "External File Change", MB_OK | MB_ICONWARNING);
        m_fileSafetyPromptActive = false;
        return;
    }

    const int choice = MessageBoxA(
        m_hwndMain,
        "This file changed outside RawrXD. Reload it now?\n\n"
        "Choose No to keep the current view.",
        "External File Change", MB_YESNO | MB_ICONWARNING);
    if (choice == IDYES && diskReadable) {
        if (setEditorTextUtf8FromFile(diskBytes)) {
            m_fileModified = false;
            if (m_hwndEditor) SendMessageW(m_hwndEditor, EM_SETMODIFY, FALSE, 0);
            if (m_activeDocument >= 0 &&
                m_activeDocument < static_cast<int>(m_documentBuffers.size())) {
                auto& buffer = m_documentBuffers[static_cast<size_t>(m_activeDocument)];
                buffer.path = m_currentFile;
                buffer.text = diskBytes;
                buffer.modified = false;
            }
            updateTitleBarText();
            updateDocumentTabs();
            updateMenuEnableStates();
            LOG_INFO("[FILE_SAFETY] external change reloaded: " + m_currentFile);
        } else {
            LOG_ERROR("[FILE_SAFETY] external change reload failed: " + m_currentFile);
        }
    } else {
        LOG_INFO("[FILE_SAFETY] external change kept out of editor: " + m_currentFile);
    }
    m_fileSafetyPromptActive = false;
}

std::string Win32IDE::sha256Hex(const std::string& bytes) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectLen = 0;
    DWORD dataLen = 0;
    DWORD hashLen = 0;
    if (bytes.size() > std::numeric_limits<ULONG>::max()) return {};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLen),
                          sizeof(objectLen), &dataLen, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen),
                          sizeof(hashLen), &dataLen, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    std::vector<UCHAR> object(objectLen);
    std::vector<UCHAR> digest(hashLen);
    if (BCryptCreateHash(alg, &hash, object.data(), objectLen, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),
                       static_cast<ULONG>(bytes.size()), 0) != 0 ||
        BCryptFinishHash(hash, digest.data(), hashLen, 0) != 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.resize(digest.size() * 2);
    for (size_t i = 0; i < digest.size(); ++i) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    return out;
}

void Win32IDE::persistActiveDocumentBuffer() {
    if (m_activeDocument < 0 ||
        m_activeDocument >= static_cast<int>(m_documentBuffers.size()) || !m_hwndEditor) {
        return;
    }
    auto& buffer = m_documentBuffers[static_cast<size_t>(m_activeDocument)];
    buffer.path = m_currentFile;
    buffer.text = getEditorTextUtf8ForFile();
    buffer.modified = m_fileModified;
    if (m_activeDocument < static_cast<int>(m_openDocuments.size())) {
        m_openDocuments[static_cast<size_t>(m_activeDocument)] = m_currentFile;
    }
}

static std::string ideSessionPath() {
    // Honor --user-data-dir / RAWRXD_USER_DATA_DIR via NativeProfile (W4-PER).
    const auto dir = RawrXD::NativeProfile::directory();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return (dir / "ide_session.json").string();
}

void Win32IDE::saveSessionPanelState(nlohmann::json& session) {
    nlohmann::json panel;
    panel["visible"] = m_panelVisible;
    panel["height"] = m_panelHeight;
    panel["maximized"] = m_panelMaximized;
    panel["activeTab"] = static_cast<int>(m_activePanelTab);
    panel["sidebarVisible"] = m_sidebarVisible;
    panel["sidebarWidth"] = m_sidebarWidth;
    panel["sidebarView"] = static_cast<int>(m_currentSidebarView);
    session["panel"] = std::move(panel);
}

void Win32IDE::restoreSessionPanelState(const nlohmann::json& session) {
    if (!session.contains("panel") || !session["panel"].is_object()) return;
    const auto& panel = session["panel"];
    m_panelVisible = panel.value("visible", true);
    const int h = panel.value("height", 250);
    m_panelHeight = (std::max)(160, (std::min)(420, h > 0 ? h : 250));
    m_panelMaximized = panel.value("maximized", false);
    const int tabIdx = panel.value("activeTab", 0);
    if (tabIdx >= 0 && tabIdx <= 3) {
        m_activePanelTab = static_cast<PanelTab>(tabIdx);
    }
    m_sidebarVisible = panel.value("sidebarVisible", true);
    m_sidebarWidth = panel.value("sidebarWidth", 240);
    m_currentSidebarView = static_cast<SidebarView>(panel.value("sidebarView", 0));
    if (m_hwndMain) {
        RECT rc{};
        GetClientRect(m_hwndMain, &rc);
        SendMessage(m_hwndMain, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rc.right, rc.bottom));
    }
}

void Win32IDE::saveIdeSession() {
    persistActiveDocumentBuffer();

    // Chat sessions are process-owned state just like document buffers.  Keep
    // the outgoing session synchronized before serializing so a cold launch
    // restores the same transcript/model route instead of only restoring the
    // editor tabs.  A running request is never persisted as running: worker
    // threads and cancellation tokens cannot safely cross a process boundary.
    if (auto* session = activeChatSession()) {
        session->history = m_chatHistory;
        session->model = m_selectedChatModel;
        session->reasoningMode = m_reasoningMode;
        session->webBrowsingEnabled = m_webBrowsingEnabled;
        session->stepRows = m_agentStepTimeline.snapshotRows();
    }

    const auto modelToJson = [](const ChatModelEntry& model) {
        return nlohmann::json{
            {"source", static_cast<int>(model.source)},
            {"breadcrumb", model.breadcrumb},
            {"identifier", model.identifier}
        };
    };
    const auto historyToJson = [](const auto& history) {
        nlohmann::json result = nlohmann::json::array();
        for (const auto& message : history) {
            result.push_back({{"role", message.first}, {"content", message.second}});
        }
        return result;
    };

    nlohmann::json root;
    root["active"] = m_activeDocument;
    root["chat_mode"] = m_chatMode ? 1 : 0;
    nlohmann::json docs = nlohmann::json::array();
    for (size_t i = 0; i < m_documentBuffers.size(); ++i) {
        const auto& buffer = m_documentBuffers[i];
        docs.push_back({
            {"path", buffer.path},
            {"text", buffer.modified ? buffer.text : std::string{}},
            {"modified", buffer.modified}
        });
    }
    root["documents"] = docs;

    nlohmann::json chat = nlohmann::json::object();
    chat["active"] = m_activeChatSession;
    chat["next_id"] = m_nextChatSessionId;
    chat["sessions"] = nlohmann::json::array();
    for (const auto& session : m_chatSessions) {
        nlohmann::json serialized{
            {"id", session.id},
            {"title", session.title},
            {"model", modelToJson(session.model)},
            {"history", historyToJson(session.history)},
            {"response_buffer", session.responseBuffer},
            {"reasoning_mode", static_cast<int>(session.reasoningMode)},
            {"web_browsing_enabled", session.webBrowsingEnabled},
            {"step_rows", session.stepRows}
        };
        // Checkpoints are intentionally retained because rollback is a user
        // visible part of the chat-session contract.  Their running state is
        // not present in the checkpoint type and is therefore safe to restore.
        serialized["checkpoints"] = nlohmann::json::array();
        for (const auto& checkpoint : session.checkpoints) {
            serialized["checkpoints"].push_back({
                {"reason", checkpoint.reason},
                {"model", modelToJson(checkpoint.model)},
                {"reasoning_mode", static_cast<int>(checkpoint.reasoningMode)},
                {"allow_cloud_ghost_text", checkpoint.allowCloudGhostText},
                {"web_browsing_enabled", checkpoint.webBrowsingEnabled},
                {"max_tokens", checkpoint.maxTokens},
                {"context_tokens", checkpoint.contextTokens},
                {"history", historyToJson(checkpoint.history)},
                {"response_buffer", checkpoint.responseBuffer}
            });
        }
        chat["sessions"].push_back(std::move(serialized));
    }
    root["chat"] = std::move(chat);

    // P08: persist bottom-dock panel.height/visible/tab so WM_CLOSE → relaunch
    // restores the dragged dock height. Win32IDE_Session.cpp helpers are not
    // in the Native link set — inline the product panel block here.
    root["panel"] = nlohmann::json{
        {"visible", m_panelVisible},
        {"height", m_panelHeight},
        {"maximized", m_panelMaximized},
        {"activeTab", static_cast<int>(m_activePanelTab)},
        {"sidebarVisible", m_sidebarVisible},
        {"sidebarWidth", m_sidebarWidth},
        {"sidebarView", static_cast<int>(m_currentSidebarView)}
    };

    // Chat/agent transcript bytes may be non-UTF-8 (Ollama). Default dump() is
    // strict and throws type_error.316 from dump_escaped; uncaught -> terminate
    // -> abort -> 0xC0000409 (G021: saveIdeSession on WM_CLOSE / session persist).
    // AgentSession::Flush already uses replace; keep IDE session persist aligned.
    std::string serialized;
    try {
        serialized = root.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    } catch (const nlohmann::json::type_error&) {
        LOG_ERROR("saveIdeSession: type_error.316; writing sanitized stub");
        try {
            serialized = nlohmann::json{
                {"active", m_activeDocument},
                {"chat_mode", m_chatMode ? 1 : 0},
                {"documents", nlohmann::json::array()},
                {"chat", {
                    {"active", m_activeChatSession},
                    {"next_id", m_nextChatSessionId},
                    {"sessions", nlohmann::json::array()}
                }},
                {"flush_error", "type_error_utf8_sanitized_fallback"}
            }.dump();
        } catch (...) {
            LOG_ERROR("saveIdeSession: sanitize stub failed; skip persist");
            return;
        }
    } catch (const nlohmann::json::exception& ex) {
        LOG_ERROR(std::string("saveIdeSession: json serialize failed: ") + ex.what());
        return;
    } catch (const std::exception& ex) {
        LOG_ERROR(std::string("saveIdeSession: serialize failed: ") + ex.what());
        return;
    } catch (...) {
        LOG_ERROR("saveIdeSession: unknown serialize failure; skip persist");
        return;
    }
    std::string error;
    if (!writeBinaryFileAtomically(ideSessionPath(), serialized, error)) {
        LOG_ERROR("Failed to persist IDE session: " + error);
    }
}

void Win32IDE::loadIdeSession() {
    std::string serialized;
    std::string readError;
    const std::string sessionPath = ideSessionPath();
    if (!readBinaryFile(sessionPath, serialized, readError)) {
        const std::string tempPath = sessionPath + ".rawrxd-tmp";
        if (!readBinaryFile(tempPath, serialized, readError)) return;
        LOG_WARNING("[FILE_SAFETY] recovering IDE session from atomic temp snapshot");
    }
    // loadIdeSession must stay out of WM_CREATE (see lifecycle). Oversized /
    // poisoned LOCALAPPDATA snapshots (~100KB+ agent dumps) can still AV or
    // stall when restored post-create → keep a hard size gate.
    constexpr size_t kMaxSessionBytes = 96 * 1024;
    constexpr size_t kMaxMsgChars = 4096;
    constexpr size_t kMaxHistoryMsgs = 64;
    if (serialized.size() > kMaxSessionBytes) {
        LOG_WARNING("[FILE_SAFETY] IDE session oversized; restore skipped");
        return;
    }
    const bool skipChatRestore = false;
    try {
        nlohmann::json root = nlohmann::json::parse(serialized);

        // P08: restore panel.height FIRST — document/chat restore can throw into
        // the outer catch and previously skipped dock height (HLoad stuck 250).
        if (root.contains("panel") && root["panel"].is_object()) {
            const auto& panel = root["panel"];
            m_panelVisible = panel.value("visible", true);
            m_panelHeight = panel.value("height", m_panelHeight);
            if (m_panelHeight < 160) m_panelHeight = 160;
            if (m_panelHeight > 420) m_panelHeight = 420;
            m_panelMaximized = panel.value("maximized", false);
            const int tabIdx = panel.value("activeTab", static_cast<int>(m_activePanelTab));
            if (tabIdx >= 0 && tabIdx <= 3) {
                m_activePanelTab = static_cast<PanelTab>(tabIdx);
            }
            m_sidebarVisible = panel.value("sidebarVisible", m_sidebarVisible);
            m_sidebarWidth = panel.value("sidebarWidth", m_sidebarWidth);
            // Apply dock geometry synchronously so relaunch probes (HLoad)
            // do not sample the createPanel default 250 before posted WM_SIZE.
            if (m_hwndPanelContainer && IsWindow(m_hwndPanelContainer) &&
                m_hwndMain && IsWindow(m_hwndMain)) {
                layoutBottomDock();
            }
        }

        const auto modelFromJson = [](const nlohmann::json& value) {
            ChatModelEntry model;
            if (!value.is_object()) return model;
            const int source = value.value("source", static_cast<int>(ChatModelEntry::Source::LocalFile));
            if (source >= static_cast<int>(ChatModelEntry::Source::LocalFile) &&
                source <= static_cast<int>(ChatModelEntry::Source::KiloFree)) {
                model.source = static_cast<ChatModelEntry::Source>(source);
            }
            model.breadcrumb = value.value("breadcrumb", std::string{});
            model.identifier = value.value("identifier", std::string{});
            return model;
        };
        const auto historyFromJson = [kMaxHistoryMsgs, kMaxMsgChars](const nlohmann::json& value) {
            std::vector<std::pair<std::string, std::string>> history;
            if (!value.is_array()) return history;
            for (const auto& message : value) {
                if (!message.is_object()) continue;
                if (history.size() >= kMaxHistoryMsgs) break;
                std::string content = message.value("content", std::string{});
                if (content.size() > kMaxMsgChars) {
                    content.resize(kMaxMsgChars);
                    content.append("\n…[truncated]");
                }
                history.emplace_back(
                    message.value("role", std::string{}),
                    std::move(content));
            }
            return history;
        };

        if (!root.contains("documents") || !root["documents"].is_array()) return;
        m_openDocuments.clear();
        m_documentBuffers.clear();
        if (m_hwndDocTabs) TabCtrl_DeleteAllItems(m_hwndDocTabs);
        // Session documents are index-authoritative.  Do NOT route through
        // addDocumentTab(): its duplicate-path collapse (and single-Untitled
        // rule) shrinks the vector, misaligns active/text restore, and yields
        // T10 FAIL_SESSION_PRESENT_NOT_RESTORED after multi-tab sessions
        // (active tab dropped; wrong buffer materialized).
        const size_t docCount = root["documents"].size();
        const size_t restoreCount = (std::min)(docCount, kMaxOpenDocuments);
        m_openDocuments.reserve(restoreCount);
        m_documentBuffers.reserve(restoreCount);
        size_t restored = 0;
        for (const auto& doc : root["documents"]) {
            if (restored >= kMaxOpenDocuments) {
                LOG_WARNING("[SESSION] document restore capped at kMaxOpenDocuments=1000");
                break;
            }
            std::string path = doc.value("path", std::string{});
            // Demote leaf-only / illegal names (e.g. "t8 01 doc") to Untitled
            // so session restore cannot re-stick an unopenable tab.
            if (!path.empty() && !isOpenableDocumentPath(path)) {
                LOG_WARNING("[SESSION] demoting invalid document path: " + path);
                path.clear();
            }
            DocumentBuffer buffer;
            buffer.path = path;
            buffer.label = (path.empty() ? std::string("Untitled")
                                         : extractLeafName(path)) + "  x";
            buffer.text = doc.value("text", std::string{});
            buffer.modified = doc.value("modified", false);
            if (!buffer.modified && !buffer.path.empty()) {
                if (!readBinaryFile(buffer.path, buffer.text, readError)) {
                    LOG_ERROR("Failed to restore session file " + buffer.path +
                              ": " + readError);
                    path.clear();
                    buffer.path.clear();
                    buffer.label = "Untitled  x";
                }
            }
            // Keep unsaved text when a bad path was demoted to Untitled.
            if (buffer.path.empty() && !buffer.text.empty()) {
                buffer.modified = true;
            }
            m_documentBuffers.push_back(std::move(buffer));
            m_openDocuments.push_back(path);
            ++restored;
        }
        m_activeDocument = -1;
        updateDocumentTabs();
        if (m_openDocuments.empty()) {
            addDocumentTab(std::string());
            // Still restore dock height/visibility for P08 even with empty docs.
            restoreSessionPanelState(root);
            return;
        }
        if (root.contains("chat_mode")) {
            m_chatMode = root["chat_mode"].get<int>() != 0;
        }

        // Restore chat sessions independently of document restoration.  The
        // chat panel is created before the editor session loader, so the tab
        // control and its selectors are available here.  Older snapshots do
        // not contain "chat" and continue to use the default Chat 1 session.
        // Oversized snapshots skip chat restore to keep CreateWindowExA safe.
        if (!skipChatRestore && root.contains("chat") && root["chat"].is_object()) {
            const auto& chat = root["chat"];
            if (chat.contains("sessions") && chat["sessions"].is_array() &&
                !chat["sessions"].empty()) {
                std::vector<ChatSessionState> restored;
                restored.reserve(chat["sessions"].size());
                for (const auto& value : chat["sessions"]) {
                    if (!value.is_object()) continue;
                    ChatSessionState session;
                    session.id = value.value("id", m_nextChatSessionId++);
                    session.title = value.value("title", std::string{});
                    session.model = modelFromJson(value.value("model", nlohmann::json::object()));
                    session.history = historyFromJson(value.value("history", nlohmann::json::array()));
                    session.responseBuffer = value.value("response_buffer", std::string{});
                    const int reasoning = value.value("reasoning_mode", static_cast<int>(ReasoningMode::Instant));
                    if (reasoning >= static_cast<int>(ReasoningMode::Instant) &&
                        reasoning <= static_cast<int>(ReasoningMode::Max)) {
                        session.reasoningMode = static_cast<ReasoningMode>(reasoning);
                    }
                    session.webBrowsingEnabled = value.value("web_browsing_enabled", false);
                    if (value.contains("step_rows") && value["step_rows"].is_array()) {
                        session.stepRows = value["step_rows"].get<std::vector<std::string>>();
                    }
                    if (value.contains("checkpoints") && value["checkpoints"].is_array()) {
                        for (const auto& checkpointValue : value["checkpoints"]) {
                            if (!checkpointValue.is_object()) continue;
                            ChatSessionCheckpoint checkpoint;
                            checkpoint.reason = checkpointValue.value("reason", std::string{});
                            checkpoint.model = modelFromJson(
                                checkpointValue.value("model", nlohmann::json::object()));
                            const int checkpointReasoning = checkpointValue.value(
                                "reasoning_mode", static_cast<int>(ReasoningMode::Instant));
                            if (checkpointReasoning >= static_cast<int>(ReasoningMode::Instant) &&
                                checkpointReasoning <= static_cast<int>(ReasoningMode::Max)) {
                                checkpoint.reasoningMode = static_cast<ReasoningMode>(checkpointReasoning);
                            }
                            checkpoint.allowCloudGhostText = checkpointValue.value(
                                "allow_cloud_ghost_text", false);
                            checkpoint.webBrowsingEnabled = checkpointValue.value(
                                "web_browsing_enabled", false);
                            checkpoint.maxTokens = checkpointValue.value("max_tokens", 4096);
                            checkpoint.contextTokens = checkpointValue.value("context_tokens", 65536);
                            checkpoint.history = historyFromJson(
                                checkpointValue.value("history", nlohmann::json::array()));
                            checkpoint.responseBuffer = checkpointValue.value(
                                "response_buffer", std::string{});
                            session.checkpoints.push_back(std::move(checkpoint));
                        }
                    }
                    // A persisted process cannot have a live worker.  Restore
                    // the transcript but force the new process to idle.
                    session.running = false;
                    restored.push_back(std::move(session));
                }
                if (!restored.empty()) {
                    m_chatSessions = std::move(restored);
                    m_closedChatSessions.clear();
                    int maxId = 0;
                    for (const auto& session : m_chatSessions) maxId = std::max(maxId, session.id);
                    m_nextChatSessionId = std::max(
                        chat.value("next_id", maxId + 1), maxId + 1);
                    int activeChat = chat.value("active", 0);
                    if (activeChat < 0 || activeChat >= static_cast<int>(m_chatSessions.size())) {
                        activeChat = 0;
                    }
                    updateChatSessionTabs();
                    switchChatSession(activeChat);
                }
            }
        }

        int active = root.value("active", 0);
        if (active < 0 || active >= static_cast<int>(m_openDocuments.size())) active = 0;
        if (m_hwndDocTabs) {
            TabCtrl_SetCurSel(m_hwndDocTabs, active);
        }
        // Force switchDocumentTab to apply buffer.text even when the active
        // index already matches (same-tab early-return would skip HWND load).
        m_activeDocument = -1;
        if (m_hwndEditor) {
            m_pendingSessionEditorMaterialize = false;
            switchDocumentTab(active);
        } else {
            m_activeDocument = active;
            m_pendingSessionEditorMaterialize = true;
        }

    } catch (...) {
        // A corrupt canonical snapshot must not block IDE launch. The atomic
        // writer leaves a recoverable temp snapshot for the next start.
        LOG_ERROR("[FILE_SAFETY] IDE session snapshot was invalid");
    }
}

// Note: openFile() is defined in Win32IDE_clean.cpp and just calls openFileDialog()
