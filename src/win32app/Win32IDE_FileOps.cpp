// File Operations Implementation for Win32IDE
// 9 comprehensive file management features

#include "Win32IDE.h"
#include "IDELogger.h"
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
#include <nlohmann/json.hpp>
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// FILE OPERATIONS (9 Features)
// ============================================================================

namespace {

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
    const std::string tempPath = path + ".rawrxd-tmp-" +
        std::to_string(static_cast<unsigned long>(GetCurrentProcessId()));
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

    SETTEXTEX setText{};
    setText.flags = ST_DEFAULT;
    setText.codepage = isValidUtf8(text) ? CP_UTF8 : CP_ACP;
    const LRESULT result = SendMessageA(
        m_hwndEditor, EM_SETTEXTEX, reinterpret_cast<WPARAM>(&setText),
        reinterpret_cast<LPARAM>(text.c_str()));

    m_suppressEditorDirty = wasSuppressed;
    if (!text.empty() && result == 0) {
        LOG_ERROR("UTF-8 editor load failed");
        return false;
    }
    return true;
}

std::string Win32IDE::getEditorTextUtf8ForFile() const {
    if (!m_hwndEditor) return {};
    GETTEXTLENGTHEX lengthInfo{};
    lengthInfo.flags = GTL_USECRLF | GTL_NUMBYTES;
    lengthInfo.codepage = CP_UTF8;
    const LRESULT byteCount = SendMessageA(
        m_hwndEditor, EM_GETTEXTLENGTHEX, reinterpret_cast<WPARAM>(&lengthInfo), 0);
    if (byteCount <= 0) return {};

    GETTEXTEX getText{};
    getText.cb = static_cast<DWORD>(byteCount + 1);
    getText.flags = GT_USECRLF;
    getText.codepage = CP_UTF8;
    std::string result(static_cast<size_t>(byteCount) + 1, '\0');
    const LRESULT copied = SendMessageA(
        m_hwndEditor, EM_GETTEXTEX, reinterpret_cast<WPARAM>(&getText),
        reinterpret_cast<LPARAM>(result.data()));
    if (copied <= 0) return {};
    result.resize(static_cast<size_t>(copied));
    return result;
}

void Win32IDE::openFileDialog() {
    LOG_INFO("openFileDialog() called");
    OPENFILENAMEA ofn = {};
    char szFile[MAX_PATH] = {0};
    
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "Text Files (*.txt;*.ps1;*.cpp;*.h;*.md;*.json)\0*.txt;*.ps1;*.cpp;*.h;*.md;*.json\0"
                      "All Files (*.*)\0*.*\0"
                      "PowerShell Scripts (*.ps1)\0*.ps1\0"
                      "C++ Files (*.cpp;*.h)\0*.cpp;*.h\0"
                      "GGUF Models (*.gguf)\0*.gguf\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = m_currentDirectory.empty() ? NULL : m_currentDirectory.c_str();
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_ENABLESIZING;
    
    LOG_DEBUG("Opening file dialog");
    if (GetOpenFileNameA(&ofn)) {
        std::string filePath = szFile;
        LOG_INFO("File selected: " + filePath);
        
        // Check if it's a GGUF model file FIRST - DON'T load as text, bypass size limits!
        if (filePath.find(".gguf") != std::string::npos || filePath.find(".GGUF") != std::string::npos) {
            LOG_INFO("Detected GGUF file, loading as model");
            // GGUF files can be multi-GB, they use streaming loader
            // Add safety check to prevent crashes on corrupted/invalid files
            try {
                m_ggufLoader = std::make_unique<StreamingGGUFLoader>();
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
            if (readBinaryFile(szFile, content, readError)) {
                // Check file size to prevent loading huge TEXT files into editor
                const size_t fileSize = content.size();
                
                if (fileSize > 10 * 1024 * 1024) { // 10MB limit for TEXT files in editor
                    MessageBoxA(m_hwndMain, "Text file too large to open in editor (>10MB).\nGGUF models use the streaming loader automatically.", "File Too Large", MB_OK | MB_ICONWARNING);
                    return;
                }
                
                if (!setEditorTextUtf8FromFile(content)) {
                    MessageBoxA(m_hwndMain, "Failed to load file text", "Error",
                                MB_OK | MB_ICONERROR);
                    return;
                }
                
                m_currentFile = szFile;
                m_fileModified = false;
                setCurrentDirectoryFromFile(m_currentFile);
                updateTitleBarText();
                
                // Update recent files
                updateRecentFiles(szFile);
                
                // Update window title
                std::string title = "RawrXD IDE - " + m_currentFile;
                SetWindowTextA(m_hwndMain, title.c_str());
                
                // Update status bar
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File opened successfully");
                
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
            if (!setEditorTextUtf8FromFile(content)) return;
            
            m_currentFile = filePath;
            m_fileModified = false;
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
    OPENFILENAMEA ofn = {};
    char szFile[MAX_PATH] = {0};
    
    if (!m_currentFile.empty()) {
        strncpy(szFile, m_currentFile.c_str(), MAX_PATH - 1);
    }
    
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "All Files (*.*)\0*.*\0"
                      "PowerShell Scripts (*.ps1)\0*.ps1\0"
                      "C++ Files (*.cpp;*.h)\0*.cpp;*.h\0"
                      "Text Files (*.txt)\0*.txt\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = m_currentDirectory.empty() ? NULL : m_currentDirectory.c_str();
    ofn.lpstrDefExt = m_defaultFileExtension.c_str();
    
    if (isSave) {
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_EXPLORER | OFN_ENABLESIZING;
        if (GetSaveFileNameA(&ofn)) {
            return std::string(szFile);
        }
    } else {
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_ENABLESIZING;
        if (GetOpenFileNameA(&ofn)) {
            return std::string(szFile);
        }
    }
    
    return "";
}

void Win32IDE::saveAll() {
    if (!m_currentFile.empty() && m_fileModified) {
        saveFile();
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"All files saved");
    }
}

void Win32IDE::closeFile() {
    if (m_fileModified && !promptSaveChanges()) {
        return;
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
    
    std::ifstream file("recent_files.ini");
    if (file) {
        std::string line;
        while (std::getline(file, line) && m_recentFiles.size() < MAX_RECENT_FILES) {
            if (!line.empty()) {
                m_recentFiles.push_back(line);
            }
        }
        file.close();
    }
}

void Win32IDE::saveRecentFiles() {
    std::ofstream file("recent_files.ini");
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
    char base[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, base))) {
        return "ide_session.json";
    }
    const std::string dir = std::string(base) + "\\RawrXD";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir + "\\ide_session.json";
}

void Win32IDE::saveIdeSession() {
    persistActiveDocumentBuffer();
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
    const std::string serialized = root.dump();
    std::string error;
    if (!writeBinaryFileAtomically(ideSessionPath(), serialized, error)) {
        LOG_ERROR("Failed to persist IDE session: " + error);
    }
}

void Win32IDE::loadIdeSession() {
    std::ifstream in(ideSessionPath(), std::ios::binary);
    if (!in) return;
    try {
        nlohmann::json root = nlohmann::json::parse(in);
        if (!root.contains("documents") || !root["documents"].is_array()) return;
        m_openDocuments.clear();
        m_documentBuffers.clear();
        if (m_hwndDocTabs) TabCtrl_DeleteAllItems(m_hwndDocTabs);
        for (const auto& doc : root["documents"]) {
            DocumentBuffer buffer;
            buffer.path = doc.value("path", std::string{});
            buffer.modified = doc.value("modified", false);
            buffer.text = doc.value("text", std::string{});
            if (!buffer.modified && !buffer.path.empty()) {
                std::string readError;
                if (!readBinaryFile(buffer.path, buffer.text, readError)) {
                    LOG_ERROR("Failed to restore session file " + buffer.path + ": " + readError);
                }
            }
            const std::string label = buffer.path.empty()
                ? std::string("Untitled") : extractLeafName(buffer.path);
            if (m_hwndDocTabs) {
                TCITEMA tie{};
                tie.mask = TCIF_TEXT;
                tie.pszText = const_cast<char*>(label.c_str());
                TabCtrl_InsertItem(m_hwndDocTabs,
                    static_cast<int>(m_openDocuments.size()), &tie);
            }
            m_openDocuments.push_back(buffer.path);
            m_documentBuffers.push_back(std::move(buffer));
        }
        if (m_openDocuments.empty()) {
            addDocumentTab(std::string());
            return;
        }
        if (root.contains("chat_mode")) {
            m_chatMode = root["chat_mode"].get<int>() != 0;
        }
        int active = root.value("active", 0);
        if (active < 0 || active >= static_cast<int>(m_openDocuments.size())) active = 0;
        switchDocumentTab(active);
    } catch (...) {
        // Corrupt session must not block IDE launch.
    }
}

// Note: openFile() is defined in Win32IDE_clean.cpp and just calls openFileDialog()
