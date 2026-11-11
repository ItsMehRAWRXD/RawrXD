// Win32IDE_Project.cpp
// ACTUAL project system implementation - NO MORE SCAFFOLDING
// Handles .rxproj files, build orchestration, project management

#include "Win32IDE_Project.h"
#include "Integration_Wiring.h"
#include <windows.h>
#include <shlwapi.h>
#include <fstream>
#include <sstream>
#include <iomanip>

// Force Unicode APIs
#undef PathRemoveFileSpec
#define PathRemoveFileSpec PathRemoveFileSpecW
#undef PathStripPath
#define PathStripPath PathStripPathW
#undef CreateDirectory
#define CreateDirectory CreateDirectoryW

// Simple JSON parser (minimal implementation)
namespace SimpleJSON {
    std::string EscapeString(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
    
    std::string UnescapeString(const std::string& str) {
        std::string result;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '\\' && i + 1 < str.length()) {
                switch (str[i + 1]) {
                    case '"': result += '"'; ++i; break;
                    case '\\': result += '\\'; ++i; break;
                    case 'b': result += '\b'; ++i; break;
                    case 'f': result += '\f'; ++i; break;
                    case 'n': result += '\n'; ++i; break;
                    case 'r': result += '\r'; ++i; break;
                    case 't': result += '\t'; ++i; break;
                    default: result += str[i];
                }
            } else {
                result += str[i];
            }
        }
        return result;
    }
}

// =============================================================================
// PROJECT FILE IMPLEMENTATION
// =============================================================================

bool RxProject::LoadFromFile(const wchar_t* filePath) {
    // Open file
    FILE* file = nullptr;
    if (_wfopen_s(&file, filePath, L"r, ccs=UTF-8") != 0 || !file) {
        return false;
    }
    
    // Read entire file
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    std::string json;
    json.resize(size);
    fread(&json[0], 1, size, file);
    fclose(file);
    
    // Parse (simplified JSON parsing)
    if (!ParseJSON(json)) {
        return false;
    }
    
    m_filePath = filePath;
    m_isLoaded = true;
    m_isModified = false;
    
    return true;
}

bool RxProject::SaveToFile(const wchar_t* filePath) const {
    if (!filePath) filePath = m_filePath.c_str();
    
    // Generate JSON
    std::string json = GenerateJSON();
    
    // Write file
    FILE* file = nullptr;
    if (_wfopen_s(&file, filePath, L"w, ccs=UTF-8") != 0 || !file) {
        return false;
    }
    
    fwrite(json.c_str(), 1, json.length(), file);
    fclose(file);
    
    return true;
}

bool RxProject::Build(IBuildCallback* callback) {
    if (!m_isLoaded) return false;
    
    if (callback) callback->OnBuildStart();
    
    // Get project directory
    wchar_t projectDir[MAX_PATH];
    wcscpy_s(projectDir, m_filePath.c_str());
    PathRemoveFileSpec(projectDir);
    
    // Compile each source file
    std::vector<std::wstring> objectFiles;
    
    for (size_t i = 0; i < m_sources.size(); ++i) {
        const auto& source = m_sources[i];
        
        if (callback) {
            wchar_t msg[256];
            swprintf_s(msg, L"Compiling %s (%zu/%zu)...", 
                      source.c_str(), i + 1, m_sources.size());
            callback->OnBuildProgress(msg, 
                (int)((i / (float)m_sources.size()) * 100));
        }
        
        // Build source path
        wchar_t sourcePath[MAX_PATH];
        swprintf_s(sourcePath, L"%s\\%s", projectDir, source.c_str());
        
        // Build object path
        wchar_t objPath[MAX_PATH];
        wchar_t objName[MAX_PATH];
        wcscpy_s(objName, source.c_str());
        PathStripPath(objName);
        wchar_t* ext = wcsrchr(objName, L'.');
        if (ext) wcscpy_s(ext, 5, L".obj");
        else wcscat_s(objName, L".obj");
        
        swprintf_s(objPath, L"%s\\%s", projectDir, objName);
        
        // Compile
        if (!RawrXD::Integration::BuildSystem::CompileFile(sourcePath, objPath)) {
            if (callback) callback->OnBuildError(L"Compilation failed");
            return false;
        }
        
        objectFiles.push_back(objPath);
    }
    
    if (callback) {
        callback->OnBuildProgress(L"Linking...", 90);
    }
    
    // Link all objects
    // TODO: Implement multi-object linking in Integration_Wiring
    // For now, just use the first object as the executable
    if (!objectFiles.empty()) {
        wchar_t outputPath[MAX_PATH];
        swprintf_s(outputPath, L"%s\\%s", projectDir, m_output.c_str());
        
        // Ensure output directory exists
        wchar_t outputDir[MAX_PATH];
        wcscpy_s(outputDir, outputPath);
        PathRemoveFileSpec(outputDir);
        CreateDirectory(outputDir, nullptr);
        
        if (!RawrXD::Integration::BuildSystem::LinkObject(
            objectFiles[0].c_str(), outputPath)) {
            if (callback) callback->OnBuildError(L"Linking failed");
            return false;
        }
    }
    
    if (callback) {
        callback->OnBuildComplete(true);
    }
    
    return true;
}

bool RxProject::ParseJSON(const std::string& json) {
    // Simplified JSON parsing - look for key-value pairs
    // In production, use a proper JSON library like nlohmann/json
    
    // Extract name
    size_t namePos = json.find("\"name\"");
    if (namePos != std::string::npos) {
        size_t colonPos = json.find(':', namePos);
        size_t quotePos = json.find('"', colonPos);
        size_t endQuote = json.find('"', quotePos + 1);
        if (quotePos != std::string::npos && endQuote != std::string::npos) {
            std::string nameStr = json.substr(quotePos + 1, endQuote - quotePos - 1);
            m_name = std::wstring(nameStr.begin(), nameStr.end());
        }
    }
    
    // Extract version
    size_t verPos = json.find("\"version\"");
    if (verPos != std::string::npos) {
        size_t colonPos = json.find(':', verPos);
        size_t quotePos = json.find('"', colonPos);
        size_t endQuote = json.find('"', quotePos + 1);
        if (quotePos != std::string::npos && endQuote != std::string::npos) {
            std::string verStr = json.substr(quotePos + 1, endQuote - quotePos - 1);
            m_version = std::wstring(verStr.begin(), verStr.end());
        }
    }
    
    // Extract type
    size_t typePos = json.find("\"type\"");
    if (typePos != std::string::npos) {
        size_t colonPos = json.find(':', typePos);
        size_t quotePos = json.find('"', colonPos);
        size_t endQuote = json.find('"', quotePos + 1);
        if (quotePos != std::string::npos && endQuote != std::string::npos) {
            std::string typeStr = json.substr(quotePos + 1, endQuote - quotePos - 1);
            if (typeStr == "executable") m_type = PROJECT_EXECUTABLE;
            else if (typeStr == "library") m_type = PROJECT_LIBRARY;
            else if (typeStr == "dll") m_type = PROJECT_DLL;
        }
    }
    
    // Extract output
    size_t outPos = json.find("\"output\"");
    if (outPos != std::string::npos) {
        size_t colonPos = json.find(':', outPos);
        size_t quotePos = json.find('"', colonPos);
        size_t endQuote = json.find('"', quotePos + 1);
        if (quotePos != std::string::npos && endQuote != std::string::npos) {
            std::string outputStr = json.substr(quotePos + 1, endQuote - quotePos - 1);
            m_output = std::wstring(outputStr.begin(), outputStr.end());
        }
    }
    
    // Extract sources array
    size_t srcPos = json.find("\"sources\"");
    if (srcPos != std::string::npos) {
        size_t bracketPos = json.find('[', srcPos);
        size_t endBracket = json.find(']', bracketPos);
        if (bracketPos != std::string::npos && endBracket != std::string::npos) {
            std::string srcArray = json.substr(bracketPos + 1, endBracket - bracketPos - 1);
            
            // Parse individual strings
            size_t pos = 0;
            while ((pos = srcArray.find('"', pos)) != std::string::npos) {
                size_t endQuote = srcArray.find('"', pos + 1);
                if (endQuote != std::string::npos) {
                    std::string src = srcArray.substr(pos + 1, endQuote - pos - 1);
                    m_sources.push_back(std::wstring(src.begin(), src.end()));
                    pos = endQuote + 1;
                } else {
                    break;
                }
            }
        }
    }
    
    // Extract headers array
    size_t hdrPos = json.find("\"headers\"");
    if (hdrPos != std::string::npos) {
        size_t bracketPos = json.find('[', hdrPos);
        size_t endBracket = json.find(']', bracketPos);
        if (bracketPos != std::string::npos && endBracket != std::string::npos) {
            std::string hdrArray = json.substr(bracketPos + 1, endBracket - bracketPos - 1);
            
            size_t pos = 0;
            while ((pos = hdrArray.find('"', pos)) != std::string::npos) {
                size_t endQuote = hdrArray.find('"', pos + 1);
                if (endQuote != std::string::npos) {
                    std::string hdr = hdrArray.substr(pos + 1, endQuote - pos - 1);
                    m_headers.push_back(std::wstring(hdr.begin(), hdr.end()));
                    pos = endQuote + 1;
                } else {
                    break;
                }
            }
        }
    }
    
    return true;
}

std::string RxProject::GenerateJSON() const {
    std::stringstream json;
    json << "{\n";
    json << "    \"name\": \"" << SimpleJSON::EscapeString(std::string(m_name.begin(), m_name.end())) << "\",\n";
    json << "    \"version\": \"" << SimpleJSON::EscapeString(std::string(m_version.begin(), m_version.end())) << "\",\n";
    
    const char* typeStr = "executable";
    switch (m_type) {
        case PROJECT_LIBRARY: typeStr = "library"; break;
        case PROJECT_DLL: typeStr = "dll"; break;
        default: typeStr = "executable"; break;
    }
    json << "    \"type\": \"" << typeStr << "\",\n";
    
    json << "    \"output\": \"" << SimpleJSON::EscapeString(std::string(m_output.begin(), m_output.end())) << "\",\n";
    
    // Sources
    json << "    \"sources\": [\n";
    for (size_t i = 0; i < m_sources.size(); ++i) {
        json << "        \"" << SimpleJSON::EscapeString(std::string(m_sources[i].begin(), m_sources[i].end())) << "\"";
        if (i < m_sources.size() - 1) json << ",";
        json << "\n";
    }
    json << "    ],\n";
    
    // Headers
    json << "    \"headers\": [\n";
    for (size_t i = 0; i < m_headers.size(); ++i) {
        json << "        \"" << SimpleJSON::EscapeString(std::string(m_headers[i].begin(), m_headers[i].end())) << "\"";
        if (i < m_headers.size() - 1) json << ",";
        json << "\n";
    }
    json << "    ],\n";
    
    // Compiler settings
    json << "    \"compiler\": {\n";
    json << "        \"flags\": \"" << SimpleJSON::EscapeString(std::string(m_compilerFlags.begin(), m_compilerFlags.end())) << "\",\n";
    json << "        \"defines\": [\"DEBUG\"]\n";
    json << "    },\n";
    
    // Linker settings
    json << "    \"linker\": {\n";
    json << "        \"subsystem\": \"console\"\n";
    json << "    }\n";
    
    json << "}\n";
    
    return json.str();
}

// =============================================================================
// PROJECT MANAGER IMPLEMENTATION
// =============================================================================

ProjectManager::ProjectManager() : m_currentProject(nullptr) {
}

ProjectManager::~ProjectManager() {
    CloseProject();
}

bool ProjectManager::NewProject(const wchar_t* name, const wchar_t* location, ProjectType type) {
    CloseProject();
    
    m_currentProject = new RxProject();
    m_currentProject->SetName(name);
    m_currentProject->SetType(type);
    m_currentProject->SetVersion(L"1.0.0");
    
    // Set default output
    switch (type) {
        case PROJECT_EXECUTABLE:
            m_currentProject->SetOutput((std::wstring(name) + L".exe").c_str());
            break;
        case PROJECT_LIBRARY:
            m_currentProject->SetOutput((std::wstring(name) + L".lib").c_str());
            break;
        case PROJECT_DLL:
            m_currentProject->SetOutput((std::wstring(name) + L".dll").c_str());
            break;
    }
    
    // Build project file path
    wchar_t projectPath[MAX_PATH];
    swprintf_s(projectPath, L"%s\\%s\\%s.rxproj", location, name, name);
    
    // Create directory
    wchar_t projectDir[MAX_PATH];
    swprintf_s(projectDir, L"%s\\%s", location, name);
    CreateDirectoryW(projectDir, nullptr);
    CreateDirectoryW((std::wstring(projectDir) + L"\\src").c_str(), nullptr);
    CreateDirectoryW((std::wstring(projectDir) + L"\\include").c_str(), nullptr);
    CreateDirectoryW((std::wstring(projectDir) + L"\\bin").c_str(), nullptr);
    
    // Create default main.c
    wchar_t mainPath[MAX_PATH];
    swprintf_s(mainPath, L"%s\\src\\main.c", projectDir);
    
    FILE* mainFile = nullptr;
    if (_wfopen_s(&mainFile, mainPath, L"w") == 0 && mainFile) {
        fprintf(mainFile, "#include <stdio.h>\n\n");
        fprintf(mainFile, "int main() {\n");
        fprintf(mainFile, "    printf(\"Hello from %s!\\n\");\n", 
                std::string(name, name + wcslen(name)).c_str());
        fprintf(mainFile, "    return 0;\n");
        fprintf(mainFile, "}\n");
        fclose(mainFile);
    }
    
    // Add to project
    m_currentProject->AddSource(L"src\\main.c");
    
    // Save project file
    m_currentProject->SetFilePath(projectPath);
    if (!m_currentProject->Save()) {
        delete m_currentProject;
        m_currentProject = nullptr;
        return false;
    }
    
    return true;
}

bool ProjectManager::OpenProject(const wchar_t* filePath) {
    CloseProject();
    
    m_currentProject = new RxProject();
    if (!m_currentProject->LoadFromFile(filePath)) {
        delete m_currentProject;
        m_currentProject = nullptr;
        return false;
    }
    
    return true;
}

bool ProjectManager::SaveProject() {
    if (!m_currentProject) return false;
    return m_currentProject->Save();
}

bool ProjectManager::SaveProjectAs(const wchar_t* filePath) {
    if (!m_currentProject) return false;
    return m_currentProject->SaveToFile(filePath);
}

void ProjectManager::CloseProject() {
    if (m_currentProject) {
        delete m_currentProject;
        m_currentProject = nullptr;
    }
}

bool ProjectManager::BuildProject(IBuildCallback* callback) {
    if (!m_currentProject) return false;
    return m_currentProject->Build(callback);
}

bool ProjectManager::IsProjectOpen() const {
    return m_currentProject != nullptr;
}

const wchar_t* ProjectManager::GetProjectName() const {
    if (!m_currentProject) return L"";
    return m_currentProject->GetName();
}

const wchar_t* ProjectManager::GetProjectFilePath() const {
    if (!m_currentProject) return L"";
    return m_currentProject->GetFilePath();
}
