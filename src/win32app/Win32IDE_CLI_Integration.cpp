// ============================================================================
// Win32IDE_CLI_Integration.cpp — Complete CLI→GUI Integration
// ============================================================================
// Wires all completed CLI tools into the Win32 IDE GUI
// Batch 1-10: Core compilers, build system, CI/CD, model management
// ============================================================================

#include "Win32IDE.h"
#include "IDELogger.h"
#include <windows.h>
#include <shellapi.h>
#include <filesystem>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <future>

#pragma comment(lib, "shell32.lib")

// ============================================================================
// CLI Tool Paths
// ============================================================================
namespace CLIPaths {
    const char* COMPILER_DIR = "d:\\rawrxd\\compilers\\real_compilers";
    const char* NATIVE_TOOLCHAIN = "d:\\rawrxd\\compilers\\native_toolchain";
    const char* CI_TOOLS = "d:\\rawrxd\\tools\\ci";
    const char* INHOUSE_TOOLS = "d:\\rawrxd\\tools\\inhouse\\bin";
    const char* CLI_V3 = "d:\\rawrxd\\compilers\\rawrxd_ide_cli_v3.bat";
}

// ============================================================================
// Batch 1: Core Compilers Integration
// ============================================================================
namespace CompilerIntegration {
    
    struct CompilerInfo {
        std::string name;
        std::string exePath;
        std::string extensions;
        bool isNative;
    };
    
    static std::vector<CompilerInfo> g_compilers = {
        {"Python", "python_compiler_real.exe", ".py", false},
        {"JavaScript", "javascript_compiler_real.exe", ".js", false},
        {"Bash", "bash_compiler_real.exe", ".sh", false},
        {"PowerShell", "powershell_compiler_real.exe", ".ps1", false},
        {"C#", "csharp_compiler_real.exe", ".cs", false},
        {"Java", "java_compiler_real.exe", ".java", false},
        {"EON", "eon_compiler_real.exe", ".eon", false},
        {"Assembly", "compile_asm.bat", ".asm", true},
        {"C/C++", "compile_c.bat", ".c,.cpp", true},
    };
    
    bool IsCompilerAvailable(const std::string& compilerName) {
        std::string path = std::string(CLIPaths::COMPILER_DIR) + "\\" + compilerName;
        return std::filesystem::exists(path);
    }
    
    std::string GetCompilerForFile(const std::string& filePath) {
        std::string ext = std::filesystem::path(filePath).extension().string();
        for (const auto& comp : g_compilers) {
            if (comp.extensions.find(ext) != std::string::npos) {
                return comp.exePath;
            }
        }
        return "";
    }
    
    // Execute compiler and capture output
    struct CompileResult {
        bool success;
        std::string output;
        std::string error;
        int exitCode;
    };
    
    CompileResult ExecuteCompiler(const std::string& sourceFile, const std::string& outputFile) {
        CompileResult result;
        
        std::string compiler = GetCompilerForFile(sourceFile);
        if (compiler.empty()) {
            result.success = false;
            result.error = "No compiler found for file type";
            return result;
        }
        
        std::string cmdLine = std::string(CLIPaths::COMPILER_DIR) + "\\" + compiler + " \"" + sourceFile + "\" \"" + outputFile + "\"";
        
        SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
        HANDLE hReadPipe, hWritePipe;
        CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
        
        STARTUPINFOA si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.wShowWindow = SW_HIDE;
        
        PROCESS_INFORMATION pi = {0};
        
        if (CreateProcessA(nullptr, (LPSTR)cmdLine.c_str(), nullptr, nullptr, TRUE, 
                          CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            CloseHandle(hWritePipe);
            
            // Read output
            char buffer[4096];
            DWORD bytesRead;
            std::string output;
            while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                output += buffer;
            }
            
            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            
            result.success = (exitCode == 0);
            result.output = output;
            result.exitCode = exitCode;
            
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            result.success = false;
            result.error = "Failed to start compiler";
        }
        
        CloseHandle(hReadPipe);
        return result;
    }
}

// ============================================================================
// Batch 2: Build System Integration
// ============================================================================
namespace BuildSystemIntegration {
    
    struct BuildTask {
        std::string projectPath;
        std::string config; // Debug/Release
        std::string target;
        bool clean;
    };
    
    bool RunCMakeBuild(const std::string& projectDir, const std::string& config, bool clean) {
        std::string buildDir = projectDir + "\\build";
        
        if (clean && std::filesystem::exists(buildDir)) {
            std::filesystem::remove_all(buildDir);
        }
        
        if (!std::filesystem::exists(buildDir)) {
            std::filesystem::create_directories(buildDir);
        }
        
        // Configure
        std::string configureCmd = "cmake -B \"" + buildDir + "\" -S \"" + projectDir + "\" -DCMAKE_BUILD_TYPE=" + config;
        int configResult = system(configureCmd.c_str());
        if (configResult != 0) return false;
        
        // Build
        std::string buildCmd = "cmake --build \"" + buildDir + "\" --config " + config;
        int buildResult = system(buildCmd.c_str());
        
        return buildResult == 0;
    }
    
    bool RunNinjaBuild(const std::string& projectDir, bool clean) {
        std::string buildDir = projectDir + "\\build";
        
        if (clean && std::filesystem::exists(buildDir)) {
            std::filesystem::remove_all(buildDir);
        }
        
        std::string ninjaCmd = "cd \"" + buildDir + "\" && ninja";
        int result = system(ninjaCmd.c_str());
        
        return result == 0;
    }
}

// ============================================================================
// Batch 3: CI/CD Pipeline Integration
// ============================================================================
namespace CIIntegration {
    
    bool RunPipelineOrchestrator() {
        std::string cmd = std::string(CLIPaths::CI_TOOLS) + "\\pipeline_orchestrator.exe";
        
        if (!std::filesystem::exists(cmd)) {
            return false;
        }
        
        int result = system(cmd.c_str());
        return result == 0;
    }
    
    struct PipelineStage {
        std::string name;
        std::vector<std::string> commands;
        bool allowFailure;
    };
    
    bool RunCustomPipeline(const std::vector<PipelineStage>& stages, 
                          std::function<void(const std::string&)> progressCallback) {
        for (const auto& stage : stages) {
            progressCallback("Starting stage: " + stage.name);
            
            for (const auto& cmd : stage.commands) {
                int result = system(cmd.c_str());
                if (result != 0 && !stage.allowFailure) {
                    progressCallback("Stage failed: " + stage.name);
                    return false;
                }
            }
            
            progressCallback("Stage complete: " + stage.name);
        }
        
        return true;
    }
}

// ============================================================================
// Batch 4: Model Management Integration
// ============================================================================
namespace ModelIntegration {
    
    struct ModelInfo {
        std::string name;
        std::string path;
        size_t size;
        std::string architecture;
    };
    
    std::vector<ModelInfo> ScanModelsDirectory(const std::string& modelsDir) {
        std::vector<ModelInfo> models;
        
        if (!std::filesystem::exists(modelsDir)) {
            return models;
        }
        
        for (const auto& entry : std::filesystem::directory_iterator(modelsDir)) {
            if (entry.path().extension() == ".gguf") {
                ModelInfo info;
                info.name = entry.path().filename().string();
                info.path = entry.path().string();
                info.size = entry.file_size();
                models.push_back(info);
            }
        }
        
        return models;
    }
    
    bool LoadModelWithGGUFLoader(const std::string& modelPath) {
        // Call the real GGUF loader
        typedef bool (*LoadModelFunc)(const char*);
        HMODULE hMod = LoadLibraryA("rawrxd_gguf_loader.dll");
        if (!hMod) return false;
        
        LoadModelFunc loadModel = (LoadModelFunc)GetProcAddress(hMod, "Win32IDE_LoadGGUFModel");
        if (!loadModel) {
            FreeLibrary(hMod);
            return false;
        }
        
        bool result = loadModel(modelPath.c_str());
        FreeLibrary(hMod);
        return result;
    }
}

// ============================================================================
// Batch 5: Inhouse Tools Integration
// ============================================================================
namespace InhouseToolsIntegration {
    
    bool RunCompiler(const std::string& sourceFile, const std::string& outputFile) {
        std::string cmd = std::string(CLIPaths::INHOUSE_TOOLS) + "\\rawrxd_compiler.exe /DIRECT \"" + 
                         sourceFile + "\" /OUT:\"" + outputFile + "\"";
        int result = system(cmd.c_str());
        return result == 0;
    }
    
    bool RunLinker(const std::vector<std::string>& objFiles, const std::string& outputExe) {
        std::string cmd = std::string(CLIPaths::INHOUSE_TOOLS) + "\\rawrxd_linker.exe";
        for (const auto& obj : objFiles) {
            cmd += " \"" + obj + "\"";
        }
        cmd += " /OUT:\"" + outputExe + "\"";
        int result = system(cmd.c_str());
        return result == 0;
    }
    
    bool RunCOFFDump(const std::string& objFile, std::string& output) {
        std::string cmd = std::string(CLIPaths::INHOUSE_TOOLS) + "\\rawrxd_coffdump.exe --in \"" + objFile + "\"";
        
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return false;
        
        char buffer[4096];
        output.clear();
        while (fgets(buffer, sizeof(buffer), pipe)) {
            output += buffer;
        }
        
        int result = _pclose(pipe);
        return result == 0;
    }
}

// ============================================================================
// Batch 6-10: Additional integrations (placeholders for next batches)
// ============================================================================
namespace AdditionalIntegrations {
    // Batch 6: LSP Tools
    // Batch 7: Debug Tools  
    // Batch 8: Profiling Tools
    // Batch 9: Testing Tools
    // Batch 10: Deployment Tools
}

// ============================================================================
// Win32IDE Integration Methods
// ============================================================================

void Win32IDE::InitializeCLIIntegration() {
    LogMessage("Initializing CLI integration...");
    
    // Verify CLI tools exist
    int availableTools = 0;
    for (const auto& comp : CompilerIntegration::g_compilers) {
        if (CompilerIntegration::IsCompilerAvailable(comp.exePath)) {
            availableTools++;
        }
    }
    
    LogMessage("CLI Integration: " + std::to_string(availableTools) + "/" + 
               std::to_string(CompilerIntegration::g_compilers.size()) + " compilers available");
}

void Win32IDE::CompileCurrentFileWithCLI() {
    if (m_currentFile.empty()) {
        ShowError("No file open to compile");
        return;
    }
    
    std::string outputFile = std::filesystem::path(m_currentFile).replace_extension(".exe").string();
    
    appendToOutput("Compiling: " + m_currentFile + "\n", "Build", OutputSeverity::Info);
    
    auto result = CompilerIntegration::ExecuteCompiler(m_currentFile, outputFile);
    
    if (result.success) {
        appendToOutput("Compilation successful!\nOutput: " + outputFile + "\n", "Build", OutputSeverity::Info);
        SetStatusBarText("Compilation successful");
    } else {
        appendToOutput("Compilation failed:\n" + result.error + "\n" + result.output + "\n", 
                      "Build", OutputSeverity::Error);
        SetStatusBarText("Compilation failed");
    }
}

void Win32IDE::BuildProjectWithCLI() {
    if (m_projectRoot.empty()) {
        ShowError("No project open");
        return;
    }
    
    appendToOutput("Building project: " + m_projectRoot + "\n", "Build", OutputSeverity::Info);
    
    bool success = BuildSystemIntegration::RunCMakeBuild(m_projectRoot, "Release", false);
    
    if (success) {
        appendToOutput("Build successful!\n", "Build", OutputSeverity::Info);
        SetStatusBarText("Build successful");
    } else {
        appendToOutput("Build failed\n", "Build", OutputSeverity::Error);
        SetStatusBarText("Build failed");
    }
}

void Win32IDE::RunCIPipeline() {
    appendToOutput("Running CI pipeline...\n", "CI", OutputSeverity::Info);
    
    bool success = CIIntegration::RunPipelineOrchestrator();
    
    if (success) {
        appendToOutput("CI pipeline completed successfully\n", "CI", OutputSeverity::Info);
    } else {
        appendToOutput("CI pipeline failed or not available\n", "CI", OutputSeverity::Warning);
    }
}

void Win32IDE::ScanModelsWithCLI() {
    std::string modelsDir = "d:\\rawrxd\\models";
    auto models = ModelIntegration::ScanModelsDirectory(modelsDir);
    
    appendToOutput("Found " + std::to_string(models.size()) + " models:\n", "Models", OutputSeverity::Info);
    for (const auto& model : models) {
        appendToOutput("  - " + model.name + " (" + std::to_string(model.size / 1024 / 1024) + " MB)\n", 
                      "Models", OutputSeverity::Info);
    }
}

void Win32IDE::LoadModelWithCLI(const std::string& modelPath) {
    appendToOutput("Loading model: " + modelPath + "\n", "Models", OutputSeverity::Info);
    
    bool success = ModelIntegration::LoadModelWithGGUFLoader(modelPath);
    
    if (success) {
        appendToOutput("Model loaded successfully\n", "Models", OutputSeverity::Info);
        SetStatusBarText("Model loaded: " + std::filesystem::path(modelPath).filename().string());
    } else {
        appendToOutput("Failed to load model\n", "Models", OutputSeverity::Error);
        ShowError("Failed to load model: " + modelPath);
    }
}

// ============================================================================
// Command Handler Integration
// ============================================================================

void Win32IDE::handleCLICommand(int commandId) {
    switch (commandId) {
        case IDM_BUILD_COMPILE:
            CompileCurrentFileWithCLI();
            break;
            
        case IDM_BUILD_SOLUTION:
            BuildProjectWithCLI();
            break;
            
        case IDM_BUILD_CLEAN:
            if (!m_projectRoot.empty()) {
                BuildSystemIntegration::RunCMakeBuild(m_projectRoot, "Release", true);
                appendToOutput("Project cleaned\n", "Build", OutputSeverity::Info);
            }
            break;
            
        case IDM_BUILD_REBUILD:
            if (!m_projectRoot.empty()) {
                BuildSystemIntegration::RunCMakeBuild(m_projectRoot, "Release", true);
                BuildProjectWithCLI();
            }
            break;
            
        case IDM_FILE_LOAD_MODEL:
            // Open file dialog for model
            {
                char filePath[MAX_PATH] = {0};
                OPENFILENAMEA ofn = {0};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = m_hwndMain;
                ofn.lpstrFilter = "GGUF Models (*.gguf)\0*.gguf\0All Files (*.*)\0*.*\0";
                ofn.lpstrFile = filePath;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_FILEMUSTEXIST;
                
                if (GetOpenFileNameA(&ofn)) {
                    LoadModelWithCLI(filePath);
                }
            }
            break;
            
        case IDM_REFRESH_MODELS:
            ScanModelsWithCLI();
            break;
            
        default:
            // Check for compiler-specific commands
            if (commandId >= 50000 && commandId < 50100) {
                int compilerIndex = commandId - 50000;
                if (compilerIndex < (int)CompilerIntegration::g_compilers.size()) {
                    // Set preferred compiler
                    appendToOutput("Selected compiler: " + CompilerIntegration::g_compilers[compilerIndex].name + "\n",
                                  "Build", OutputSeverity::Info);
                }
            }
            break;
    }
}

// ============================================================================
// Menu Integration
// ============================================================================

void Win32IDE::BuildCLIMenu(HMENU hMenu) {
    // Add Compiler submenu to Build menu
    HMENU hCompilerMenu = CreatePopupMenu();
    
    int cmdId = 50000;
    for (const auto& comp : CompilerIntegration::g_compilers) {
        std::string itemName = comp.name;
        if (CompilerIntegration::IsCompilerAvailable(comp.exePath)) {
            itemName += " \u2713"; // Checkmark
        }
        AppendMenuA(hCompilerMenu, MF_STRING, cmdId++, itemName.c_str());
    }
    
    AppendMenuA(hCompilerMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hCompilerMenu, MF_STRING, 50100, "Detect Compilers");
    
    // Find Build menu and insert Compiler submenu
    int menuCount = GetMenuItemCount(hMenu);
    for (int i = 0; i < menuCount; i++) {
        char buf[256];
        if (GetMenuStringA(hMenu, i, buf, sizeof(buf), MF_BYPOSITION)) {
            if (strstr(buf, "Build") || strstr(buf, "&Build")) {
                HMENU hBuildMenu = GetSubMenu(hMenu, i);
                if (hBuildMenu) {
                    AppendMenuA(hBuildMenu, MF_SEPARATOR, 0, nullptr);
                    AppendMenuA(hBuildMenu, MF_POPUP, (UINT_PTR)hCompilerMenu, "&Compiler");
                }
                break;
            }
        }
    }
}

// ============================================================================
// C API for external integration
// ============================================================================

extern "C" {

__declspec(dllexport) void Win32IDE_InitCLIIntegration(HWND hwnd) {
    Win32IDE* ide = Win32IDE::GetInstance();
    if (ide) {
        ide->InitializeCLIIntegration();
    }
}

__declspec(dllexport) void Win32IDE_CompileWithCLI(HWND hwnd) {
    Win32IDE* ide = Win32IDE::GetInstance();
    if (ide) {
        ide->CompileCurrentFileWithCLI();
    }
}

__declspec(dllexport) void Win32IDE_BuildWithCLI(HWND hwnd) {
    Win32IDE* ide = Win32IDE::GetInstance();
    if (ide) {
        ide->BuildProjectWithCLI();
    }
}

__declspec(dllexport) void Win32IDE_RunCIPipeline(HWND hwnd) {
    Win32IDE* ide = Win32IDE::GetInstance();
    if (ide) {
        ide->RunCIPipeline();
    }
}

} // extern "C"

// ============================================================================
// Implementation functions for Win32IDE_Commands.cpp integration
// ============================================================================

void Win32IDE_CompileCurrentFileWithCLI_Impl(Win32IDE* ide) {
    if (!ide) return;
    ide->CompileCurrentFileWithCLI();
}

void Win32IDE_BuildProjectWithCLI_Impl(Win32IDE* ide) {
    if (!ide) return;
    ide->BuildProjectWithCLI();
}

void Win32IDE_RunCIPipeline_Impl(Win32IDE* ide) {
    if (!ide) return;
    ide->RunCIPipeline();
}
