#include "ide/CompilerPanel.hpp"
#include "ide/PanelState.hpp"
#include "ide/FileDialog.hpp"
#include "ide/EditorPanel.hpp"
#include "ide/common/compiler_integration.h"
#include <imgui.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace IDE {

namespace IDE {

// Static member definitions
bool CompilerPanel::s_visible = false;
bool CompilerPanel::s_initialized = false;
bool CompilerPanel::s_compiling = false;
float CompilerPanel::s_compileProgress = 0.0f;

char CompilerPanel::s_selectedFile[512] = {};
char CompilerPanel::s_outputPath[512] = {};
char CompilerPanel::s_outputBuffer[65536] = {};
int CompilerPanel::s_outputBufferPos = 0;

bool CompilerPanel::s_optimize = true;
bool CompilerPanel::s_debug = false;
bool CompilerPanel::s_verbose = false;
int CompilerPanel::s_selectedLanguage = 0;

std::vector<std::string> CompilerPanel::s_recentFiles;
std::vector<std::string> CompilerPanel::s_buildErrors;

const char* CompilerPanel::Id() { return "CompilerPanel"; }
void CompilerPanel::Toggle() { PanelState::Toggle(Id()); }
bool CompilerPanel::IsVisible() { return PanelState::Visible(Id()); }
const char* CompilerPanel::GetPanelName() { return "Compiler"; }

void CompilerPanel::Init() {
    if (s_initialized) return;
    
    // Initialize compiler integration
    if (!RawrxdCompiler_Init()) {
        AppendOutput("[ERROR] Failed to initialize compiler integration\n");
        AppendOutput("        Ensure rawrxd-compiler.exe is available\n");
    } else {
        AppendOutput("[INFO] Compiler integration initialized\n");
        AppendOutput("       Version: ");
        AppendOutput(RawrxdCompiler_GetVersion());
        AppendOutput("\n");
    }
    
    s_initialized = true;
}

void CompilerPanel::Shutdown() {
    if (!s_initialized) return;
    RawrxdCompiler_Shutdown();
    s_initialized = false;
}

void CompilerPanel::ClearOutput() {
    s_outputBuffer[0] = '\0';
    s_outputBufferPos = 0;
    s_buildErrors.clear();
}

void CompilerPanel::AppendOutput(const char* text) {
    size_t len = strlen(text);
    if (s_outputBufferPos + len >= sizeof(s_outputBuffer) - 1) {
        // Buffer full, scroll up
        memmove(s_outputBuffer, s_outputBuffer + len, s_outputBufferPos - len);
        s_outputBufferPos -= len;
    }
    memcpy(s_outputBuffer + s_outputBufferPos, text, len);
    s_outputBufferPos += len;
    s_outputBuffer[s_outputBufferPos] = '\0';
}

void CompilerPanel::AppendOutputFmt(const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    AppendOutput(buf);
}

void CompilerPanel::Render() {
    if (!PanelState::Visible(Id())) return;
    
    ImGui::Begin("Compiler", nullptr, ImGuiWindowFlags_MenuBar);
    
    RenderToolbar();
    ImGui::Separator();
    
    RenderFileBrowser();
    ImGui::Separator();
    
    RenderBuildConfig();
    ImGui::Separator();
    
    RenderOutput();
    
    ImGui::End();
}

void CompilerPanel::RenderToolbar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open Source...", "Ctrl+O")) {
                std::string selected = FileDialog::OpenFile("Open Source File", FileDialog::GetDefaultFilters());
                if (!selected.empty()) {
                    strncpy(s_selectedFile, selected.c_str(), sizeof(s_selectedFile) - 1);
                    s_recentFiles.push_back(selected);
                    // Auto-generate output path
                    strncpy(s_outputPath, selected.c_str(), sizeof(s_outputPath) - 1);
                    // Change extension to .exe
                    char* dot = strrchr(s_outputPath, '.');
                    if (dot) {
                        strcpy(dot, ".exe");
                    } else {
                        strcat(s_outputPath, ".exe");
                    }
                }
            }
            if (ImGui::MenuItem("Clear Output")) {
                ClearOutput();
            }
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Build")) {
            if (ImGui::MenuItem("Compile Current File", "F7", false, !s_compiling)) {
                // Get current file from editor
                const char* editorFile = EditorPanel::GetCurrentFilePath();
                if (editorFile && editorFile[0]) {
                    strncpy(s_selectedFile, editorFile, sizeof(s_selectedFile) - 1);
                    // Auto-generate output path
                    strncpy(s_outputPath, editorFile, sizeof(s_outputPath) - 1);
                    char* dot = strrchr(s_outputPath, '.');
                    if (dot) {
                        strcpy(dot, ".exe");
                    } else {
                        strcat(s_outputPath, ".exe");
                    }
                    CompileFile(s_selectedFile);
                } else if (s_selectedFile[0]) {
                    CompileFile(s_selectedFile);
                } else {
                    AppendOutput("[ERROR] No file selected. Open a file in the editor first.\n");
                }
            }
            if (ImGui::MenuItem("Build Project", "Ctrl+Shift+B", false, !s_compiling)) {
                BuildProject();
            }
            if (ImGui::MenuItem("Clean", false, false, !s_compiling)) {
                CleanBuild();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Run", "Ctrl+F5", false, s_outputPath[0] != '\0')) {
                RunExecutable(s_outputPath);
            }
            ImGui::EndMenu();
        }
        
        ImGui::EndMenuBar();
    }
    
    // Toolbar buttons
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 4));
    
    if (ImGui::Button("Compile", ImVec2(80, 0))) {
        // Try editor's current file first
        const char* editorFile = EditorPanel::GetCurrentFilePath();
        if (editorFile && editorFile[0]) {
            strncpy(s_selectedFile, editorFile, sizeof(s_selectedFile) - 1);
            // Auto-generate output path
            strncpy(s_outputPath, editorFile, sizeof(s_outputPath) - 1);
            char* dot = strrchr(s_outputPath, '.');
            if (dot) {
                strcpy(dot, ".exe");
            } else {
                strcat(s_outputPath, ".exe");
            }
            CompileFile(s_selectedFile);
        } else if (s_selectedFile[0]) {
            CompileFile(s_selectedFile);
        } else {
            AppendOutput("[ERROR] No file selected. Open a file in the editor first.\n");
        }
    }
    ImGui::SameLine();
    
    if (ImGui::Button("Build", ImVec2(80, 0))) {
        BuildProject();
    }
    ImGui::SameLine();
    
    if (ImGui::Button("Clean", ImVec2(80, 0))) {
        CleanBuild();
    }
    ImGui::SameLine();
    
    bool canRun = (s_outputPath[0] != '\0');
    if (!canRun) ImGui::BeginDisabled();
    if (ImGui::Button("Run", ImVec2(80, 0))) {
        RunExecutable(s_outputPath);
    }
    if (!canRun) ImGui::EndDisabled();
    
    ImGui::PopStyleVar();
}

void CompilerPanel::RenderFileBrowser() {
    ImGui::Text("Source File:");
    ImGui::InputText("##Source", s_selectedFile, sizeof(s_selectedFile));
    ImGui::SameLine();
    if (ImGui::Button("Browse...")) {
        std::string selected = FileDialog::OpenFile("Select Source File", FileDialog::GetDefaultFilters());
        if (!selected.empty()) {
            strncpy(s_selectedFile, selected.c_str(), sizeof(s_selectedFile) - 1);
            s_recentFiles.push_back(selected);
            // Auto-generate output path
            strncpy(s_outputPath, selected.c_str(), sizeof(s_outputPath) - 1);
            char* dot = strrchr(s_outputPath, '.');
            if (dot) {
                strcpy(dot, ".exe");
            } else {
                strcat(s_outputPath, ".exe");
            }
        }
    }
    
    // Recent files
    if (!s_recentFiles.empty()) {
        ImGui::Text("Recent:");
        for (const auto& file : s_recentFiles) {
            ImGui::BulletText("%s", file.c_str());
            if (ImGui::IsItemClicked()) {
                strncpy(s_selectedFile, file.c_str(), sizeof(s_selectedFile) - 1);
            }
        }
    }
}

void CompilerPanel::RenderBuildConfig() {
    ImGui::Text("Build Configuration:");
    ImGui::Checkbox("Optimize", &s_optimize);
    ImGui::SameLine();
    ImGui::Checkbox("Debug Info", &s_debug);
    ImGui::SameLine();
    ImGui::Checkbox("Verbose", &s_verbose);
    
    const char* languages[] = { "Auto-detect", "C", "Assembly", "C#" };
    ImGui::Combo("Language", &s_selectedLanguage, languages, IM_ARRAYSIZE(languages));
    
    if (s_compiling) {
        ImGui::ProgressBar(s_compileProgress, ImVec2(-1, 0), "Compiling...");
    }
}

void CompilerPanel::RenderOutput() {
    ImGui::Text("Output:");
    
    ImVec2 available = ImGui::GetContentRegionAvail();
    ImGui::InputTextMultiline("##Output", s_outputBuffer, sizeof(s_outputBuffer),
                               ImVec2(available.x, available.y - 30),
                               ImGuiInputTextFlags_ReadOnly);
    
    // Auto-scroll
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
        ImGui::SetScrollHereY(1.0f);
    }
}

void CompilerPanel::CompileFile(const char* filePath) {
    if (!filePath || !filePath[0]) return;
    
    s_compiling = true;
    s_compileProgress = 0.0f;
    
    AppendOutputFmt("\n[INFO] Compiling: %s\n", filePath);
    
    // Detect language
    RawrxdLanguage lang = RawrxdCompiler_DetectLanguage(filePath);
    AppendOutputFmt("[INFO] Detected language: %s\n", RawrxdCompiler_LanguageName(lang));
    
    // Build config
    RawrxdBuildConfig config;
    RawrxdCompiler_GetDefaultConfig(&config, nullptr);
    config.optimize = s_optimize;
    config.debug = s_debug;
    config.verbose = s_verbose;
    
    // Compile
    RawrxdCompileResult result = RawrxdCompiler_Compile(filePath, &config);
    
    s_compileProgress = 1.0f;
    
    if (result.success) {
        AppendOutputFmt("[SUCCESS] Compilation successful!\n");
        AppendOutputFmt("          Output: %s\n", result.outputPath);
        AppendOutputFmt("          Time: %.2f ms\n", result.compileTimeMs);
        strncpy(s_outputPath, result.outputPath, sizeof(s_outputPath) - 1);
        
        // Add to recent files
        s_recentFiles.push_back(filePath);
        if (s_recentFiles.size() > 10) {
            s_recentFiles.erase(s_recentFiles.begin());
        }
    } else {
        AppendOutputFmt("[ERROR] Compilation failed!\n");
        AppendOutputFmt("        Exit code: %d\n", result.exitCode);
        if (result.error[0]) {
            AppendOutputFmt("        %s\n", result.error);
        }
        if (result.output[0]) {
            AppendOutput("\n--- Compiler Output ---\n");
            AppendOutput(result.output);
        }
    }
    
    s_compiling = false;
}

void CompilerPanel::BuildProject() {
    AppendOutput("\n[INFO] Building project...\n");
    // TODO: Multi-file build
    AppendOutput("[INFO] Project build not yet implemented\n");
}

void CompilerPanel::CleanBuild() {
    AppendOutput("\n[INFO] Cleaning build artifacts...\n");
    
    // Clear output buffer
    ClearOutput();
    
    // Reset output path
    s_outputPath[0] = '\0';
    
    // Clear build errors
    s_buildErrors.clear();
    
    // Try to delete the output file if it exists
    if (s_outputPath[0]) {
        if (DeleteFileA(s_outputPath)) {
            AppendOutputFmt("[INFO] Deleted: %s\n", s_outputPath);
        }
    }
    
    // Clear selected file if we want a full clean
    // s_selectedFile[0] = '\0'; // Keep the source file selected
    
    AppendOutput("[INFO] Clean complete\n");
}

void CompilerPanel::RunExecutable(const char* exePath) {
    if (!exePath || !exePath[0]) return;
    
    AppendOutputFmt("\n[INFO] Running: %s\n", exePath);
    
    // Simple ShellExecute
    #ifdef _WIN32
    ShellExecuteA(nullptr, "open", exePath, nullptr, nullptr, SW_SHOW);
    #endif
    
    AppendOutput("[INFO] Launched executable\n");
}

} // namespace IDE

