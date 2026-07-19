#pragma once
#include <cstring>
#include <vector>
#include <string>

namespace IDE {

class CompilerPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static const char* Id();
    static const char* GetPanelName();
    
    // Compiler operations
    static void CompileFile(const char* filePath);
    static void BuildProject();
    static void CleanBuild();
    static void RunExecutable(const char* exePath);
    
    // Output management
    static void ClearOutput();
    static void AppendOutput(const char* text);
    static void AppendOutputFmt(const char* fmt, ...);
    
private:
    static void RenderToolbar();
    static void RenderFileBrowser();
    static void RenderOutput();
    static void RenderBuildConfig();
    
    static bool s_visible;
    static bool s_initialized;
    static bool s_compiling;
    static float s_compileProgress;
    
    static char s_selectedFile[512];
    static char s_outputPath[512];
    static char s_outputBuffer[65536];
    static int s_outputBufferPos;
    
    static bool s_optimize;
    static bool s_debug;
    static bool s_verbose;
    static int s_selectedLanguage;
    
    static std::vector<std::string> s_recentFiles;
    static std::vector<std::string> s_buildErrors;
};

} // namespace IDE
