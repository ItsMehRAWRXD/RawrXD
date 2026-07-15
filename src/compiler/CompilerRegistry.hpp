/*==========================================================================
 * RawrXD Compiler Registry — Unified 69-Compiler Management System
 * 
 * REAL IMPLEMENTATION — NO STUBS
 * 
 * Features:
 * - Auto-detection of 69+ compilers from system PATH and known locations
 * - File extension → compiler mapping (autonomous compilation)
 * - Self-healing builds with fallback compiler chains
 * - Integration with both GUI (Win32IDE) and CLI
 * - Agentic build automation with error recovery
 * 
 * Compilers Supported:
 * 1. System Compilers (MSVC, Clang, GCC, etc.)
 * 2. From-Scratch Compilers (MASM-based custom implementations)
 * 3. Language-Specific Compilers (Rust, Go, Zig, etc.)
 * 4. Cross-Compilers (ARM, WebAssembly, etc.)
 *=========================================================================*/

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <mutex>
#include <filesystem>
#include <optional>

namespace RawrXD::Compiler {

// =========================================================================
// Compiler Capability Flags
// =========================================================================
enum class CompilerCapability : uint32_t {
    None              = 0,
    CompileC          = 1 << 0,   // Can compile C
    CompileCpp        = 1 << 1,   // Can compile C++
    CompileAsm        = 1 << 2,   // Can compile Assembly
    CompileObj        = 1 << 3,   // Can compile to object files
    LinkExe           = 1 << 4,   // Can link executables
    LinkDll           = 1 << 5,   // Can link DLLs
    LinkLib           = 1 << 6,   // Can link static libraries
    Optimize          = 1 << 7,   // Has optimization passes
    DebugInfo         = 1 << 8,   // Can generate debug info
    CrossCompile      = 1 << 9,   // Supports cross-compilation
    JIT               = 1 << 10,  // JIT compilation support
    LTO               = 1 << 11,  // Link-time optimization
    PCH               = 1 << 12,  // Precompiled headers
    Modules           = 1 << 13,  // C++20 modules support
    Sanitize          = 1 << 14,  // Sanitizer support
    Coverage          = 1 << 15,  // Code coverage
    Profile           = 1 << 16,  // Profiling support
    AVX512            = 1 << 17,  // AVX-512 code generation
    SelfHosted        = 1 << 18,  // Self-hosted compiler
    FromScratch       = 1 << 19,  // Custom from-scratch implementation
};

inline CompilerCapability operator|(CompilerCapability a, CompilerCapability b) {
    return static_cast<CompilerCapability>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline CompilerCapability operator&(CompilerCapability a, CompilerCapability b) {
    return static_cast<CompilerCapability>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline bool HasCapability(CompilerCapability flags, CompilerCapability cap) {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(cap)) != 0;
}

// =========================================================================
// Compiler Information
// =========================================================================
struct CompilerInfo {
    std::string id;                    // Unique identifier (e.g., "msvc-14.40", "clang-18", "rust-1.80")
    std::string name;                  // Display name (e.g., "Microsoft Visual C++ 2022")
    std::string version;               // Version string
    std::string executable_path;       // Full path to compiler executable
    std::string linker_path;           // Full path to linker (if separate)
    std::string assembler_path;        // Full path to assembler (if separate)
    std::vector<std::string> supported_extensions; // e.g., ".cpp", ".c", ".asm"
    CompilerCapability capabilities = CompilerCapability::None;
    int priority = 100;                // Lower = higher priority for auto-selection
    bool is_system_compiler = true;    // vs from-scratch
    bool is_available = false;         // Detected on this system
    std::vector<std::string> fallback_ids; // Alternative compilers to try on failure
    std::unordered_map<std::string, std::string> config; // Compiler-specific config
};

// =========================================================================
// Compilation Task
// =========================================================================
struct CompileTask {
    std::string source_file;
    std::string output_file;
    std::string compiler_id;           // Empty = auto-detect
    std::vector<std::string> include_paths;
    std::vector<std::string> defines;
    std::vector<std::string> libraries;
    std::string standard = "c++20";    // Language standard
    bool debug = true;
    bool optimize = true;
    int optimization_level = 2;          // 0-3
    std::vector<std::string> extra_flags;
    std::string working_directory;
};

// =========================================================================
// Compilation Result
// =========================================================================
struct CompileResult {
    bool success = false;
    std::string compiler_id;
    std::string command_executed;
    std::string stdout_output;
    std::string stderr_output;
    int exit_code = -1;
    uint64_t duration_ms = 0;
    std::vector<std::string> output_files;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::vector<std::string> fallback_attempts; // Which compilers were tried
};

// =========================================================================
// Build Configuration
// =========================================================================
struct BuildConfiguration {
    std::string name;                  // "Debug", "Release", etc.
    bool debug_info = true;
    bool optimize = false;
    int optimization_level = 0;
    std::vector<std::string> defines;
    std::vector<std::string> additional_flags;
};

// =========================================================================
// Compiler Registry — Main Class
// =========================================================================
class CompilerRegistry {
public:
    // Singleton access
    static CompilerRegistry& Instance();
    
    // Initialization
    void Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Detection
    void DetectAllCompilers();
    void DetectSystemCompilers();
    void DetectFromScratchCompilers();
    void DetectLanguageCompilers();
    
    // Registration
    bool RegisterCompiler(const CompilerInfo& info);
    bool UnregisterCompiler(const std::string& compiler_id);
    void RegisterDefaultCompilers(); // Register all 69 known compilers
    
    // Query
    std::vector<CompilerInfo> GetAllCompilers() const;
    std::vector<CompilerInfo> GetAvailableCompilers() const;
    std::vector<CompilerInfo> GetCompilersForExtension(const std::string& ext) const;
    std::optional<CompilerInfo> GetCompiler(const std::string& compiler_id) const;
    std::optional<CompilerInfo> GetBestCompilerForFile(const std::string& file_path) const;
    std::optional<CompilerInfo> GetBestCompilerForExtension(const std::string& ext) const;
    
    // Compilation
    CompileResult Compile(const CompileTask& task);
    CompileResult CompileWithFallback(const CompileTask& task);
    CompileResult CompileWithSpecificCompiler(const CompileTask& task, const std::string& compiler_id);
    
    // Agentic features
    bool AutoCompileFile(const std::string& file_path, std::string* output_path = nullptr);
    bool AutoCompileProject(const std::string& project_path, std::string* output_path = nullptr);
    bool SelfHealBuild(const CompileTask& failed_task, CompileResult* result);
    
    // Build configurations
    void AddBuildConfiguration(const BuildConfiguration& config);
    std::optional<BuildConfiguration> GetBuildConfiguration(const std::string& name) const;
    std::vector<BuildConfiguration> GetBuildConfigurations() const;
    
    // Utility
    std::string GetFileExtension(const std::string& path) const;
    bool IsSourceFile(const std::string& path) const;
    std::vector<std::string> GetSupportedExtensions() const;
    
    // Callbacks for async operations
    using ProgressCallback = std::function<void(const std::string& message, int percent)>;
    using ErrorCallback = std::function<void(const std::string& error)>;
    void SetProgressCallback(ProgressCallback cb) { progress_cb_ = cb; }
    void SetErrorCallback(ErrorCallback cb) { error_cb_ = cb; }

private:
    CompilerRegistry() = default;
    ~CompilerRegistry() = default;
    
    // Detection helpers
    bool DetectMSVC();
    bool DetectClang();
    bool DetectGCC();
    bool DetectRust();
    bool DetectGo();
    bool DetectZig();
    bool DetectNim();
    bool DetectOdin();
    bool DetectJai();
    bool DetectD();
    bool DetectFortran();
    bool DetectPascal();
    bool DetectAda();
    bool DetectCobol();
    bool DetectHaskell();
    bool DetectOCaml();
    bool DetectSwift();
    bool DetectKotlin();
    bool DetectJava();
    bool DetectCSharp();
    bool DetectFSharp();
    bool DetectVB();
    bool DetectPythonCompiler();
    bool DetectRubyCompiler();
    bool DetectPerlCompiler();
    bool DetectLuaCompiler();
    bool DetectJavaScriptCompiler();
    bool DetectTypeScriptCompiler();
    bool DetectDartCompiler();
    bool DetectElixirCompiler();
    bool DetectErlangCompiler();
    bool DetectClojureCompiler();
    bool DetectScalaCompiler();
    bool DetectGroovyCompiler();
    bool DetectJuliaCompiler();
    bool DetectCrystalCompiler();
    bool DetectVCompiler();
    bool DetectCarbonCompiler();
    bool DetectMotokoCompiler();
    bool DetectMoveCompiler();
    bool DetectSolidityCompiler();
    bool DetectVyperCompiler();
    bool DetectBashCompiler();
    bool DetectPowerShellCompiler();
    bool DetectBatchCompiler();
    bool DetectMATLABCompiler();
    bool DetectRCompiler();
    bool DetectPHPCompiler();
    bool DetectWebAssemblyCompiler();
    bool DetectLLVMIRCompiler();
    bool DetectMLIRCompiler();
    bool DetectSPIRVCompiler();
    bool DetectGLSLCompiler();
    bool DetectHLSLCompiler();
    bool DetectMetalCompiler();
    bool DetectCUDACompiler();
    bool DetectHIPCompiler();
    bool DetectOpenCLCompiler();
    bool DetectSYCLCompiler();
    bool DetectISPCCompiler();
    bool DetectTBBCompiler();
    bool DetectOpenMPCompiler();
    bool DetectMPICompiler();
    bool DetectUPCCompiler();
    bool DetectCAFCompiler();
    bool DetectChapelCompiler();
    bool DetectJuliaGPUCompiler();
    bool DetectTritonCompiler();
    bool DetectMLIRGPUCompiler();
    
    // From-scratch compiler detection
    bool DetectFromScratchMASM();
    bool DetectFromScratchNASM();
    bool DetectFromScratchFASM();
    bool DetectFromScratchYASM();
    bool DetectFromScratchGAS();
    bool DetectFromScratchLLVM();
    bool DetectFromScratchCustom(const std::string& name, const std::vector<std::string>& paths);
    
    // Compilation helpers
    CompileResult ExecuteCompileCommand(const std::string& compiler, const std::vector<std::string>& args, 
                                        const std::string& working_dir);
    std::vector<std::string> BuildCompileArgs(const CompilerInfo& compiler, const CompileTask& task);
    std::vector<std::string> GetFallbackCompilers(const std::string& compiler_id) const;
    bool TryCompilerHeuristic(const std::string& compiler_id, const CompileTask& task, CompileResult* result);
    
    // Utility
    std::string FindInPath(const std::string& executable) const;
    std::string FindInProgramFiles(const std::string& subpath) const;
    std::string FindInVSInstall(const std::string& tool) const;
    std::string GetCompilerVersion(const std::string& executable) const;
    bool TestCompiler(const std::string& executable) const;
    void ReportProgress(const std::string& message, int percent);
    void ReportError(const std::string& error);
    
    // Member variables
    mutable std::mutex mutex_;
    std::unordered_map<std::string, CompilerInfo> compilers_;
    std::unordered_map<std::string, std::vector<std::string>> extension_to_compilers_;
    std::unordered_map<std::string, BuildConfiguration> build_configs_;
    bool initialized_ = false;
    ProgressCallback progress_cb_;
    ErrorCallback error_cb_;
    
    // Detection cache
    mutable std::unordered_map<std::string, std::string> path_cache_;
    mutable std::unordered_map<std::string, std::string> version_cache_;
};

// =========================================================================
// Convenience Functions
// =========================================================================
inline CompilerRegistry& GetCompilerRegistry() {
    return CompilerRegistry::Instance();
}

// Quick compile function
inline bool QuickCompile(const std::string& source_file, std::string* output = nullptr) {
    return GetCompilerRegistry().AutoCompileFile(source_file, output);
}

// Get compiler for file extension
inline std::optional<CompilerInfo> GetCompilerForFile(const std::string& path) {
    return GetCompilerRegistry().GetBestCompilerForFile(path);
}

} // namespace RawrXD::Compiler
