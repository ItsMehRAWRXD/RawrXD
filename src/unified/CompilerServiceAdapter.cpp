#include "CompilerServiceAdapter.h"
#include <iostream>
#include <filesystem>

namespace RawrXD {
namespace Unified {

CompilerServiceAdapter::CompilerServiceAdapter() = default;

CompilerServiceAdapter::~CompilerServiceAdapter() = default;

bool CompilerServiceAdapter::Initialize() {
    // Initialize context engine
    contextEngine_.IndexProject(std::filesystem::current_path().string());
    
    initialized_ = true;
    std::cout << "CompilerServiceAdapter: Initialized" << std::endl;
    return true;
}

bool CompilerServiceAdapter::InitializeWithAI(AIProvider* ai) {
    aiProvider_ = ai;
    
    // Create compiler agent with AI
    if (ai) {
        compilerAgent_ = std::make_unique<CompilerAgent>(ai, &contextEngine_);
    }
    
    return Initialize();
}

std::string CompilerServiceAdapter::GetCompilerForLanguage(const std::string& language) {
    static const std::unordered_map<std::string, std::string> compilerMap = {
        {"c", "cl.exe"},
        {"cpp", "cl.exe"},
        {"cxx", "cl.exe"},
        {"cc", "cl.exe"},
        {"asm", "ml64.exe"},
        {"rust", "rustc.exe"},
        {"go", "go.exe"},
        {"zig", "zig.exe"},
        {"nim", "nim.exe"},
        {"d", "dmd.exe"},
        {"fortran", "ifx.exe"},
        {"cuda", "nvcc.exe"},
        {"hip", "hipcc.exe"},
        {"opencl", "cl.exe"},
        {"metal", "xcrun metal"},
        {"spirv", "spirv-as.exe"},
        {"wasm", "clang.exe"},
        {"javascript", "node.exe"},
        {"typescript", "tsc.exe"},
        {"python", "python.exe"},
        {"java", "javac.exe"},
        {"kotlin", "kotlinc.exe"},
        {"scala", "scalac.exe"},
        {"groovy", "groovyc.exe"},
        {"clojure", "clojure.exe"},
        {"csharp", "csc.exe"},
        {"fsharp", "fsc.exe"},
        {"vb", "vbc.exe"},
        {"powershell", "powershell.exe"},
        {"shell", "bash.exe"},
        {"perl", "perl.exe"},
        {"ruby", "ruby.exe"},
        {"php", "php.exe"},
        {"lua", "lua.exe"},
        {"r", "R.exe"},
        {"matlab", "matlab.exe"},
        {"octave", "octave.exe"},
        {"julia", "julia.exe"},
        {"swift", "swiftc.exe"},
        {"objectivec", "cl.exe"},
        {"pascal", "fpc.exe"},
        {"delphi", "dcc32.exe"},
        {"ada", "gnat.exe"},
        {"cobol", "cobc.exe"},
        {"fortran", "gfortran.exe"},
        {"lisp", "sbcl.exe"},
        {"scheme", "scheme.exe"},
        {"erlang", "erlc.exe"},
        {"elixir", "elixirc.exe"},
        {"haskell", "ghc.exe"},
        {"ocaml", "ocamlc.exe"},
        {"ml", "mlton.exe"},
        {"prolog", "swipl.exe"},
        {"smalltalk", "gst.exe"},
        {"tcl", "tclsh.exe"},
        {"awk", "awk.exe"},
        {"sed", "sed.exe"},
        {"make", "nmake.exe"},
        {"cmake", "cmake.exe"},
        {"ninja", "ninja.exe"},
        {"msbuild", "msbuild.exe"},
        {"gradle", "gradle.exe"},
        {"maven", "mvn.exe"},
        {"ant", "ant.exe"},
        {"sbt", "sbt.exe"},
        {"cargo", "cargo.exe"},
        {"stack", "stack.exe"},
        {"cabal", "cabal.exe"},
        {"opam", "opam.exe"},
        {"pip", "pip.exe"},
        {"npm", "npm.exe"},
        {"yarn", "yarn.exe"},
        {"pnpm", "pnpm.exe"},
        {"bun", "bun.exe"},
        {"deno", "deno.exe"},
        {"dotnet", "dotnet.exe"},
        {"mono", "mono.exe"},
        {"jvm", "java.exe"},
        {"llvm", "clang.exe"},
        {"gcc", "gcc.exe"},
        {"gpp", "g++.exe"},
        {"clang", "clang.exe"},
        {"clangpp", "clang++.exe"}
    };
    
    auto it = compilerMap.find(language);
    if (it != compilerMap.end()) {
        return it->second;
    }
    return "cl.exe"; // Default to MSVC
}

ICompilerService::CompileResult CompilerServiceAdapter::Compile(const CompileRequest& req) {
    CompileResult result;
    
    // Update context engine with current file
    if (std::filesystem::exists(req.sourcePath)) {
        std::ifstream file(req.sourcePath);
        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        contextEngine_.UpdateFile(req.sourcePath, content);
        contextEngine_.SetCursor(req.sourcePath, 1);
    }
    
    // Build compiler arguments
    std::string compiler = GetCompilerForLanguage(req.language);
    std::string args;
    
    if (req.optimize) {
        args += "/O2 ";
    }
    
    if (req.targetArch == "x64") {
        args += "/arch:AVX2 ";
    }
    
    // Execute compilation
    std::string cmd = compiler + " " + args + " \"" + req.sourcePath + "\" /Fe:\"" + req.outputPath + "\"";
    
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (pipe) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result.output += buffer;
        }
        int exitCode = _pclose(pipe);
        result.success = (exitCode == 0);
        
        if (!result.success) {
            result.errors = result.output;
        }
        
        result.binaryPath = req.outputPath;
    } else {
        result.errors = "Failed to execute compiler: " + compiler;
    }
    
    return result;
}

ICompilerService::CompileResult CompilerServiceAdapter::CompileWithAIFix(const CompileRequest& req, int maxIterations) {
    CompileResult result;
    
    if (!compilerAgent_ || !aiProvider_) {
        // Fall back to regular compile
        return Compile(req);
    }
    
    // Use CompilerAgent for autonomous fixing
    bool success = compilerAgent_->CompileAndFix(req.sourcePath, "/O2 /arch:AVX2", maxIterations);
    
    result.success = success;
    result.binaryPath = req.outputPath;
    
    if (!success) {
        result.errors = "Failed to compile even with AI assistance after " + std::to_string(maxIterations) + " iterations";
    }
    
    return result;
}

std::vector<std::string> CompilerServiceAdapter::GetSupportedLanguages() {
    return {
        "c", "cpp", "cxx", "cc", "asm",
        "rust", "go", "zig", "nim", "d",
        "fortran", "cuda", "hip", "opencl", "metal",
        "spirv", "wasm", "javascript", "typescript",
        "python", "java", "kotlin", "scala", "groovy",
        "clojure", "csharp", "fsharp", "vb", "powershell",
        "shell", "perl", "ruby", "php", "lua",
        "r", "matlab", "octave", "julia", "swift",
        "objectivec", "pascal", "delphi", "ada", "cobol",
        "lisp", "scheme", "erlang", "elixir", "haskell",
        "ocaml", "ml", "prolog", "smalltalk", "tcl",
        "awk", "sed", "make", "cmake", "ninja",
        "msbuild", "gradle", "maven", "ant", "sbt",
        "cargo", "stack", "cabal", "opam", "pip",
        "npm", "yarn", "pnpm", "bun", "deno",
        "dotnet", "mono", "jvm", "llvm", "gcc",
        "gpp", "clang", "clangpp"
    };
}

} // namespace Unified
} // namespace RawrXD
