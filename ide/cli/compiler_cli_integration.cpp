/*============================================================================
 * RAWRXD Compiler Driver - CLI IDE Integration
 * Adds compiler commands to the CLI IDE
 *============================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include "../common/compiler_integration.h"

/*==========================================================================
 * CLI Commands
 *==========================================================================*/

static void PrintCompilerBanner(void) {
    printf("\n");
    printf("================================================================\n");
    printf("  RAWRXD Compiler Driver v%s\n", RawrxdCompiler_GetVersion());
    printf("  Integrated with Codex CLI IDE\n");
    printf("================================================================\n\n");
}

static void PrintCompilerHelp(void) {
    printf("Compiler Commands:\n");
    printf("  compile <file>     Compile a single source file\n");
    printf("  build <files...>   Build multiple files into one executable\n");
    printf("  clean              Clean build artifacts\n");
    printf("  run <exe>          Run compiled executable\n");
    printf("  check              Check compiler availability\n");
    printf("  version            Show compiler version\n");
    printf("\n");
    printf("Compile Options:\n");
    printf("  -O                 Enable optimization\n");
    printf("  -g                 Include debug information\n");
    printf("  -v                 Verbose output\n");
    printf("  -o <file>          Specify output file\n");
    printf("  -I <path>          Add include path\n");
    printf("  -D <define>        Add preprocessor definition\n");
    printf("\n");
}

/*==========================================================================
 * Command Handlers
 *==========================================================================*/

static int HandleCompileCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("[-] Usage: compile <file> [options]\n");
        return 1;
    }
    
    const char* sourceFile = argv[1];
    
    // Check if file exists
    if (GetFileAttributesA(sourceFile) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] File not found: %s\n", sourceFile);
        return 1;
    }
    
    // Detect language
    RawrxdLanguage lang = RawrxdCompiler_DetectLanguage(sourceFile);
    if (lang == RAWRXD_LANG_UNKNOWN) {
        printf("[-] Unknown file type: %s\n", sourceFile);
        printf("    Supported: .c, .h, .asm, .s, .nasm, .cs\n");
        return 1;
    }
    
    printf("[*] Detected language: %s\n", RawrxdCompiler_LanguageName(lang));
    
    // Parse options
    RawrxdBuildConfig config;
    RawrxdCompiler_GetDefaultConfig(&config, nullptr);
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-O") == 0) {
            config.optimize = true;
            printf("[*] Optimization enabled\n");
        } else if (strcmp(argv[i], "-g") == 0) {
            config.debug = true;
            printf("[*] Debug info enabled\n");
        } else if (strcmp(argv[i], "-v") == 0) {
            config.verbose = true;
            printf("[*] Verbose mode\n");
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(config.outputName, argv[++i], MAX_PATH - 1);
            printf("[*] Output: %s\n", config.outputName);
        } else if (strcmp(argv[i], "-I") == 0 && i + 1 < argc) {
            strncat(config.includePaths, argv[++i], sizeof(config.includePaths) - strlen(config.includePaths) - 2);
            strncat(config.includePaths, ";", sizeof(config.includePaths) - strlen(config.includePaths) - 1);
        } else if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
            strncat(config.defines, argv[++i], sizeof(config.defines) - strlen(config.defines) - 2);
            strncat(config.defines, ";", sizeof(config.defines) - strlen(config.defines) - 1);
        }
    }
    
    // Compile
    printf("[*] Compiling: %s\n", sourceFile);
    printf("    ");
    
    RawrxdCompileResult result = RawrxdCompiler_Compile(sourceFile, &config);
    
    if (result.success) {
        printf("\n[+] Compilation successful!\n");
        printf("    Output: %s\n", result.outputPath);
        printf("    Time: %.2f ms\n", result.compileTimeMs);
        
        if (config.verbose && result.output[0]) {
            printf("\n--- Compiler Output ---\n%s\n", result.output);
        }
        
        return 0;
    } else {
        printf("\n[-] Compilation failed!\n");
        printf("    Exit code: %d\n", result.exitCode);
        
        if (result.error[0]) {
            printf("    Error: %s\n", result.error);
        }
        
        if (result.output[0]) {
            printf("\n--- Compiler Output ---\n%s\n", result.output);
        }
        
        return 1;
    }
}

static int HandleBuildCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("[-] Usage: build <file1> [file2] ... [options]\n");
        return 1;
    }
    
    std::vector<const char*> sourceFiles;
    RawrxdBuildConfig config;
    RawrxdCompiler_GetDefaultConfig(&config, nullptr);
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            // Option
            if (strcmp(argv[i], "-O") == 0) {
                config.optimize = true;
            } else if (strcmp(argv[i], "-g") == 0) {
                config.debug = true;
            } else if (strcmp(argv[i], "-v") == 0) {
                config.verbose = true;
            } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
                strncpy(config.outputName, argv[++i], MAX_PATH - 1);
            }
        } else {
            // Source file
            if (GetFileAttributesA(argv[i]) != INVALID_FILE_ATTRIBUTES) {
                sourceFiles.push_back(argv[i]);
            } else {
                printf("[-] File not found: %s\n", argv[i]);
            }
        }
    }
    
    if (sourceFiles.empty()) {
        printf("[-] No valid source files specified\n");
        return 1;
    }
    
    printf("[*] Building %zu file(s)...\n\n", sourceFiles.size());
    
    for (size_t i = 0; i < sourceFiles.size(); i++) {
        printf("    [%zu/%zu] %s\n", i + 1, sourceFiles.size(), sourceFiles[i]);
    }
    printf("\n");
    
    // Build
    RawrxdCompileResult result = RawrxdCompiler_Build(sourceFiles.data(), 
                                                      (int)sourceFiles.size(), &config);
    
    if (result.success) {
        printf("\n[+] Build successful!\n");
        if (config.outputName[0]) {
            printf("    Output: %s\n", config.outputName);
        }
        printf("    Time: %.2f ms\n", result.compileTimeMs);
        return 0;
    } else {
        printf("\n[-] Build failed!\n");
        if (result.error[0]) {
            printf("    %s\n", result.error);
        }
        if (result.output[0]) {
            printf("\n%s\n", result.output);
        }
        return 1;
    }
}

static int HandleCleanCommand(void) {
    printf("[*] Cleaning build artifacts...\n");
    
    // Remove common build outputs
    const char* patterns[] = {
        "*.exe", "*.obj", "*.o", "*.lib", "*.a",
        "*.pdb", "*.ilk", "*.exp", "*.manifest"
    };
    
    int removed = 0;
    for (int i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(patterns[i], &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (DeleteFileA(fd.cFileName)) {
                        printf("    Removed: %s\n", fd.cFileName);
                        removed++;
                    }
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }
    
    printf("[+] Clean complete. Removed %d file(s).\n", removed);
    return 0;
}

static int HandleRunCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("[-] Usage: run <executable> [args...]\n");
        return 1;
    }
    
    const char* exePath = argv[1];
    
    if (GetFileAttributesA(exePath) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Executable not found: %s\n", exePath);
        return 1;
    }
    
    printf("[*] Running: %s\n\n", exePath);
    
    // Build command line
    char cmdLine[4096] = {};
    strncpy(cmdLine, "\"", sizeof(cmdLine) - 1);
    strncat(cmdLine, exePath, sizeof(cmdLine) - strlen(cmdLine) - 1);
    strncat(cmdLine, "\"", sizeof(cmdLine) - strlen(cmdLine) - 1);
    
    for (int i = 2; i < argc; i++) {
        strncat(cmdLine, " ", sizeof(cmdLine) - strlen(cmdLine) - 1);
        strncat(cmdLine, argv[i], sizeof(cmdLine) - strlen(cmdLine) - 1);
    }
    
    // Execute
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        printf("\n[*] Process exited with code: %lu\n", exitCode);
        return (int)exitCode;
    } else {
        printf("[-] Failed to start process: %lu\n", GetLastError());
        return 1;
    }
}

static int HandleCheckCommand(void) {
    PrintCompilerBanner();
    
    printf("[*] Checking compiler availability...\n\n");
    
    if (RawrxdCompiler_IsAvailable()) {
        printf("[+] Compiler is available!\n");
        printf("    Version: %s\n", RawrxdCompiler_GetVersion());
        printf("    Path: %s\n", "(found in PATH or standard location)");
        
        printf("\n[*] Supported languages:\n");
        printf("    - C (.c, .h)\n");
        printf("    - Assembly (.asm, .s, .nasm)\n");
        printf("    - C# (.cs)\n");
        
        return 0;
    } else {
        printf("[-] Compiler not found!\n");
        printf("    Please ensure rawrxd-compiler.exe is in PATH\n");
        printf("    or installed in a standard location.\n");
        return 1;
    }
}

static int HandleVersionCommand(void) {
    PrintCompilerBanner();
    return 0;
}

/*==========================================================================
 * Main Integration Function
 *==========================================================================*/

int HandleCompilerCLICommand(int argc, char* argv[]) {
    if (argc < 1) {
        PrintCompilerHelp();
        return 1;
    }
    
    const char* cmd = argv[0];
    
    if (strcmp(cmd, "compile") == 0) {
        return HandleCompileCommand(argc, argv);
    } else if (strcmp(cmd, "build") == 0) {
        return HandleBuildCommand(argc, argv);
    } else if (strcmp(cmd, "clean") == 0) {
        return HandleCleanCommand();
    } else if (strcmp(cmd, "run") == 0) {
        return HandleRunCommand(argc, argv);
    } else if (strcmp(cmd, "check") == 0) {
        return HandleCheckCommand();
    } else if (strcmp(cmd, "version") == 0) {
        return HandleVersionCommand();
    } else if (strcmp(cmd, "help") == 0) {
        PrintCompilerHelp();
        return 0;
    } else {
        printf("[-] Unknown compiler command: %s\n", cmd);
        PrintCompilerHelp();
        return 1;
    }
}

/*==========================================================================
 * REPL Integration
 *==========================================================================*/

void CompilerREPL_Help(void) {
    printf("Compiler REPL Commands:\n");
    printf("  :compile <file>    Compile a file\n");
    printf("  :build <files>     Build multiple files\n");
    printf("  :clean             Clean build artifacts\n");
    printf("  :run <exe>         Run executable\n");
    printf("  :check             Check compiler status\n");
    printf("  :version           Show version\n");
    printf("\n");
}

bool CompilerREPL_HandleCommand(const char* input) {
    if (strncmp(input, ":compile ", 9) == 0) {
        char* args[3] = {"compile", (char*)input + 9, NULL};
        HandleCompileCommand(2, args);
        return true;
    } else if (strncmp(input, ":build ", 7) == 0) {
        // Parse multiple files
        char buffer[4096];
        strncpy(buffer, input + 7, sizeof(buffer) - 1);
        
        std::vector<char*> args;
        args.push_back("build");
        
        char* token = strtok(buffer, " ");
        while (token) {
            args.push_back(token);
            token = strtok(NULL, " ");
        }
        
        HandleBuildCommand((int)args.size(), args.data());
        return true;
    } else if (strcmp(input, ":clean") == 0) {
        HandleCleanCommand();
        return true;
    } else if (strncmp(input, ":run ", 5) == 0) {
        char* args[2] = {"run", (char*)input + 5};
        HandleRunCommand(2, args);
        return true;
    } else if (strcmp(input, ":check") == 0) {
        HandleCheckCommand();
        return true;
    } else if (strcmp(input, ":version") == 0) {
        HandleVersionCommand();
        return true;
    } else if (strcmp(input, ":compiler-help") == 0) {
        CompilerREPL_Help();
        return true;
    }
    
    return false; // Not a compiler command
}

/*==========================================================================
 * Initialization
 *==========================================================================*/

bool InitializeCompilerCLI(void) {
    return RawrxdCompiler_Init();
}

void ShutdownCompilerCLI(void) {
    RawrxdCompiler_Shutdown();
}
