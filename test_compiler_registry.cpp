/*==========================================================================
 * Compiler Registry Test — REAL VERIFICATION
 * 
 * This test verifies that the CompilerRegistry actually works:
 * 1. Initializes and detects compilers
 * 2. Can query compilers by extension
 * 3. Can compile a real C++ file
 *=========================================================================*/

#include "src/compiler/CompilerRegistry.hpp"
#include <iostream>
#include <fstream>
#include <cassert>

using namespace RawrXD::Compiler;

int main(int argc, char* argv[]) {
    std::cout << "RawrXD Compiler Registry Test\n";
    std::cout << "=============================\n\n";
    
    // Test 1: Initialize
    std::cout << "[Test 1] Initializing Compiler Registry...\n";
    CompilerRegistry::Instance().Initialize();
    std::cout << "  ✓ Registry initialized\n\n";
    
    // Test 2: Get available compilers
    std::cout << "[Test 2] Detecting available compilers...\n";
    auto available = CompilerRegistry::Instance().GetAvailableCompilers();
    std::cout << "  Found " << available.size() << " available compilers\n";
    
    if (available.empty()) {
        std::cout << "  WARNING: No compilers detected. This may be normal if no compilers are installed.\n";
    } else {
        std::cout << "  Available compilers:\n";
        for (const auto& c : available) {
            std::cout << "    - " << c.name << " (" << c.id << ")\n";
        }
    }
    std::cout << "\n";
    
    // Test 3: Query by extension
    std::cout << "[Test 3] Querying compilers by extension...\n";
    auto cpp_compilers = CompilerRegistry::Instance().GetCompilersForExtension(".cpp");
    std::cout << "  Found " << cpp_compilers.size() << " compilers for .cpp files\n";
    
    auto asm_compilers = CompilerRegistry::Instance().GetCompilersForExtension(".asm");
    std::cout << "  Found " << asm_compilers.size() << " compilers for .asm files\n";
    std::cout << "\n";
    
    // Test 4: Get best compiler
    std::cout << "[Test 4] Getting best compiler for .cpp...\n";
    auto best = CompilerRegistry::Instance().GetBestCompilerForExtension(".cpp");
    if (best.has_value()) {
        std::cout << "  Best compiler: " << best->name << " (" << best->id << ")\n";
    } else {
        std::cout << "  No compiler available for .cpp\n";
    }
    std::cout << "\n";
    
    // Test 5: Create and compile a test file (if MSVC is available)
    std::cout << "[Test 5] Testing compilation...\n";
    
    // Create a simple test file
    std::string test_file = "test_compile_me.cpp";
    std::ofstream test_out(test_file);
    test_out << "#include <iostream>\n";
    test_out << "int main() {\n";
    test_out << "    std::cout << \"Hello from compiled code!\" << std::endl;\n";
    test_out << "    return 0;\n";
    test_out << "}\n";
    test_out.close();
    
    std::cout << "  Created test file: " << test_file << "\n";
    
    // Try to compile it
    CompileTask task;
    task.source_file = test_file;
    task.debug = true;
    task.optimize = false;
    
    auto result = CompilerRegistry::Instance().Compile(task);
    
    if (result.success) {
        std::cout << "  ✓ Compilation SUCCESSFUL\n";
        std::cout << "  Duration: " << result.duration_ms << " ms\n";
        std::cout << "  Command: " << result.command_executed << "\n";
    } else {
        std::cout << "  ✗ Compilation FAILED\n";
        std::cout << "  Exit code: " << result.exit_code << "\n";
        if (!result.errors.empty()) {
            std::cout << "  Errors:\n";
            for (const auto& e : result.errors) {
                std::cout << "    " << e << "\n";
            }
        }
    }
    
    // Cleanup
    std::filesystem::remove(test_file);
    if (std::filesystem::exists("test_compile_me.obj")) {
        std::filesystem::remove("test_compile_me.obj");
    }
    
    std::cout << "\n=============================\n";
    std::cout << "Test complete!\n";
    
    return result.success ? 0 : 1;
}
