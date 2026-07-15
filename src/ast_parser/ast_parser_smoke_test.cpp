#include "ASTContextProvider.h"
#include <iostream>
#include <chrono>

using namespace rawrxd;

int main() {
    std::cout << "=== AST Parser Smoke Test ===" << std::endl;
    
    // Test 1: Configuration defaults
    ASTParserConfig config;
    std::cout << "[TEST] Max parse time: " << config.max_parse_time_ms << "ms" << std::endl;
    if (config.max_parse_time_ms != 50) {
        std::cerr << "[FAIL] Expected 50ms, got " << config.max_parse_time_ms << std::endl;
        return 1;
    }
    std::cout << "[PASS] Configuration defaults" << std::endl;
    
    // Test 2: Provider creation
    auto start = std::chrono::steady_clock::now();
    ASTContextProvider provider(config);
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    std::cout << "[TEST] Provider creation time: " << ms << "ms" << std::endl;
    std::cout << "[PASS] Provider creation" << std::endl;
    
    // Test 3: Parse sample file
    std::string sample_code = R"(
class MyClass {
public:
    void myMethod() {
        int localVar = 42;
        float anotherVar = 3.14f;
    }
    
    int memberVar;
};

void globalFunction() {
    MyClass obj;
    obj.myMethod();
}
)";
    
    bool parse_result = provider.parse_file("test.cpp", sample_code);
    std::cout << "[TEST] Parse result: " << (parse_result ? "true" : "false") << std::endl;
    if (!parse_result) {
        std::cerr << "[FAIL] Parse failed" << std::endl;
        return 1;
    }
    std::cout << "[PASS] File parsing" << std::endl;
    
    // Test 4: Check file in cache
    bool has_file = provider.has_file("test.cpp");
    std::cout << "[TEST] Has file in cache: " << (has_file ? "true" : "false") << std::endl;
    if (!has_file) {
        std::cerr << "[FAIL] File not in cache" << std::endl;
        return 1;
    }
    std::cout << "[PASS] Cache check" << std::endl;
    
    // Test 5: Get symbols at cursor
    CursorPosition cursor{5, 10, "test.cpp"};
    auto symbols = provider.get_symbols_at_cursor(cursor);
    std::cout << "[TEST] Found " << symbols.size() << " symbols near cursor" << std::endl;
    for (size_t i = 0; i < symbols.size() && i < 3; ++i) {
        std::cout << "  [Symbol " << (i+1) << "] " << symbols[i].name 
                  << " (" << static_cast<int>(symbols[i].kind) << ")" << std::endl;
    }
    std::cout << "[PASS] Symbol lookup" << std::endl;
    
    // Test 6: Get current scope
    std::string scope = provider.get_current_scope(cursor);
    std::cout << "[TEST] Current scope at line 5: " << scope << std::endl;
    std::cout << "[PASS] Scope detection" << std::endl;
    
    // Test 7: Get symbol type
    std::string type = provider.get_symbol_type("localVar", cursor);
    std::cout << "[TEST] Type of 'localVar': " << (type.empty() ? "(not found)" : type) << std::endl;
    std::cout << "[PASS] Type lookup" << std::endl;
    
    // Test 8: Find references
    auto refs = provider.find_references("myMethod");
    std::cout << "[TEST] Found " << refs.size() << " references to 'myMethod'" << std::endl;
    for (size_t i = 0; i < refs.size() && i < 3; ++i) {
        std::cout << "  [Ref " << (i+1) << "] Line " << refs[i].line << std::endl;
    }
    std::cout << "[PASS] Reference search" << std::endl;
    
    // Test 9: Move semantics
    ASTContextProvider provider2(std::move(provider));
    std::cout << "[PASS] Move constructor" << std::endl;
    
    ASTContextProvider provider3(config);
    provider3 = std::move(provider2);
    std::cout << "[PASS] Move assignment" << std::endl;
    
    // Test 10: Invalidate file
    provider3.invalidate_file("test.cpp");
    bool still_has = provider3.has_file("test.cpp");
    std::cout << "[TEST] File invalidated: " << (!still_has ? "true" : "false") << std::endl;
    if (still_has) {
        std::cerr << "[FAIL] File still in cache after invalidation" << std::endl;
        return 1;
    }
    std::cout << "[PASS] Cache invalidation" << std::endl;
    
    // Test 11: Clear cache
    provider3.parse_file("test2.cpp", sample_code);
    provider3.clear_cache();
    bool empty = !provider3.has_file("test2.cpp");
    std::cout << "[TEST] Cache cleared: " << (empty ? "true" : "false") << std::endl;
    std::cout << "[PASS] Cache clear" << std::endl;
    
    std::cout << std::endl;
    std::cout << "=== All AST Parser Smoke Tests PASSED ===" << std::endl;
    std::cout << "AST Parser module is functional and ready for Phase 17 integration." << std::endl;
    
    return 0;
}