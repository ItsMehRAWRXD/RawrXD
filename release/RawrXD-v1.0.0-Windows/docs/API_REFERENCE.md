# RawrXD Production Toolchain - API Reference

## Core Components

### 1. Test Framework API

#### Test Suite Management

```c
// Create a test suite
TestSuite* test_suite_create(const char* name, const char* description);

// Destroy a test suite
void test_suite_destroy(TestSuite* suite);

// Register a test case
void test_suite_register(TestSuite* suite, const char* name, 
                         const char* description, const char* file, 
                         int line, TestResult (*run)(void));

// Run all tests in suite
TestResult test_suite_run(TestSuite* suite);

// Print test results
void test_suite_print_results(TestSuite* suite);
```

#### Assertion Macros

```c
TEST_ASSERT(condition)                    // Basic assertion
TEST_ASSERT_EQ(expected, actual)         // Equality assertion
TEST_ASSERT_NE(expected, actual)         // Not equal assertion
TEST_ASSERT_NULL(ptr)                    // Null check
TEST_ASSERT_NOT_NULL(ptr)                // Non-null check
TEST_ASSERT_STR_EQ(expected, actual)     // String equality
```

#### Utility Functions

```c
double test_get_time_ms(void);           // High-res timer
void test_sleep_ms(int ms);              // Sleep function
char* test_read_file(const char* filename, size_t* size);
int test_write_file(const char* filename, const void* data, size_t size);
void test_generate_random_data(void* buffer, size_t size);
```

### 2. C Parser API

#### Parser Lifecycle

```c
// Create parser
Parser* parser_create(const char* source, const char* filename);

// Destroy parser
void parser_destroy(Parser* parser);

// Parse source
int parser_parse(Parser* parser);

// Get AST root
ASTNode* parser_get_ast(Parser* parser);
```

#### Scope Management

```c
void parser_push_scope(Parser* parser);
void parser_pop_scope(Parser* parser);
Scope* parser_current_scope(Parser* parser);
```

#### Symbol Management

```c
Symbol* parser_add_symbol(Parser* parser, const char* name, 
                          SymbolKind kind, Type* type);
Symbol* parser_lookup_symbol(Parser* parser, const char* name);
Symbol* parser_lookup_symbol_current(Parser* parser, const char* name);
```

#### Type System

```c
Type* type_create(TypeKind kind);
Type* type_pointer(Type* pointee);
Type* type_array(Type* element, int size);
Type* type_function(Type* ret, Type** params, int count, int variadic);
Type* type_copy(Type* type);
void type_destroy(Type* type);
int type_equal(Type* a, Type* b);
int type_size(Type* type);
int type_alignment(Type* type);
```

#### AST Utilities

```c
ASTNode* ast_create(ASTNodeType type, Token* token);
void ast_destroy(ASTNode* node);
void ast_print(ASTNode* node, int indent);
const char* ast_type_name(ASTNodeType type);
```

### 3. Profiler API

```c
// Initialize profiler
void profiler_init(void);

// Shutdown profiler
void profiler_shutdown(void);

// Register function
int profiler_register_function(const char* name, const char* file, int line);

// Enter/exit function
void profiler_enter_function(int func_idx);
void profiler_exit_function(int func_idx);

// Record memory allocation
void profiler_record_allocation(int func_idx, size_t size);

// Generate reports
void profiler_print_summary(void);
void profiler_print_functions(void);
void profiler_print_call_graph(void);
void profiler_print_memory(void);
void profiler_export_json(const char* filename);
```

#### Convenience Macros

```c
PROFILE_INIT()           // Initialize profiling
PROFILE_SHUTDOWN()       // Shutdown profiling
PROFILE_FUNC()           // Profile current function
PROFILE_REPORT()         // Print all reports
```

### 4. Coverage Tool API

```c
// Create coverage report
CoverageReport* coverage_create_report(void);

// Destroy coverage report
void coverage_destroy_report(CoverageReport* report);

// Add file to report
void coverage_add_file(CoverageReport* report, const char* file_path, int line_count);

// Record line hit
void coverage_record_line_hit(CoverageReport* report, const char* file_path, int line);

// Calculate coverage
void coverage_calculate(CoverageReport* report);

// Generate reports
void coverage_print_summary(CoverageReport* report);
void coverage_print_file_details(CoverageReport* report);
void coverage_export_html(CoverageReport* report, const char* output_path);
void coverage_export_lcov(CoverageReport* report, const char* output_path);
```

### 5. Static Analyzer API

```c
// Create analysis report
AnalysisReport* analysis_create_report(void);

// Destroy analysis report
void analysis_destroy_report(AnalysisReport* report);

// Analyze file
void analyze_file(AnalysisReport* report, const char* file_path);

// Generate reports
void analysis_print_summary(AnalysisReport* report);
void analysis_print_issues(AnalysisReport* report, IssueSeverity min_severity);
void analysis_export_json(AnalysisReport* report, const char* filename);
```

## Command Line Tools

### Build System

```batch
build [target]
```

**Targets:**
- `all` - Build everything
- `toolchain` - Build native toolchain
- `tests` - Build test suite
- `ci` - Run CI pipeline
- `clean` - Clean build artifacts
- `install` - Install to system

### Test Runner

```batch
run_tests [filter]
```

**Filters:**
- `all` - Run all tests
- `unit` - Run unit tests only
- `integration` - Run integration tests
- `fuzz` - Run fuzz tests
- `sanitizer` - Run sanitizer tests
- `ci` - Run CI test suite
- `[test_name]` - Run specific test

### Package Manager

```batch
rpkg [command] [package] [version]
```

**Commands:**
- `install [pkg] [ver]` - Install package
- `remove [pkg]` - Remove package
- `list` - List installed packages
- `search [term]` - Search packages
- `update` - Update package index
- `upgrade` - Upgrade packages
- `clean` - Clean cache
- `verify` - Verify integrity

### CI Pipeline

```batch
ci\ci_pipeline.bat [build_number]
```

**Phases:**
1. Clean build environment
2. Build native toolchain
3. Run unit tests
4. Run integration tests
5. Static analysis
6. Package artifacts

### Production Verification

```batch
verify_production.bat
```

Runs 10-point verification checklist:
1. Core binaries exist
2. Test framework exists
3. Unit tests exist
4. Integration tests exist
5. Fuzz tests exist
6. Sanitizer tests exist
7. CI/CD pipeline exists
8. Development tools exist
9. Directory structure complete
10. File count verification

## File Structure

```
d:\rawrxd\
├── native_toolchain\          # Core compiler
│   ├── minimal_assembler_v2.exe
│   ├── linker_with_imports.exe
│   ├── c_compiler_enhanced.c
│   ├── c_parser.h
│   └── c_parser.c
├── tests\                    # Test framework
│   ├── include\test_framework.h
│   ├── src\test_framework.c
│   ├── unit\test_assembler.c
│   ├── unit\test_linker.c
│   ├── integration\test_pipeline.c
│   ├── fuzz\fuzz_assembler.c
│   └── sanitizer\sanitizer_tests.c
├── ci\                      # CI/CD
│   └── ci_pipeline.bat
├── tools\                   # Development tools
│   ├── coverage\coverage_tool.c
│   ├── profiler\profiler.c
│   └── analyzer\static_analyzer.c
├── build.bat                # Master build
├── run_tests.bat            # Test runner
├── rpkg.bat                 # Package manager
└── verify_production.bat    # Verification
```

## Environment Variables

- `RAWRXD_HOME` - Installation directory (default: `d:\rawrxd`)
- `RAWRXD_BUILD` - Build output directory
- `RAWRXD_TEST` - Test output directory

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Build failed |
| 3 | Tests failed |
| 4 | Verification failed |

## Performance Targets

| Operation | Target | Status |
|-----------|--------|--------|
| Assembler (100 lines) | < 100ms | ✅ |
| Linker (1 object) | < 50ms | ✅ |
| Full Pipeline (100 lines) | < 500ms | ✅ |
| Full Pipeline (500 lines) | < 5s | ✅ |
| Test Suite (40 tests) | < 30s | ✅ |
| Fuzz Test (1000 iter) | < 60s | ✅ |

## Support

For issues or questions, refer to component-specific documentation in each directory.
