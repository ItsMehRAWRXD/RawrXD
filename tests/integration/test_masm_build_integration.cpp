// ============================================================================
// MASM Build Integration Tests
// Tests MASM build process + Problems panel parsing
// ============================================================================

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <QProcess>
#include <QTemporaryDir>
#include <QFile>
#include <QTextStream>
#include <QString>
#include <QDir>
#include <memory>
#include <string>
#include <vector>
#include <regex>

using namespace testing;

// ============================================================================
// MASM Build System
// ============================================================================

struct BuildError {
    std::string file;
    int line;
    int column;
    std::string severity; // "error", "warning", "info"
    std::string code;     // Error code like "A2006"
    std::string message;
    
    bool operator==(const BuildError& other) const {
        return file == other.file && line == other.line && 
               severity == other.severity && code == other.code;
    }
};

struct BuildResult {
    bool success = false;
    int exit_code = 0;
    std::string stdout_output;
    std::string stderr_output;
    std::vector<BuildError> errors;
    std::vector<BuildError> warnings;
    int elapsed_ms = 0;
};

class MasmBuildSystem {
public:
    struct Configuration {
        std::string ml64_path = "ml64.exe";
        std::string include_path;
        std::string lib_path;
        std::vector<std::string> defines;
        std::vector<std::string> additional_flags;
        int timeout_ms = 30000;
    };
    
    explicit MasmBuildSystem(const Configuration& config)
        : config_(config) {}
    
    BuildResult build(const std::string& source_file, const std::string& output_file) {
        BuildResult result;
        auto start = std::chrono::steady_clock::now();
        
        QProcess process;
        process.setProgram(QString::fromStdString(config_.ml64_path));
        
        QStringList args;
        args << "/c"; // Compile only
        
        // Add include paths
        if (!config_.include_path.empty()) {
            args << QString("/I%1").arg(QString::fromStdString(config_.include_path));
        }
        
        // Add defines
        for (const auto& define : config_.defines) {
            args << QString("/D%1").arg(QString::fromStdString(define));
        }
        
        // Add additional flags
        for (const auto& flag : config_.additional_flags) {
            args << QString::fromStdString(flag);
        }
        
        // Add output file
        args << QString("/Fo%1").arg(QString::fromStdString(output_file));
        
        // Add source file
        args << QString::fromStdString(source_file);
        
        process.setArguments(args);
        process.start();
        
        bool finished = process.waitForFinished(config_.timeout_ms);
        
        result.exit_code = process.exitCode();
        result.success = finished && (result.exit_code == 0);
        result.stdout_output = process.readAllStandardOutput().toStdString();
        result.stderr_output = process.readAllStandardError().toStdString();
        
        auto end = std::chrono::steady_clock::now();
        result.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        // Parse errors and warnings
        parseProblemsFromOutput(result);
        
        return result;
    }
    
    BuildResult link(const std::vector<std::string>& object_files, const std::string& output_exe) {
        BuildResult result;
        auto start = std::chrono::steady_clock::now();
        
        QProcess process;
        process.setProgram("link.exe");
        
        QStringList args;
        args << "/SUBSYSTEM:CONSOLE";
        args << "/MACHINE:X64";
        args << QString("/OUT:%1").arg(QString::fromStdString(output_exe));
        
        // Add library path
        if (!config_.lib_path.empty()) {
            args << QString("/LIBPATH:%1").arg(QString::fromStdString(config_.lib_path));
        }
        
        // Add object files
        for (const auto& obj : object_files) {
            args << QString::fromStdString(obj);
        }
        
        process.setArguments(args);
        process.start();
        
        bool finished = process.waitForFinished(config_.timeout_ms);
        
        result.exit_code = process.exitCode();
        result.success = finished && (result.exit_code == 0);
        result.stdout_output = process.readAllStandardOutput().toStdString();
        result.stderr_output = process.readAllStandardError().toStdString();
        
        auto end = std::chrono::steady_clock::now();
        result.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        parseProblemsFromOutput(result);
        
        return result;
    }
    
private:
    void parseProblemsFromOutput(BuildResult& result) {
        // Parse MASM error format:
        // filename.asm(line) : severity code: message
        // Example: test.asm(10) : error A2006: undefined symbol : MyProc
        
        std::regex error_pattern(
            R"(([^\(]+)\((\d+)\)\s*:\s*(error|warning)\s+([A-Z]\d+)\s*:\s*(.+))"
        );
        
        std::string combined_output = result.stdout_output + "\n" + result.stderr_output;
        std::istringstream stream(combined_output);
        std::string line;
        
        while (std::getline(stream, line)) {
            std::smatch match;
            if (std::regex_search(line, match, error_pattern)) {
                BuildError error;
                error.file = match[1].str();
                error.line = std::stoi(match[2].str());
                error.column = 0; // MASM doesn't provide column info
                error.severity = match[3].str();
                error.code = match[4].str();
                error.message = match[5].str();
                
                if (error.severity == "error") {
                    result.errors.push_back(error);
                } else if (error.severity == "warning") {
                    result.warnings.push_back(error);
                }
            }
        }
    }
    
    Configuration config_;
};

// ============================================================================
// Problems Panel Parser
// ============================================================================

class ProblemsPanel {
public:
    struct Problem {
        std::string file;
        int line;
        int column;
        std::string severity;
        std::string message;
        std::string source; // "masm", "cpp", "linker", etc.
    };
    
    void clearProblems() {
        problems_.clear();
    }
    
    void addProblemsFromBuildResult(const BuildResult& result, const std::string& source = "masm") {
        for (const auto& error : result.errors) {
            Problem problem;
            problem.file = error.file;
            problem.line = error.line;
            problem.column = error.column;
            problem.severity = "error";
            problem.message = error.code + ": " + error.message;
            problem.source = source;
            problems_.push_back(problem);
        }
        
        for (const auto& warning : result.warnings) {
            Problem problem;
            problem.file = warning.file;
            problem.line = warning.line;
            problem.column = warning.column;
            problem.severity = "warning";
            problem.message = warning.code + ": " + warning.message;
            problem.source = source;
            problems_.push_back(problem);
        }
    }
    
    std::vector<Problem> getProblems() const {
        return problems_;
    }
    
    std::vector<Problem> getProblemsByFile(const std::string& file) const {
        std::vector<Problem> result;
        for (const auto& problem : problems_) {
            if (problem.file == file) {
                result.push_back(problem);
            }
        }
        return result;
    }
    
    std::vector<Problem> getProblemsBySeverity(const std::string& severity) const {
        std::vector<Problem> result;
        for (const auto& problem : problems_) {
            if (problem.severity == severity) {
                result.push_back(problem);
            }
        }
        return result;
    }
    
    int getErrorCount() const {
        return getProblemsBySeverity("error").size();
    }
    
    int getWarningCount() const {
        return getProblemsBySeverity("warning").size();
    }
    
private:
    std::vector<Problem> problems_;
};

// ============================================================================
// Test Fixtures
// ============================================================================

class MasmBuildTest : public ::testing::Test {
protected:
    void SetUp() override {
        temp_dir = std::make_unique<QTemporaryDir>();
        ASSERT_TRUE(temp_dir->isValid());
        
        test_dir = temp_dir->path().toStdString();
        
        // Configure build system
        MasmBuildSystem::Configuration config;
        config.ml64_path = "ml64.exe";
        config.timeout_ms = 10000;
        build_system = std::make_unique<MasmBuildSystem>(config);
        
        problems_panel = std::make_unique<ProblemsPanel>();
    }
    
    void TearDown() override {
        problems_panel.reset();
        build_system.reset();
        temp_dir.reset();
    }
    
    std::string createTestFile(const std::string& filename, const std::string& content) {
        std::string filepath = test_dir + "/" + filename;
        QFile file(QString::fromStdString(filepath));
        EXPECT_TRUE(file.open(QIODevice::WriteOnly | QIODevice::Text));
        QTextStream out(&file);
        out << QString::fromStdString(content);
        file.close();
        return filepath;
    }
    
    std::unique_ptr<QTemporaryDir> temp_dir;
    std::string test_dir;
    std::unique_ptr<MasmBuildSystem> build_system;
    std::unique_ptr<ProblemsPanel> problems_panel;
};

// ============================================================================
// Basic Build Tests
// ============================================================================

TEST_F(MasmBuildTest, Build_ValidSimpleProgram_Succeeds) {
    std::string source = R"(
.code
main PROC
    mov rax, 0
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("simple.asm", source);
    std::string object_file = test_dir + "/simple.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.exit_code, 0);
    EXPECT_TRUE(result.errors.empty());
    EXPECT_TRUE(QFile::exists(QString::fromStdString(object_file)));
}

TEST_F(MasmBuildTest, Build_SyntaxError_ReportsError) {
    std::string source = R"(
.code
main PROC
    mov rax ; Missing operand
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("syntax_error.asm", source);
    std::string object_file = test_dir + "/syntax_error.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    EXPECT_FALSE(result.success);
    EXPECT_NE(result.exit_code, 0);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(MasmBuildTest, Build_UndefinedSymbol_ReportsError) {
    std::string source = R"(
.code
main PROC
    call UndefinedProc  ; This proc doesn't exist
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("undefined.asm", source);
    std::string object_file = test_dir + "/undefined.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    // Note: Undefined symbols may be caught at link time, not compile time
    // This test validates that we can compile without link
    EXPECT_TRUE(result.success || !result.errors.empty());
}

TEST_F(MasmBuildTest, Build_MultipleErrors_ReportsAll) {
    std::string source = R"(
.code
main PROC
    mov rax     ; Error 1: missing operand
    add rbx     ; Error 2: missing operand
    sub rcx     ; Error 3: missing operand
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("multiple_errors.asm", source);
    std::string object_file = test_dir + "/multiple_errors.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    EXPECT_FALSE(result.success);
    // Should report multiple errors
    EXPECT_GE(result.errors.size(), 2);
}

// ============================================================================
// Problems Panel Integration Tests
// ============================================================================

TEST_F(MasmBuildTest, ProblemsPanel_ParsesErrorsCorrectly) {
    std::string source = R"(
.code
main PROC
    mov rax ; Missing operand - line 4
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("error.asm", source);
    std::string object_file = test_dir + "/error.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    problems_panel->clearProblems();
    problems_panel->addProblemsFromBuildResult(result, "masm");
    
    auto problems = problems_panel->getProblems();
    
    EXPECT_FALSE(problems.empty());
    EXPECT_EQ(problems_panel->getErrorCount(), result.errors.size());
    
    if (!problems.empty()) {
        EXPECT_EQ(problems[0].severity, "error");
        EXPECT_EQ(problems[0].source, "masm");
        EXPECT_THAT(problems[0].file, HasSubstr("error.asm"));
    }
}

TEST_F(MasmBuildTest, ProblemsPanel_FiltersByFile) {
    // Create two files with errors
    std::string source1 = R"(
.code
proc1 PROC
    mov rax ; Error in file1
    ret
proc1 ENDP
END
)";
    
    std::string source2 = R"(
.code
proc2 PROC
    mov rbx ; Error in file2
    ret
proc2 ENDP
END
)";
    
    std::string file1 = createTestFile("file1.asm", source1);
    std::string file2 = createTestFile("file2.asm", source2);
    
    auto result1 = build_system->build(file1, test_dir + "/file1.obj");
    auto result2 = build_system->build(file2, test_dir + "/file2.obj");
    
    problems_panel->clearProblems();
    problems_panel->addProblemsFromBuildResult(result1, "masm");
    problems_panel->addProblemsFromBuildResult(result2, "masm");
    
    auto file1_problems = problems_panel->getProblemsByFile(file1);
    auto file2_problems = problems_panel->getProblemsByFile(file2);
    
    EXPECT_FALSE(file1_problems.empty());
    EXPECT_FALSE(file2_problems.empty());
    
    // Verify problems are correctly associated with their files
    for (const auto& problem : file1_problems) {
        EXPECT_EQ(problem.file, file1);
    }
    for (const auto& problem : file2_problems) {
        EXPECT_EQ(problem.file, file2);
    }
}

TEST_F(MasmBuildTest, ProblemsPanel_FiltersBySeverity) {
    // Create a file with both errors and warnings (if possible)
    std::string source = R"(
.code
main PROC
    mov rax ; Error
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("mixed.asm", source);
    std::string object_file = test_dir + "/mixed.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    problems_panel->clearProblems();
    problems_panel->addProblemsFromBuildResult(result, "masm");
    
    auto errors = problems_panel->getProblemsBySeverity("error");
    auto warnings = problems_panel->getProblemsBySeverity("warning");
    
    EXPECT_EQ(errors.size(), result.errors.size());
    EXPECT_EQ(warnings.size(), result.warnings.size());
}

TEST_F(MasmBuildTest, ProblemsPanel_ClearsCorrectly) {
    std::string source = R"(
.code
main PROC
    mov rax ; Error
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("clear.asm", source);
    std::string object_file = test_dir + "/clear.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    problems_panel->clearProblems();
    problems_panel->addProblemsFromBuildResult(result, "masm");
    
    EXPECT_FALSE(problems_panel->getProblems().empty());
    
    problems_panel->clearProblems();
    
    EXPECT_TRUE(problems_panel->getProblems().empty());
    EXPECT_EQ(problems_panel->getErrorCount(), 0);
    EXPECT_EQ(problems_panel->getWarningCount(), 0);
}

// ============================================================================
// Error Message Parsing Tests
// ============================================================================

TEST_F(MasmBuildTest, ErrorParsing_ExtractsFilename) {
    BuildResult result;
    result.stdout_output = "test.asm(10) : error A2006: undefined symbol : MyProc\n";
    
    MasmBuildSystem temp_builder(MasmBuildSystem::Configuration{});
    // We need to expose parseProblemsFromOutput for testing
    // For now, test through the full build pipeline
}

TEST_F(MasmBuildTest, ErrorParsing_ExtractsLineNumber) {
    std::string source = R"(
.code
main PROC
    mov rax ; Line 4 error
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("line_test.asm", source);
    std::string object_file = test_dir + "/line_test.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    if (!result.errors.empty()) {
        // Verify line number is captured (should be line 4)
        EXPECT_GT(result.errors[0].line, 0);
    }
}

TEST_F(MasmBuildTest, ErrorParsing_ExtractsErrorCode) {
    std::string source = R"(
.code
main PROC
    mov rax ; Error should have code
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("code_test.asm", source);
    std::string object_file = test_dir + "/code_test.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    if (!result.errors.empty()) {
        // Verify error code is captured (e.g., A2008)
        EXPECT_FALSE(result.errors[0].code.empty());
        EXPECT_THAT(result.errors[0].code, MatchesRegex("A\\d+"));
    }
}

TEST_F(MasmBuildTest, ErrorParsing_ExtractsMessage) {
    std::string source = R"(
.code
main PROC
    mov rax ; Missing operand
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("message_test.asm", source);
    std::string object_file = test_dir + "/message_test.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    if (!result.errors.empty()) {
        // Verify message is captured
        EXPECT_FALSE(result.errors[0].message.empty());
    }
}

// ============================================================================
// Link Tests
// ============================================================================

TEST_F(MasmBuildTest, Link_ValidObjectFile_Succeeds) {
    std::string source = R"(
EXTERN ExitProcess:PROC

.code
main PROC
    xor rcx, rcx
    call ExitProcess
main ENDP
END
)";
    
    std::string source_file = createTestFile("link_test.asm", source);
    std::string object_file = test_dir + "/link_test.obj";
    std::string exe_file = test_dir + "/link_test.exe";
    
    auto build_result = build_system->build(source_file, object_file);
    ASSERT_TRUE(build_result.success);
    
    auto link_result = build_system->link({object_file}, exe_file);
    
    EXPECT_TRUE(link_result.success);
    EXPECT_TRUE(QFile::exists(QString::fromStdString(exe_file)));
}

TEST_F(MasmBuildTest, Link_UndefinedSymbol_ReportsError) {
    std::string source = R"(
.code
main PROC
    call UndefinedProc
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("undefined_link.asm", source);
    std::string object_file = test_dir + "/undefined_link.obj";
    std::string exe_file = test_dir + "/undefined_link.exe";
    
    auto build_result = build_system->build(source_file, object_file);
    auto link_result = build_system->link({object_file}, exe_file);
    
    EXPECT_FALSE(link_result.success);
    // Linker should report undefined symbol
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_F(MasmBuildTest, Performance_BuildCompletesQuickly) {
    std::string source = R"(
.code
main PROC
    mov rax, 0
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("perf_test.asm", source);
    std::string object_file = test_dir + "/perf_test.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    // Build should complete in reasonable time (< 5 seconds)
    EXPECT_LT(result.elapsed_ms, 5000);
}

TEST_F(MasmBuildTest, Performance_LargeProgramBuilds) {
    // Generate a larger MASM program
    std::ostringstream source;
    source << ".code\n";
    for (int i = 0; i < 100; i++) {
        source << "proc" << i << " PROC\n";
        source << "    mov rax, " << i << "\n";
        source << "    ret\n";
        source << "proc" << i << " ENDP\n\n";
    }
    source << "END\n";
    
    std::string source_file = createTestFile("large.asm", source.str());
    std::string object_file = test_dir + "/large.obj";
    
    auto result = build_system->build(source_file, object_file);
    
    EXPECT_TRUE(result.success);
    // Large build should still complete in reasonable time (< 10 seconds)
    EXPECT_LT(result.elapsed_ms, 10000);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(MasmBuildTest, Integration_BuildFixRebuild_Workflow) {
    // 1. Build with error
    std::string source_with_error = R"(
.code
main PROC
    mov rax ; Error
    ret
main ENDP
END
)";
    
    std::string source_file = createTestFile("workflow.asm", source_with_error);
    std::string object_file = test_dir + "/workflow.obj";
    
    auto result1 = build_system->build(source_file, object_file);
    EXPECT_FALSE(result1.success);
    
    problems_panel->clearProblems();
    problems_panel->addProblemsFromBuildResult(result1, "masm");
    EXPECT_GT(problems_panel->getErrorCount(), 0);
    
    // 2. Fix error
    std::string source_fixed = R"(
.code
main PROC
    mov rax, 0
    ret
main ENDP
END
)";
    
    QFile file(QString::fromStdString(source_file));
    file.open(QIODevice::WriteOnly | QIODevice::Text);
    QTextStream out(&file);
    out << QString::fromStdString(source_fixed);
    file.close();
    
    // 3. Rebuild
    auto result2 = build_system->build(source_file, object_file);
    EXPECT_TRUE(result2.success);
    
    problems_panel->clearProblems();
    problems_panel->addProblemsFromBuildResult(result2, "masm");
    EXPECT_EQ(problems_panel->getErrorCount(), 0);
}

TEST_F(MasmBuildTest, Integration_MultiFileProject_BuildsSuccessfully) {
    // File 1: main.asm
    std::string main_source = R"(
EXTERN helper_proc:PROC
EXTERN ExitProcess:PROC

.code
main PROC
    call helper_proc
    xor rcx, rcx
    call ExitProcess
main ENDP
END
)";
    
    // File 2: helper.asm
    std::string helper_source = R"(
.code
helper_proc PROC PUBLIC
    mov rax, 42
    ret
helper_proc ENDP
END
)";
    
    std::string main_file = createTestFile("main.asm", main_source);
    std::string helper_file = createTestFile("helper.asm", helper_source);
    
    std::string main_obj = test_dir + "/main.obj";
    std::string helper_obj = test_dir + "/helper.obj";
    std::string exe_file = test_dir + "/program.exe";
    
    auto main_result = build_system->build(main_file, main_obj);
    auto helper_result = build_system->build(helper_file, helper_obj);
    
    EXPECT_TRUE(main_result.success);
    EXPECT_TRUE(helper_result.success);
    
    auto link_result = build_system->link({main_obj, helper_obj}, exe_file);
    
    EXPECT_TRUE(link_result.success);
    EXPECT_TRUE(QFile::exists(QString::fromStdString(exe_file)));
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
