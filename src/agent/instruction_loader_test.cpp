<<<<<<< HEAD
/**
 * @file instruction_loader_test.cpp
 * @brief Tests for instruction file loading (Qt-free)
 *
 * Tests file reading and content verification.
 * File-system watching is handled by platform APIs (not Qt QFileSystemWatcher).
 */

#include <cassert>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

class InstructionLoaderTest {
public:
    void testLoadAndReload() {
        std::string tmp = (std::filesystem::temp_directory_path() / "rawrxd_instr_test.md").string();

        // Write initial instructions
        {
            std::ofstream f(tmp, std::ios::trunc);
            assert(f.is_open());
            f << "INSTR: HelloAI\nAlways greet the user.";
        }

        // Verify initial content
        {
            std::ifstream f(tmp);
            assert(f.is_open());
            std::string content((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
            assert(content.find("HelloAI") != std::string::npos);
        }

        // Modify file
        {
            std::ofstream f(tmp, std::ios::trunc);
            assert(f.is_open());
            f << "INSTR: NewMarker\nChanged content";
        }

        // Verify modified content
        {
            std::ifstream f(tmp);
            assert(f.is_open());
            std::string content((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
            assert(content.find("NewMarker") != std::string::npos);
=======
class InstructionLoaderTest  {private s:
    void testLoadAndReload() {
        std::string tmp = "" + "/rawrxd_instr_test.md";

        // Write initial instructions
        // File operation removed;
        if (f.open(std::iostream::WriteOnly | std::iostream::Text)) {
            f.write("INSTR: HelloAI\nAlways greet the user.");
            f.close();
        } else {
            QFAIL("Failed to create temp instruction file");
        }

        // SystemWatcher watcher;
        bool notified = false;
        // Connect removed{
            if (path == tmp) notified = true;
        });

        QVERIFY(watcher.addPath(tmp));

        // Modify file and ensure watcher notices
        if (f.open(std::iostream::WriteOnly | std::iostream::Text | std::iostream::Truncate)) {
            f.write("INSTR: NewMarker\nChanged content");
            f.close();
        } else {
            QFAIL("Failed to modify temp instruction file");
        }

        QTest::qWait(600);
        QVERIFY(notified);

        // Read file content and verify change
        if (f.open(std::iostream::ReadOnly | std::iostream::Text)) {
            std::string content = std::stringstream(&f).readAll();
            f.close();
            QVERIFY(content.contains("NewMarker"));
        } else {
            QFAIL("Failed to open temp instruction file for read");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }

        // Cleanup
        std::filesystem::remove(tmp);
<<<<<<< HEAD
        fprintf(stderr, "[INFO] InstructionLoaderTest::testLoadAndReload PASSED\n");
    }
};

// Standalone test runner (no MOC needed)
#ifdef INSTRUCTION_LOADER_TEST_MAIN
int main() {
    InstructionLoaderTest test;
    test.testLoadAndReload();
    return 0;
}
#endif
=======
    }
};

// Test removed
// MOC removed

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
