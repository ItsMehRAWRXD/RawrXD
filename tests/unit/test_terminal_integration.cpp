/**
 * @file test_terminal_integration.cpp
 * @brief Terminal integration tests: process spawning, I/O capture, error parsing
 */

#include <gtest/gtest.h>
#include <QProcess>
#include <QTemporaryDir>
#include <QString>
#include <QFile>
#include <QDebug>
#include <chrono>
#include <thread>
#include <memory>

/**
 * @class TerminalIntegrationTest
 * @brief Test fixture for terminal operations
 */
class TerminalIntegrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_tempDir = std::make_unique<QTemporaryDir>();
        ASSERT_TRUE(m_tempDir->isValid()) << "Failed to create temporary directory";
    }

    void TearDown() override
    {
        m_tempDir.reset();
    }

    std::unique_ptr<QTemporaryDir> m_tempDir;
};

/**
 * Test: Process spawning and basic execution
 */
TEST_F(TerminalIntegrationTest, ProcessSpawningBasic)
{
    QProcess process;
    
    // Record start time for latency tracking
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Run simple echo command
    process.start("cmd.exe", QStringList() << "/c" << "echo hello_world");
    
    ASSERT_TRUE(process.waitForStarted(5000)) << "Process failed to start";
    ASSERT_TRUE(process.waitForFinished(5000)) << "Process did not finish";
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Record metric
    qInfo() << "[TerminalIntegrationTest] Process execution latency:" << latencyMs << "ms";
    
    EXPECT_EQ(process.exitCode(), 0) << "Process exited with error";
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    EXPECT_TRUE(output.contains("hello_world")) << "Output missing expected string";
    EXPECT_LT(latencyMs, 5000) << "Process took too long";
}

/**
 * Test: Standard output capture
 */
TEST_F(TerminalIntegrationTest, StandardOutputCapture)
{
    QProcess process;
    QStringList expectedLines;
    expectedLines << "Line 1" << "Line 2" << "Line 3";
    
    // Create batch script that outputs multiple lines
    QString scriptPath = m_tempDir->path() + "/test_output.bat";
    QFile scriptFile(scriptPath);
    ASSERT_TRUE(scriptFile.open(QIODevice::WriteOnly));
    
    QTextStream out(&scriptFile);
    for (const QString& line : expectedLines) {
        out << "echo " << line << "\n";
    }
    scriptFile.close();
    
    // Execute script
    process.start("cmd.exe", QStringList() << "/c" << scriptPath);
    ASSERT_TRUE(process.waitForFinished(5000));
    
    // Parse output
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    
    // Verify all lines present
    for (const QString& expected : expectedLines) {
        bool found = false;
        for (const QString& line : lines) {
            if (line.contains(expected)) {
                found = true;
                break;
            }
        }
        EXPECT_TRUE(found) << "Expected line not found: " << expected.toStdString();
    }
}

/**
 * Test: Standard error capture
 */
TEST_F(TerminalIntegrationTest, StandardErrorCapture)
{
    QProcess process;
    
    // Create script that writes to stderr
    QString scriptPath = m_tempDir->path() + "/test_error.bat";
    QFile scriptFile(scriptPath);
    ASSERT_TRUE(scriptFile.open(QIODevice::WriteOnly));
    
    QTextStream out(&scriptFile);
    out << "powershell -Command \"Write-Error 'Test error message' -ErrorAction Continue\"\n";
    out << "exit /b 0\n";
    scriptFile.close();
    
    process.start("cmd.exe", QStringList() << "/c" << scriptPath);
    ASSERT_TRUE(process.waitForFinished(5000));
    
    QString stderr = QString::fromUtf8(process.readAllStandardError());
    qInfo() << "[TerminalIntegrationTest] Captured stderr:" << stderr;
    
    EXPECT_FALSE(stderr.isEmpty()) << "No stderr output captured";
}

/**
 * Test: Process timeout handling
 */
TEST_F(TerminalIntegrationTest, ProcessTimeout)
{
    QProcess process;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Start process that sleeps
    process.start("powershell.exe", 
        QStringList() << "-Command" << "Start-Sleep -Seconds 10");
    
    // Wait only 1 second
    bool finished = process.waitForFinished(1000);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    // Should timeout
    EXPECT_FALSE(finished) << "Process should have timed out";
    
    // Kill the process
    process.kill();
    EXPECT_TRUE(process.waitForFinished(2000)) << "Process failed to terminate";
    
    qInfo() << "[TerminalIntegrationTest] Timeout handled correctly, latency:" << latencyMs << "ms";
}

/**
 * Test: Process error detection
 */
TEST_F(TerminalIntegrationTest, ProcessErrorDetection)
{
    QProcess process;
    
    // Run command that fails
    process.start("cmd.exe", QStringList() << "/c" << "exit /b 42");
    
    ASSERT_TRUE(process.waitForFinished(5000));
    
    int exitCode = process.exitCode();
    EXPECT_NE(exitCode, 0) << "Exit code should indicate failure";
    EXPECT_EQ(exitCode, 42) << "Exit code should match expected value";
}

/**
 * Test: Concurrent process execution
 */
TEST_F(TerminalIntegrationTest, ConcurrentProcessExecution)
{
    const int NUM_PROCESSES = 5;
    std::vector<std::unique_ptr<QProcess>> processes;
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Start multiple processes concurrently
    for (int i = 0; i < NUM_PROCESSES; ++i) {
        auto proc = std::make_unique<QProcess>();
        proc->start("powershell.exe", 
            QStringList() << "-Command" << QString("Write-Host 'Process %1'; Start-Sleep -Milliseconds 100").arg(i));
        processes.push_back(std::move(proc));
    }
    
    // Wait for all to finish
    int completedCount = 0;
    for (auto& proc : processes) {
        if (proc->waitForFinished(5000)) {
            completedCount++;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    EXPECT_EQ(completedCount, NUM_PROCESSES) << "Not all processes completed";
    qInfo() << "[TerminalIntegrationTest] Concurrent execution of" << NUM_PROCESSES 
            << "processes completed in" << latencyMs << "ms";
}

/**
 * Test: Large output handling
 */
TEST_F(TerminalIntegrationTest, LargeOutputHandling)
{
    QProcess process;
    
    // Generate large output (10MB of text)
    QString command = R"(
        for($i=0; $i -lt 100000; $i++) {
            Write-Output "Line $i: This is a test line with some content to increase size"
        }
    )";
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    process.start("powershell.exe", QStringList() << "-Command" << command);
    ASSERT_TRUE(process.waitForFinished(30000)) << "Large output processing timeout";
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    QByteArray output = process.readAllStandardOutput();
    
    qInfo() << "[TerminalIntegrationTest] Large output (" << output.size() << " bytes)"
            << "processed in" << latencyMs << "ms";
    
    EXPECT_GT(output.size(), 1000000) << "Expected large output";
    EXPECT_LT(latencyMs, 30000) << "Processing took too long";
}

/**
 * Test: Real-time output streaming
 */
TEST_F(TerminalIntegrationTest, RealtimeOutputStreaming)
{
    QProcess process;
    QStringList capturedLines;
    int lineCount = 0;
    
    // Connect to readyReadStandardOutput signal for real-time capture
    QObject::connect(&process, QOverload<>::of(&QProcess::readyReadStandardOutput),
        [&process, &capturedLines, &lineCount]() {
            QString output = QString::fromUtf8(process.readAllStandardOutput());
            QStringList lines = output.split('\n', Qt::SkipEmptyParts);
            capturedLines.append(lines);
            lineCount += lines.count();
        });
    
    QString command = R"(
        for($i=0; $i -lt 50; $i++) {
            Write-Output "Stream line $i"
            Start-Sleep -Milliseconds 10
        }
    )";
    
    process.start("powershell.exe", QStringList() << "-Command" << command);
    ASSERT_TRUE(process.waitForFinished(10000));
    
    qInfo() << "[TerminalIntegrationTest] Streamed" << lineCount << "lines in real-time";
    EXPECT_GT(lineCount, 40) << "Should have captured most lines";
}

/**
 * Test: Process environment variables
 */
TEST_F(TerminalIntegrationTest, ProcessEnvironmentVariables)
{
    QProcess process;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert("TEST_VAR", "TestValue123");
    process.setProcessEnvironment(env);
    
    process.start("cmd.exe", 
        QStringList() << "/c" << "echo %TEST_VAR%");
    
    ASSERT_TRUE(process.waitForFinished(5000));
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    EXPECT_TRUE(output.contains("TestValue123")) << "Environment variable not set correctly";
}

/**
 * Test: Working directory handling
 */
TEST_F(TerminalIntegrationTest, WorkingDirectoryHandling)
{
    QProcess process;
    process.setWorkingDirectory(m_tempDir->path());
    
    // Create test file in temp dir
    QString testFile = m_tempDir->path() + "/test.txt";
    QFile file(testFile);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    file.write("test content");
    file.close();
    
    // List directory
    process.start("cmd.exe", QStringList() << "/c" << "dir /B test.txt");
    ASSERT_TRUE(process.waitForFinished(5000));
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    EXPECT_TRUE(output.contains("test.txt")) << "File should be found in working directory";
}

/**
 * Test: Standard input to process
 */
TEST_F(TerminalIntegrationTest, StandardInputToProcess)
{
    QProcess process;
    
    process.start("cmd.exe", QStringList() << "/c" << "findstr /i hello");
    ASSERT_TRUE(process.waitForStarted(5000));
    
    // Send input
    process.write("hello world\n");
    process.closeWriteChannel();
    
    ASSERT_TRUE(process.waitForFinished(5000));
    
    QString output = QString::fromUtf8(process.readAllStandardOutput());
    EXPECT_TRUE(output.contains("hello")) << "Process should echo our input";
}

/**
 * Test: Error parsing - CMake style
 */
TEST_F(TerminalIntegrationTest, ErrorParsingCMakeStyle)
{
    QString errorLine = "CMake Error at CMakeLists.txt:42 (message):\n"
                        "  Syntax error: expected expression";
    
    // Parse using regex
    QRegularExpression regex("CMake Error at (.+):([0-9]+)");
    QRegularExpressionMatch match = regex.match(errorLine);
    
    ASSERT_TRUE(match.hasMatch()) << "CMake error pattern not matched";
    EXPECT_EQ(match.captured(1), "CMakeLists.txt");
    EXPECT_EQ(match.captured(2), "42");
}

/**
 * Test: Error parsing - MSBuild style
 */
TEST_F(TerminalIntegrationTest, ErrorParsingMSBuildStyle)
{
    QString errorLine = "src\\main.cpp(123,45): error C2001: newline in constant";
    
    QRegularExpression regex(R"((.+?)\((\d+),(\d+)\)\s*:\s*(error|warning)\s+(.+?)\s*:\s*(.+))");
    QRegularExpressionMatch match = regex.match(errorLine);
    
    ASSERT_TRUE(match.hasMatch()) << "MSBuild error pattern not matched";
    EXPECT_TRUE(match.captured(1).contains("src"));
    EXPECT_EQ(match.captured(2), "123");
    EXPECT_EQ(match.captured(3), "45");
    EXPECT_EQ(match.captured(4), "error");
}

/**
 * Test: Error parsing - MASM style
 */
TEST_F(TerminalIntegrationTest, ErrorParsingMASMStyle)
{
    QString errorLine = "kernel.asm(567): error ML2000: Invalid instruction";
    
    QRegularExpression regex(R"(([^\s(]+\.asm)\((\d+)\)\s*:\s*(error|warning)\s+(ML\d+)\s*:\s*(.+))");
    QRegularExpressionMatch match = regex.match(errorLine);
    
    ASSERT_TRUE(match.hasMatch()) << "MASM error pattern not matched";
    EXPECT_EQ(match.captured(1), "kernel.asm");
    EXPECT_EQ(match.captured(2), "567");
    EXPECT_EQ(match.captured(4), "ML2000");
}
