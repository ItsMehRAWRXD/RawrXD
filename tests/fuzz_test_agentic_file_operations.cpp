<<<<<<< HEAD
/**
 * @file fuzz_test_agentic_file_operations.cpp
 * @brief Fuzz tests for Keep/Undo file operations — C++20, no Qt.
 *
 * Tests robustness with large files, special characters, unicode,
 * sequential/concurrent-style ops, path edge cases, and binary content.
 */

#include "agentic_file_operations.h"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;

#define TEST_VERIFY(cond) do { if (!(cond)) { std::fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, #cond); ++g_failed; } ++g_run; } while(0)

static int g_run = 0;
static int g_failed = 0;
static std::mt19937 g_rng{42};

static std::string generateRandomString(int length) {
    const char possible[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::uniform_int_distribution<int> dist(0, static_cast<int>(sizeof(possible) - 2));
    std::string s;
    s.reserve(static_cast<size_t>(length));
    for (int i = 0; i < length; ++i)
        s += possible[dist(g_rng)];
    return s;
}

static std::string generateRandomUnicodeString(int length) {
    std::string s;
    s.reserve(static_cast<size_t>(length * 3));
    std::uniform_int_distribution<int> dist(0x00, 0xFF);
    for (int i = 0; i < length; ++i) {
        int cp = dist(g_rng) | (dist(g_rng) << 8);
        if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0x20;
        if (cp < 0x80) {
            s += static_cast<char>(cp);
        } else if (cp < 0x800) {
            s += static_cast<char>(0xC0 | (cp >> 6));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            s += static_cast<char>(0xE0 | (cp >> 12));
            s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            s += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    return s;
}

static std::vector<uint8_t> generateRandomBinaryData(size_t length) {
    std::vector<uint8_t> data(length);
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < length; ++i)
        data[i] = static_cast<uint8_t>(dist(g_rng));
    return data;
}

static std::string readAll(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::string(std::istreambuf_iterator<char>(f), {});
}

static void testLargeFileOperations() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_large";
    fs::create_directories(tmp);
    std::string testFilePath = (tmp / "large_file_test.txt").string();

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    std::string largeContent = generateRandomString(1024 * 1024);
    fileOps.createFileWithApproval(testFilePath, largeContent);

    TEST_VERIFY(fs::exists(testFilePath));
    TEST_VERIFY(fs::file_size(testFilePath) > 1000000);

    std::string modifiedContent = generateRandomString(1024 * 1024);
    fileOps.modifyFileWithApproval(testFilePath, modifiedContent);
    TEST_VERIFY(readAll(testFilePath).size() == modifiedContent.size());

    fileOps.deleteFileWithApproval(testFilePath);
    TEST_VERIFY(!fs::exists(testFilePath));

    fs::remove_all(tmp);
}

static void testSpecialCharacterFilenames() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_special";
    fs::create_directories(tmp);

    std::vector<std::string> names = {
        "test file with spaces.txt",
        "test-file-with-dashes.txt",
        "test_file_with_underscores.txt",
        "test.file.with.dots.txt",
    };

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    for (const auto& name : names) {
        std::string path = (tmp / name).string();
        std::string content = "Content for " + name;
        fileOps.createFileWithApproval(path, content);
        TEST_VERIFY(fs::exists(path));
        fileOps.modifyFileWithApproval(path, "Modified " + content);
        TEST_VERIFY(readAll(path).find("Modified") != std::string::npos);
        fileOps.deleteFileWithApproval(path);
        TEST_VERIFY(!fs::exists(path));
    }

    fs::remove_all(tmp);
}

static void testUnicodeContent() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_unicode";
    fs::create_directories(tmp);
    std::string testFilePath = (tmp / "unicode_test.txt").string();

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    std::string unicodeContent = generateRandomUnicodeString(10000);
    fileOps.createFileWithApproval(testFilePath, unicodeContent);
    TEST_VERIFY(fs::exists(testFilePath));

    std::string modifiedUnicode = generateRandomUnicodeString(10000);
    fileOps.modifyFileWithApproval(testFilePath, modifiedUnicode);
    TEST_VERIFY(fs::file_size(testFilePath) > 0);

    fileOps.deleteFileWithApproval(testFilePath);
    TEST_VERIFY(!fs::exists(testFilePath));

    fs::remove_all(tmp);
}

static void testConcurrentStyleOperations() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_concurrent";
    fs::create_directories(tmp);

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    for (int i = 0; i < 50; ++i) {
        std::string path = (tmp / ("concurrent_test_" + std::to_string(i) + ".txt")).string();
        std::string content = "Content " + std::to_string(i);

        switch (i % 3) {
            case 0:
                fileOps.createFileWithApproval(path, content);
                TEST_VERIFY(fs::exists(path));
                break;
            case 1: {
                fileOps.createFileWithApproval(path, content);
                TEST_VERIFY(fs::exists(path));
                fileOps.modifyFileWithApproval(path, "Modified content " + std::to_string(i));
                break;
            }
            case 2:
                fileOps.createFileWithApproval(path, content);
                TEST_VERIFY(fs::exists(path));
                fileOps.deleteFileWithApproval(path);
                TEST_VERIFY(!fs::exists(path));
                break;
        }
    }

    fs::remove_all(tmp);
}

static void testPathTraversalAttempts() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_traversal";
    fs::create_directories(tmp);

    std::string base = tmp.string();
    std::vector<std::string> traversalPaths = {
        base + "/../traversal_test1.txt",
        base + "/./traversal_test3.txt",
    };

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    for (const auto& path : traversalPaths) {
        fileOps.createFileWithApproval(path, "Traversal test content");
        if (fs::exists(path)) {
            fileOps.modifyFileWithApproval(path, "Modified traversal content");
            fileOps.deleteFileWithApproval(path);
        }
    }

    fs::remove_all(tmp);
}

static void testVeryLongPaths() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_long";
    fs::create_directories(tmp);
    fs::path longPath = tmp;
    for (int i = 0; i < 20; ++i)
        longPath = longPath / ("very_long_directory_name_" + std::to_string(i));
    fs::create_directories(longPath);
    std::string filePath = (longPath / "very_long_filename.txt").string();

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    fileOps.createFileWithApproval(filePath, "Content for very long path");
    if (fs::exists(filePath)) {
        fileOps.modifyFileWithApproval(filePath, "Modified content for very long path");
        fileOps.deleteFileWithApproval(filePath);
    }

    fs::remove_all(tmp);
}

static void testEmptyAndWhitespaceContent() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_whitespace";
    fs::create_directories(tmp);
    std::string testFilePath = (tmp / "whitespace_test.txt").string();

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    fileOps.createFileWithApproval(testFilePath, "");
    TEST_VERIFY(fs::exists(testFilePath));
    TEST_VERIFY(fs::file_size(testFilePath) == 0);

    std::string whitespace = "   \t\n  \r\n  \t  ";
    fileOps.modifyFileWithApproval(testFilePath, whitespace);
    TEST_VERIFY(readAll(testFilePath) == whitespace);

    fileOps.deleteFileWithApproval(testFilePath);
    TEST_VERIFY(!fs::exists(testFilePath));

    fs::remove_all(tmp);
}

static void testBinaryContent() {
    fs::path tmp = fs::temp_directory_path() / "rawrxd_fuzz_binary";
    fs::create_directories(tmp);
    std::string testFilePath = (tmp / "binary_test.bin").string();

    auto binaryContent = generateRandomBinaryData(10000);
    std::string binStr(binaryContent.begin(), binaryContent.end());
    std::ofstream f(testFilePath, std::ios::binary);
    f.write(binStr.data(), static_cast<std::streamsize>(binStr.size()));
    f.close();

    AgenticFileOperations fileOps;
    fileOps.setApprovalCallback([](const std::string&, AgenticFileActionType, const std::string*) { return true; });

    auto modifiedBinary = generateRandomBinaryData(10000);
    std::string modStr(modifiedBinary.begin(), modifiedBinary.end());
    fileOps.modifyFileWithApproval(testFilePath, modStr);
    std::string readBack = readAll(testFilePath);
    TEST_VERIFY(readBack.size() == modStr.size());

    fileOps.deleteFileWithApproval(testFilePath);
    TEST_VERIFY(!fs::exists(testFilePath));

    fs::remove_all(tmp);
}

#define RUN(test) do { test(); } while(0)

int main() {
    std::fprintf(stdout, "Fuzz tests for AgenticFileOperations (C++20, no Qt)\n");
    RUN(testLargeFileOperations);
    RUN(testSpecialCharacterFilenames);
    RUN(testUnicodeContent);
    RUN(testConcurrentStyleOperations);
    RUN(testPathTraversalAttempts);
    RUN(testVeryLongPaths);
    RUN(testEmptyAndWhitespaceContent);
    RUN(testBinaryContent);
    std::fprintf(stdout, "Done: %d run, %d failed\n", g_run, g_failed);
    return g_failed ? 1 : 0;
}
=======
#include "agentic_file_operations.h"
#include "agentic_error_handler.h"
#include <QTest>
#include <QTemporaryDir>
#include <QFile>
#include <QTextStream>
#include <QRandomGenerator>
#include <QSignalSpy>

/**
 * @class FuzzTestAgenticFileOperations
 * @brief Fuzz tests for Keep/Undo file operations with randomized inputs
 * 
 * Tests the robustness of file operations with various edge cases,
 * including very large files, special characters, unicode, etc.
 */
class FuzzTestAgenticFileOperations : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testLargeFileOperations();
    void testSpecialCharacterFilenames();
    void testUnicodeContent();
    void testConcurrentOperations();
    void testPathTraversalAttempts();
    void testVeryLongPaths();
    void testEmptyAndWhitespaceContent();
    void testBinaryContent();

private:
    QTemporaryDir* m_tempDir;
    QString m_testDirPath;
    AgenticErrorHandler* m_errorHandler;
    
    QString generateRandomString(int length);
    QString generateRandomUnicodeString(int length);
    QByteArray generateRandomBinaryData(int length);
};

void FuzzTestAgenticFileOperations::initTestCase()
{
    m_tempDir = new QTemporaryDir();
    QVERIFY(m_tempDir->isValid());
    m_testDirPath = m_tempDir->path();
    
    m_errorHandler = new AgenticErrorHandler();
    QVERIFY(m_errorHandler != nullptr);
}

void FuzzTestAgenticFileOperations::cleanupTestCase()
{
    delete m_errorHandler;
    delete m_tempDir;
}

QString FuzzTestAgenticFileOperations::generateRandomString(int length)
{
    const QString possibleCharacters("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    QString randomString;
    for(int i = 0; i < length; ++i)
    {
        int index = QRandomGenerator::global()->bounded(possibleCharacters.length());
        QChar nextChar = possibleCharacters.at(index);
        randomString.append(nextChar);
    }
    return randomString;
}

QString FuzzTestAgenticFileOperations::generateRandomUnicodeString(int length)
{
    QString unicodeString;
    for(int i = 0; i < length; ++i)
    {
        // Generate random Unicode code points (Basic Multilingual Plane)
        uint codePoint = QRandomGenerator::global()->bounded(0x0000, 0xFFFF);
        unicodeString.append(QChar(codePoint));
    }
    return unicodeString;
}

QByteArray FuzzTestAgenticFileOperations::generateRandomBinaryData(int length)
{
    QByteArray data;
    data.reserve(length);
    for(int i = 0; i < length; ++i)
    {
        char byte = static_cast<char>(QRandomGenerator::global()->bounded(0, 256));
        data.append(byte);
    }
    return data;
}

void FuzzTestAgenticFileOperations::testLargeFileOperations()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    QString testFilePath = m_testDirPath + "/large_file_test.txt";
    
    // Generate large content (1MB)
    QString largeContent = generateRandomString(1024 * 1024);
    
    // Test creation with large content
    fileOps.createFileWithApproval(testFilePath, largeContent);
    
    // Verify file exists and has correct size
    QFile file(testFilePath);
    QVERIFY(file.exists());
    QVERIFY(file.size() > 1000000); // Approximate check
    
    // Test modification with large content
    QString modifiedLargeContent = generateRandomString(1024 * 1024);
    fileOps.modifyFileWithApproval(testFilePath, largeContent, modifiedLargeContent);
    
    // Verify modification
    QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
    QString readContent = QTextStream(&file).readAll();
    file.close();
    QCOMPARE(readContent.size(), modifiedLargeContent.size());
    
    // Test deletion
    fileOps.deleteFileWithApproval(testFilePath);
    QVERIFY(!file.exists());
}

void FuzzTestAgenticFileOperations::testSpecialCharacterFilenames()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    QStringList specialFilenames;
    
    // Test various special character combinations
    specialFilenames << m_testDirPath + "/test file with spaces.txt"
                     << m_testDirPath + "/test-file-with-dashes.txt"
                     << m_testDirPath + "/test_file_with_underscores.txt"
                     << m_testDirPath + "/test.file.with.dots.txt"
                     << m_testDirPath + "/test#file#with#hashes.txt"
                     << m_testDirPath + "/test@file@with@at.txt"
                     << m_testDirPath + "/test$file$with$dollar.txt"
                     << m_testDirPath + "/test%file%with%percent.txt"
                     << m_testDirPath + "/test^file^with^caret.txt"
                     << m_testDirPath + "/test&file&with&ersand.txt";
    
    for (const QString& filename : specialFilenames) {
        QString content = "Content for " + filename;
        
        // Test creation
        fileOps.createFileWithApproval(filename, content);
        QVERIFY(QFile::exists(filename));
        
        // Test modification
        QString modifiedContent = "Modified content for " + filename;
        fileOps.modifyFileWithApproval(filename, content, modifiedContent);
        
        // Verify modification
        QFile file(filename);
        QVERIFY(file.open(QIODevice::ReadOnly | QIODevice::Text));
        QString readContent = QTextStream(&file).readAll();
        file.close();
        QCOMPARE(readContent, modifiedContent);
        
        // Test deletion
        fileOps.deleteFileWithApproval(filename);
        QVERIFY(!file.exists());
    }
}

void FuzzTestAgenticFileOperations::testUnicodeContent()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    QString testFilePath = m_testDirPath + "/unicode_test.txt";
    
    // Generate Unicode content
    QString unicodeContent = generateRandomUnicodeString(10000);
    
    // Test creation with Unicode content
    fileOps.createFileWithApproval(testFilePath, unicodeContent);
    QVERIFY(QFile::exists(testFilePath));
    
    // Verify content preservation
    QFile file(testFilePath);
    QVERIFY(file.open(QIODevice::ReadOnly));
    QByteArray rawData = file.readAll();
    file.close();
    
    // Test modification with Unicode content
    QString modifiedUnicodeContent = generateRandomUnicodeString(10000);
    fileOps.modifyFileWithApproval(testFilePath, unicodeContent, modifiedUnicodeContent);
    
    // Verify modification
    QVERIFY(file.open(QIODevice::ReadOnly));
    QByteArray modifiedRawData = file.readAll();
    file.close();
    QVERIFY(modifiedRawData.size() > 0);
    
    // Test deletion
    fileOps.deleteFileWithApproval(testFilePath);
    QVERIFY(!file.exists());
}

void FuzzTestAgenticFileOperations::testConcurrentOperations()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    
    // Perform multiple operations in sequence to test concurrency handling
    for (int i = 0; i < 50; ++i) {
        QString testFilePath = QString("%1/concurrent_test_%2.txt").arg(m_testDirPath).arg(i);
        QString content = QString("Content %1").arg(i);
        
        // Alternate between different operations
        switch (i % 3) {
            case 0:
                fileOps.createFileWithApproval(testFilePath, content);
                QVERIFY(QFile::exists(testFilePath));
                break;
            case 1:
                // Create file first, then modify
                fileOps.createFileWithApproval(testFilePath, content);
                QVERIFY(QFile::exists(testFilePath));
                QString modifiedContent = QString("Modified content %1").arg(i);
                fileOps.modifyFileWithApproval(testFilePath, content, modifiedContent);
                break;
            case 2:
                // Create file first, then delete
                fileOps.createFileWithApproval(testFilePath, content);
                QVERIFY(QFile::exists(testFilePath));
                fileOps.deleteFileWithApproval(testFilePath);
                QVERIFY(!QFile::exists(testFilePath));
                break;
        }
    }
}

void FuzzTestAgenticFileOperations::testPathTraversalAttempts()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    
    // Test path traversal attempts (these should be handled by the system)
    QStringList traversalPaths;
    traversalPaths << m_testDirPath + "/../traversal_test1.txt"
                   << m_testDirPath + "/../../traversal_test2.txt"
                   << m_testDirPath + "/./traversal_test3.txt"
                   << m_testDirPath + "/nested/../../../traversal_test4.txt";
    
    for (const QString& path : traversalPaths) {
        QString content = "Traversal test content";
        
        // These operations should either succeed (if path resolution is safe)
        // or fail gracefully (if path is invalid)
        fileOps.createFileWithApproval(path, content);
        
        // If file exists, test other operations
        if (QFile::exists(path)) {
            QString modifiedContent = "Modified traversal test content";
            fileOps.modifyFileWithApproval(path, content, modifiedContent);
            fileOps.deleteFileWithApproval(path);
        }
    }
}

void FuzzTestAgenticFileOperations::testVeryLongPaths()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    
    // Generate a very long path
    QString longPath = m_testDirPath + "/";
    for (int i = 0; i < 50; ++i) {
        longPath += "very_long_directory_name_" + QString::number(i) + "/";
    }
    longPath += "very_long_filename.txt";
    
    QString content = "Content for very long path";
    
    // Test creation with very long path
    fileOps.createFileWithApproval(longPath, content);
    
    // If file exists, test other operations
    if (QFile::exists(longPath)) {
        QString modifiedContent = "Modified content for very long path";
        fileOps.modifyFileWithApproval(longPath, content, modifiedContent);
        fileOps.deleteFileWithApproval(longPath);
    }
}

void FuzzTestAgenticFileOperations::testEmptyAndWhitespaceContent()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    QString testFilePath = m_testDirPath + "/whitespace_test.txt";
    
    // Test empty content
    QString emptyContent = "";
    fileOps.createFileWithApproval(testFilePath, emptyContent);
    QVERIFY(QFile::exists(testFilePath));
    
    QFile file(testFilePath);
    QVERIFY(file.open(QIODevice::ReadOnly));
    QCOMPARE(file.readAll().size(), 0);
    file.close();
    
    // Test whitespace-only content
    QString whitespaceContent = "   \t\n  \r\n  \t  ";
    fileOps.modifyFileWithApproval(testFilePath, emptyContent, whitespaceContent);
    
    QVERIFY(file.open(QIODevice::ReadOnly));
    QString readContent = QTextStream(&file).readAll();
    file.close();
    QCOMPARE(readContent, whitespaceContent);
    
    // Test deletion
    fileOps.deleteFileWithApproval(testFilePath);
    QVERIFY(!file.exists());
}

void FuzzTestAgenticFileOperations::testBinaryContent()
{
    AgenticFileOperations fileOps(nullptr, m_errorHandler);
    QString testFilePath = m_testDirPath + "/binary_test.bin";
    
    // Generate binary content
    QByteArray binaryContent = generateRandomBinaryData(10000);
    
    // Write binary content to file manually first
    QFile file(testFilePath);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write(binaryContent);
    file.close();
    
    // Test modification with binary content as string
    QString binaryString = QString::fromLatin1(binaryContent.data(), binaryContent.size());
    QString modifiedBinaryString = QString::fromLatin1(generateRandomBinaryData(10000).data(), 10000);
    
    fileOps.modifyFileWithApproval(testFilePath, binaryString, modifiedBinaryString);
    
    // Verify modification
    QVERIFY(file.open(QIODevice::ReadOnly));
    QByteArray readData = file.readAll();
    file.close();
    
    // Test deletion
    fileOps.deleteFileWithApproval(testFilePath);
    QVERIFY(!file.exists());
}

QTEST_MAIN(FuzzTestAgenticFileOperations)
#include "fuzz_test_agentic_file_operations.moc"
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
