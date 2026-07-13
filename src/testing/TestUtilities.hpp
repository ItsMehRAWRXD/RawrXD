/**
 * TestUtilities.hpp
 *
 * Phase I Batch 5/5: Test Utilities & Helpers
 *
 * Utility functions, test data generators, assertion helpers,
 * and common testing patterns.
 */

#pragma once

#include "UnitTestFramework.hpp"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <random>
#include <chrono>
#include <fstream>
#include <sstream>

namespace Testing {

// ============================================================================
// Random Generators
// ============================================================================

/**
 * Random data generators for tests.
 */
class RandomGenerator {
public:
    RandomGenerator();
    explicit RandomGenerator(uint32_t seed);
    
    // Integers
    int32_t Int32();
    int32_t Int32(int32_t min, int32_t max);
    int64_t Int64();
    int64_t Int64(int64_t min, int64_t max);
    
    // Floating point
    float Float();
    float Float(float min, float max);
    double Double();
    double Double(double min, double max);
    
    // Strings
    std::string String(uint32_t length);
    std::string String(uint32_t minLength, uint32_t maxLength);
    std::string AlphaString(uint32_t length);
    std::string AlphaNumericString(uint32_t length);
    std::string HexString(uint32_t length);
    std::string Base64String(uint32_t length);
    
    // Text
    std::string Word();
    std::string Sentence(uint32_t wordCount = 5);
    std::string Paragraph(uint32_t sentenceCount = 3);
    std::string LoremIpsum(uint32_t wordCount);
    
    // Identifiers
    std::string Uuid();
    std::string Guid();
    std::string ObjectId();
    
    // Personal data
    std::string FirstName();
    std::string LastName();
    std::string FullName();
    std::string Email();
    std::string PhoneNumber();
    std::string Address();
    std::string City();
    std::string State();
    std::string ZipCode();
    std::string Country();
    
    // Internet
    std::string Url();
    std::string Domain();
    std::string IpAddress();
    std::string MacAddress();
    std::string UserAgent();
    
    // Dates and times
    std::chrono::system_clock::time_point DateTime();
    std::chrono::system_clock::time_point DateTime(
        const std::chrono::system_clock::time_point& min,
        const std::chrono::system_clock::time_point& max);
    std::string IsoDateTime();
    std::string DateString(const std::string& format = "%Y-%m-%d");
    
    // Collections
    template<typename T>
    T Choice(const std::vector<T>& choices);
    
    template<typename T>
    std::vector<T> Sample(const std::vector<T>& population, uint32_t count);
    
    template<typename T>
    void Shuffle(std::vector<T>& items);
    
    // Boolean
    bool Bool();
    bool Bool(double probability);
    
    // Bytes
    std::vector<uint8_t> Bytes(uint32_t count);
    
    // Seed
    void Seed(uint32_t seed);
    
private:
    std::mt19937 rng_;
    
    static const std::vector<std::string> firstNames_;
    static const std::vector<std::string> lastNames_;
    static const std::vector<std::string> loremWords_;
    static const std::vector<std::string> cities_;
    static const std::vector<std::string> countries_;
    static const std::vector<std::string> domains_;
    static const std::vector<std::string> userAgents_;
};

// ============================================================================
// File Utilities
// ============================================================================

/**
 * File utilities for tests.
 */
class FileUtils {
public:
    // Path operations
    static std::string JoinPath(const std::string& a, const std::string& b);
    static std::string JoinPath(const std::vector<std::string>& parts);
    static std::string GetTempDirectory();
    static std::string GetCurrentDirectory();
    static std::string GetAbsolutePath(const std::string& path);
    static std::string GetFileName(const std::string& path);
    static std::string GetDirectoryName(const std::string& path);
    static std::string GetExtension(const std::string& path);
    static std::string ChangeExtension(const std::string& path, const std::string& extension);
    
    // File operations
    static bool Exists(const std::string& path);
    static bool IsFile(const std::string& path);
    static bool IsDirectory(const std::string& path);
    static uint64_t GetSize(const std::string& path);
    static std::chrono::system_clock::time_point GetLastModified(const std::string& path);
    
    static bool CreateDirectory(const std::string& path);
    static bool CreateDirectories(const std::string& path);
    static bool Delete(const std::string& path);
    static bool DeleteRecursive(const std::string& path);
    static bool Copy(const std::string& source, const std::string& destination);
    static bool Move(const std::string& source, const std::string& destination);
    
    // File content
    static std::string ReadAllText(const std::string& path);
    static std::vector<std::string> ReadAllLines(const std::string& path);
    static std::vector<uint8_t> ReadAllBytes(const std::string& path);
    static bool WriteAllText(const std::string& path, const std::string& content);
    static bool WriteAllLines(const std::string& path, const std::vector<std::string>& lines);
    static bool WriteAllBytes(const std::string& path, const std::vector<uint8_t>& bytes);
    static bool AppendText(const std::string& path, const std::string& content);
    
    // Directory operations
    static std::vector<std::string> GetFiles(const std::string& path);
    static std::vector<std::string> GetFiles(const std::string& path, const std::string& pattern);
    static std::vector<std::string> GetDirectories(const std::string& path);
    static std::vector<std::string> GetEntries(const std::string& path);
    
    // Temporary files
    static std::string CreateTempFile(const std::string& prefix = "test");
    static std::string CreateTempFile(const std::string& prefix, const std::string& extension);
    static std::string CreateTempDirectory(const std::string& prefix = "test");
    static void CleanUpTempFiles();
    
    // Comparison
    static bool AreEqual(const std::string& file1, const std::string& file2);
    static std::vector<std::string> FindDifferences(const std::string& file1, const std::string& file2);
};

// ============================================================================
// String Utilities
// ============================================================================

/**
 * String utilities for tests.
 */
class StringUtils {
public:
    // Case
    static std::string ToUpper(const std::string& str);
    static std::string ToLower(const std::string& str);
    static bool EqualsIgnoreCase(const std::string& a, const std::string& b);
    
    // Trimming
    static std::string Trim(const std::string& str);
    static std::string TrimStart(const std::string& str);
    static std::string TrimEnd(const std::string& str);
    
    // Split/Join
    static std::vector<std::string> Split(const std::string& str, char delimiter);
    static std::vector<std::string> Split(const std::string& str, const std::string& delimiter);
    static std::string Join(const std::vector<std::string>& parts, const std::string& delimiter);
    
    // Contains
    static bool Contains(const std::string& str, const std::string& substring);
    static bool ContainsIgnoreCase(const std::string& str, const std::string& substring);
    static bool StartsWith(const std::string& str, const std::string& prefix);
    static bool EndsWith(const std::string& str, const std::string& suffix);
    
    // Replace
    static std::string Replace(const std::string& str, const std::string& oldValue,
                                  const std::string& newValue);
    static std::string ReplaceAll(const std::string& str, const std::string& oldValue,
                                   const std::string& newValue);
    
    // Padding
    static std::string PadLeft(const std::string& str, uint32_t length, char padding = ' ');
    static std::string PadRight(const std::string& str, uint32_t length, char padding = ' ');
    
    // Encoding
    static std::string Base64Encode(const std::string& str);
    static std::string Base64Decode(const std::string& str);
    static std::string UrlEncode(const std::string& str);
    static std::string UrlDecode(const std::string& str);
    static std::string HtmlEncode(const std::string& str);
    static std::string HtmlDecode(const std::string& str);
    
    // Formatting
    static std::string Format(const std::string& format, ...);
    template<typename... Args>
    static std::string Format(const std::string& format, Args... args);
    
    // Validation
    static bool IsEmpty(const std::string& str);
    static bool IsWhitespace(const std::string& str);
    static bool IsNumeric(const std::string& str);
    static bool IsAlpha(const std::string& str);
    static bool IsAlphaNumeric(const std::string& str);
    
    // Comparison
    static int Compare(const std::string& a, const std::string& b);
    static int CompareIgnoreCase(const std::string& a, const std::string& b);
    
    // Distance
    static uint32_t LevenshteinDistance(const std::string& a, const std::string& b);
    static double Similarity(const std::string& a, const std::string& b);
};

// ============================================================================
// Collection Utilities
// ============================================================================

/**
 * Collection utilities for tests.
 */
template<typename T>
class CollectionUtils {
public:
    // Comparison
    static bool AreEqual(const std::vector<T>& a, const std::vector<T>& b);
    static bool AreEquivalent(const std::vector<T>& a, const std::vector<T>& b);
    static bool Contains(const std::vector<T>& container, const T& item);
    static bool ContainsAll(const std::vector<T>& container, const std::vector<T>& items);
    static bool ContainsAny(const std::vector<T>& container, const std::vector<T>& items);
    
    // Operations
    static std::vector<T> Distinct(const std::vector<T>& items);
    static std::vector<T> Intersect(const std::vector<T>& a, const std::vector<T>& b);
    static std::vector<T> Union(const std::vector<T>& a, const std::vector<T>& b);
    static std::vector<T> Except(const std::vector<T>& a, const std::vector<T>& b);
    
    // Transformation
    template<typename U>
    static std::vector<U> Map(const std::vector<T>& items, std::function<U(const T&)> mapper);
    
    static std::vector<T> Filter(const std::vector<T>& items, std::function<bool(const T&)> predicate);
    
    template<typename U>
    static U Reduce(const std::vector<T>& items, U initial, std::function<U(U, const T&)> reducer);
    
    // Sorting
    static std::vector<T> Sort(const std::vector<T>& items);
    static std::vector<T> Sort(const std::vector<T>& items, std::function<bool(const T&, const T&)> comparer);
    static std::vector<T> Reverse(const std::vector<T>& items);
    
    // Searching
    static std::optional<T> First(const std::vector<T>& items, std::function<bool(const T&)> predicate);
    static std::optional<T> FirstOrDefault(const std::vector<T>& items);
    static std::optional<T> Last(const std::vector<T>& items, std::function<bool(const T&)> predicate);
    static std::optional<T> LastOrDefault(const std::vector<T>& items);
    static int IndexOf(const std::vector<T>& items, const T& item);
    static int IndexOf(const std::vector<T>& items, std::function<bool(const T&)> predicate);
    
    // Statistics
    static T Min(const std::vector<T>& items);
    static T Max(const std::vector<T>& items);
    static T Sum(const std::vector<T>& items);
    static double Average(const std::vector<T>& items);
};

// ============================================================================
// Time Utilities
// ============================================================================

/**
 * Time utilities for tests.
 */
class TimeUtils {
public:
    // Current time
    static std::chrono::system_clock::time_point Now();
    static uint64_t NowMs();
    static uint64_t NowNs();
    
    // Formatting
    static std::string Format(const std::chrono::system_clock::time_point& time,
                               const std::string& format = "%Y-%m-%d %H:%M:%S");
    static std::string FormatIso8601(const std::chrono::system_clock::time_point& time);
    static std::string FormatRfc3339(const std::chrono::system_clock::time_point& time);
    static std::string FormatDuration(std::chrono::milliseconds duration);
    static std::string FormatDuration(std::chrono::nanoseconds duration);
    
    // Parsing
    static std::optional<std::chrono::system_clock::time_point> Parse(
        const std::string& str, const std::string& format);
    static std::optional<std::chrono::system_clock::time_point> ParseIso8601(
        const std::string& str);
    
    // Arithmetic
    static std::chrono::system_clock::time_point AddSeconds(
        const std::chrono::system_clock::time_point& time, int64_t seconds);
    static std::chrono::system_clock::time_point AddMinutes(
        const std::chrono::system_clock::time_point& time, int64_t minutes);
    static std::chrono::system_clock::time_point AddHours(
        const std::chrono::system_clock::time_point& time, int64_t hours);
    static std::chrono::system_clock::time_point AddDays(
        const std::chrono::system_clock::time_point& time, int64_t days);
    
    // Comparison
    static int64_t DiffSeconds(const std::chrono::system_clock::time_point& a,
                                const std::chrono::system_clock::time_point& b);
    static int64_t DiffMilliseconds(const std::chrono::system_clock::time_point& a,
                                     const std::chrono::system_clock::time_point& b);
    
    // Rounding
    static std::chrono::system_clock::time_point TruncateToSeconds(
        const std::chrono::system_clock::time_point& time);
    static std::chrono::system_clock::time_point TruncateToMinutes(
        const std::chrono::system_clock::time_point& time);
    static std::chrono::system_clock::time_point TruncateToHours(
        const std::chrono::system_clock::time_point& time);
    static std::chrono::system_clock::time_point TruncateToDays(
        const std::chrono::system_clock::time_point& time);
    
    // Timer
    class Timer {
    public:
        Timer();
        void Start();
        void Stop();
        void Reset();
        std::chrono::nanoseconds Elapsed() const;
        std::chrono::milliseconds ElapsedMs() const;
        double ElapsedSeconds() const;
        
    private:
        std::chrono::high_resolution_clock::time_point startTime_;
        std::chrono::high_resolution_clock::time_point endTime_;
        bool running_;
    };
    
    // Scoped timer
    class ScopedTimer {
    public:
        explicit ScopedTimer(std::chrono::nanoseconds& result);
        ~ScopedTimer();
        
    private:
        std::chrono::high_resolution_clock::time_point startTime_;
        std::chrono::nanoseconds& result_;
    };
};

// ============================================================================
// JSON Utilities
// ============================================================================

/**
 * JSON utilities for tests.
 */
class JsonUtils {
public:
    // Validation
    static bool IsValid(const std::string& json);
    static std::string GetValidationError(const std::string& json);
    
    // Comparison
    static bool AreEqual(const std::string& json1, const std::string& json2);
    static bool AreEquivalent(const std::string& json1, const std::string& json2);
    static std::vector<std::string> GetDifferences(const std::string& json1,
                                                       const std::string& json2);
    
    // Normalization
    static std::string Normalize(const std::string& json);
    static std::string Minify(const std::string& json);
    static std::string Prettify(const std::string& json, uint32_t indent = 2);
    
    // Path-based access
    static bool HasPath(const std::string& json, const std::string& path);
    static std::string GetValue(const std::string& json, const std::string& path);
    static std::vector<std::string> GetArray(const std::string& json, const std::string& path);
    static std::map<std::string, std::string> GetObject(const std::string& json,
                                                          const std::string& path);
    
    // Schema validation
    static bool ValidateSchema(const std::string& json, const std::string& schema);
    static std::vector<std::string> GetSchemaErrors(const std::string& json,
                                                     const std::string& schema);
    
    // Building
    class Builder {
    public:
        Builder();
        Builder& BeginObject();
        Builder& EndObject();
        Builder& BeginArray();
        Builder& EndArray();
        Builder& Property(const std::string& name);
        Builder& Value(const std::string& value);
        Builder& Value(int value);
        Builder& Value(double value);
        Builder& Value(bool value);
        Builder& Null();
        std::string Build();
        
    private:
        std::ostringstream oss_;
        std::vector<bool> inArray_;
        bool first_;
    };
};

// ============================================================================
// XML Utilities
// ============================================================================

/**
 * XML utilities for tests.
 */
class XmlUtils {
public:
    // Validation
    static bool IsValid(const std::string& xml);
    static bool IsWellFormed(const std::string& xml);
    
    // Comparison
    static bool AreEqual(const std::string& xml1, const std::string& xml2);
    static bool AreEquivalent(const std::string& xml1, const std::string& xml2);
    
    // Normalization
    static std::string Normalize(const std::string& xml);
    static std::string Minify(const std::string& xml);
    static std::string Prettify(const std::string& xml, uint32_t indent = 2);
    
    // XPath
    static std::string SelectSingle(const std::string& xml, const std::string& xpath);
    static std::vector<std::string> Select(const std::string& xml, const std::string& xpath);
    static bool Exists(const std::string& xml, const std::string& xpath);
    
    // Schema validation
    static bool ValidateDtd(const std::string& xml, const std::string& dtd);
    static bool ValidateXsd(const std::string& xml, const std::string& xsd);
    static bool ValidateRelaxNg(const std::string& xml, const std::string& rng);
};

// ============================================================================
// Network Utilities
// ============================================================================

/**
 * Network utilities for tests.
 */
class NetworkUtils {
public:
    // Host resolution
    static std::string ResolveHost(const std::string& hostname);
    static std::vector<std::string> ResolveHosts(const std::string& hostname);
    
    // Port checking
    static bool IsPortOpen(const std::string& host, uint16_t port, uint64_t timeoutMs = 5000);
    static std::vector<uint16_t> ScanPorts(const std::string& host,
                                             const std::vector<uint16_t>& ports);
    
    // HTTP
    struct HttpResponse {
        int statusCode;
        std::map<std::string, std::string> headers;
        std::string body;
        uint64_t responseTimeMs;
    };
    
    static HttpResponse HttpGet(const std::string& url,
                                 const std::map<std::string, std::string>& headers = {});
    static HttpResponse HttpPost(const std::string& url, const std::string& body,
                                  const std::map<std::string, std::string>& headers = {});
    static HttpResponse HttpPut(const std::string& url, const std::string& body,
                                 const std::map<std::string, std::string>& headers = {});
    static HttpResponse HttpDelete(const std::string& url,
                                    const std::map<std::string, std::string>& headers = {});
    
    // TCP
    static bool TcpConnect(const std::string& host, uint16_t port, uint64_t timeoutMs = 5000);
    static std::string TcpSendReceive(const std::string& host, uint16_t port,
                                       const std::string& data, uint64_t timeoutMs = 5000);
    
    // UDP
    static bool UdpSend(const std::string& host, uint16_t port, const std::string& data);
    static std::string UdpReceive(uint16_t port, uint64_t timeoutMs = 5000);
    
    // WebSocket
    static bool WebSocketConnect(const std::string& url);
    static bool WebSocketSend(const std::string& message);
    static std::string WebSocketReceive(uint64_t timeoutMs = 5000);
    static void WebSocketClose();
};

// ============================================================================
// Process Utilities
// ============================================================================

/**
 * Process utilities for tests.
 */
class ProcessUtils {
public:
    struct ProcessResult {
        int exitCode;
        std::string stdout;
        std::string stderr;
        uint64_t durationMs;
    };
    
    // Execution
    static ProcessResult Run(const std::string& command);
    static ProcessResult Run(const std::string& command, const std::vector<std::string>& args);
    static ProcessResult Run(const std::string& command, const std::string& workingDir);
    static ProcessResult Run(const std::string& command, const std::map<std::string, std::string>& env);
    
    // Async execution
    static int RunAsync(const std::string& command);
    static bool IsRunning(int processId);
    static bool WaitForExit(int processId, uint64_t timeoutMs);
    static bool Kill(int processId);
    static ProcessResult GetResult(int processId);
    
    // Process info
    static int GetCurrentProcessId();
    static std::vector<int> GetChildProcesses(int parentId);
    static uint64_t GetMemoryUsage(int processId);
    static double GetCpuUsage(int processId);
    
    // Shell
    static std::string Which(const std::string& command);
    static bool CommandExists(const std::string& command);
};

// ============================================================================
// Assertion Helpers
// ============================================================================

/**
 * Additional assertion helpers.
 */
class Assert {
public:
    // File assertions
    static void FileExists(const std::string& path);
    static void FileNotExists(const std::string& path);
    static void FileContains(const std::string& path, const std::string& content);
    static void FilesEqual(const std::string& expected, const std::string& actual);
    
    // String assertions
    static void Contains(const std::string& str, const std::string& substring);
    static void StartsWith(const std::string& str, const std::string& prefix);
    static void EndsWith(const std::string& str, const std::string& suffix);
    static void Matches(const std::string& str, const std::string& pattern);
    static void IsEmpty(const std::string& str);
    static void IsNotEmpty(const std::string& str);
    
    // Collection assertions
    template<typename T>
    static void Contains(const std::vector<T>& container, const T& item);
    template<typename T>
    static void DoesNotContain(const std::vector<T>& container, const T& item);
    template<typename T>
    static void AreEqual(const std::vector<T>& expected, const std::vector<T>& actual);
    template<typename T>
    static void AreEquivalent(const std::vector<T>& expected, const std::vector<T>& actual);
    template<typename T>
    static void IsEmpty(const std::vector<T>& container);
    template<typename T>
    static void IsNotEmpty(const std::vector<T>& container);
    
    // Exception assertions
    template<typename ExceptionType, typename Func>
    static void Throws(Func func);
    template<typename Func>
    static void Throws(Func func, const std::string& messageContains);
    template<typename Func>
    static void DoesNotThrow(Func func);
    
    // Type assertions
    template<typename T, typename U>
    static void IsInstanceOf(const U& obj);
    
    // Range assertions
    template<typename T>
    static void InRange(const T& value, const T& min, const T& max);
    template<typename T>
    static void NotInRange(const T& value, const T& min, const T& max);
    
    // JSON assertions
    static void JsonEqual(const std::string& expected, const std::string& actual);
    static void JsonEquivalent(const std::string& expected, const std::string& actual);
    static void JsonContains(const std::string& json, const std::string& path, const std::string& expected);
    
    // XML assertions
    static void XmlEqual(const std::string& expected, const std::string& actual);
    static void XmlEquivalent(const std::string& expected, const std::string& actual);
    static void XmlValid(const std::string& xml);
    
    // Time assertions
    static void WithinDuration(const std::chrono::system_clock::time_point& expected,
                                const std::chrono::system_clock::time_point& actual,
                                std::chrono::milliseconds tolerance);
    
    // Performance assertions
    static void CompletesWithin(std::function<void()> action, std::chrono::milliseconds maxDuration);
};

// ============================================================================
// Test Guard
// ============================================================================

/**
 * RAII guard for test resources.
 */
template<typename T>
class TestGuard {
public:
    explicit TestGuard(T* resource, std::function<void(T*)> cleanup)
        : resource_(resource), cleanup_(cleanup), dismissed_(false) {}
    
    ~TestGuard() {
        if (!dismissed_ && resource_) {
            cleanup_(resource_);
        }
    }
    
    void Dismiss() { dismissed_ = true; }
    T* Get() { return resource_; }
    
private:
    T* resource_;
    std::function<void(T*)> cleanup_;
    bool dismissed_;
};

// ============================================================================
// Scoped Environment
// ============================================================================

/**
 * Temporarily modify environment variables.
 */
class ScopedEnvironment {
public:
    explicit ScopedEnvironment(const std::map<std::string, std::string>& variables);
    ~ScopedEnvironment();
    
    void Set(const std::string& name, const std::string& value);
    void Unset(const std::string& name);
    void Restore(const std::string& name);
    void RestoreAll();
    
private:
    std::map<std::string, std::string> originalValues_;
    std::set<std::string> modifiedVariables_;
};

// ============================================================================
// Scoped Directory
// ============================================================================

/**
 * Temporary directory for tests.
 */
class ScopedDirectory {
public:
    explicit ScopedDirectory(const std::string& prefix = "test");
    ~ScopedDirectory();
    
    std::string GetPath() const { return path_; }
    std::string CreateFile(const std::string& name, const std::string& content = "");
    std::string CreateDirectory(const std::string& name);
    
    void Keep();  // Don't delete on destruction
    
private:
    std::string path_;
    bool keep_;
};

// ============================================================================
// Scoped Working Directory
// ============================================================================

/**
 * Temporarily change working directory.
 */
class ScopedWorkingDirectory {
public:
    explicit ScopedWorkingDirectory(const std::string& path);
    ~ScopedWorkingDirectory();
    
private:
    std::string originalPath_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Skip a test with reason.
 */
void Skip(const std::string& reason);

/**
 * Mark test as inconclusive.
 */
void Inconclusive(const std::string& reason);

/**
 * Log a message during test execution.
 */
void Log(const std::string& message);
void LogInfo(const std::string& message);
void LogWarning(const std::string& message);
void LogError(const std::string& message);

/**
 * Write test output.
 */
void WriteLine(const std::string& line);
void Write(const std::string& text);

/**
 * Get test context information.
 */
std::string GetTestName();
std::string GetTestSuite();
std::string GetTestFile();
uint32_t GetTestLine();

} // namespace Testing
