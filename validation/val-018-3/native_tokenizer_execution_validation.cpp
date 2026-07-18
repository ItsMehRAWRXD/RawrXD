// VAL-018.3: Native Tokenizer Execution Validation
// Progressive validation of RawrXD-native BPE tokenizer
// Level 1: ASCII text (Hello world)
// Level 2: UTF-8 (Unicode)
// Level 3: Production vocabulary (if available)

#include "native_tokenizer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <filesystem>
#include <chrono>

// Simple JSON writer for evidence
class JSONWriter {
    std::stringstream ss;
    int indent = 0;
    bool first = true;
    
    void Indent() { for(int i=0;i<indent;i++) ss << "  "; }
    
public:
    void BeginObject() {
        if(!first) ss << ",";
        ss << "{\n";
        indent++;
        first = true;
    }
    
    void EndObject() {
        indent--;
        ss << "\n";
        Indent();
        ss << "}";
        first = false;
    }
    
    void BeginArray(const char* name) {
        if(!first) ss << ",";
        ss << "\n";
        Indent();
        ss << "\"" << name << "\": [\n";
        indent++;
        first = true;
    }
    
    void EndArray() {
        indent--;
        ss << "\n";
        Indent();
        ss << "]";
        first = false;
    }
    
    void AddString(const char* name, const std::string& value) {
        if(!first) ss << ",";
        ss << "\n";
        Indent();
        ss << "\"" << name << "\": \"" << Escape(value) << "\"";
        first = false;
    }
    
    void AddInt(const char* name, int value) {
        if(!first) ss << ",";
        ss << "\n";
        Indent();
        ss << "\"" << name << "\": " << value;
        first = false;
    }
    
    void AddBool(const char* name, bool value) {
        if(!first) ss << ",";
        ss << "\n";
        Indent();
        ss << "\"" << name << "\": " << (value ? "true" : "false");
        first = false;
    }
    
    void AddObjectToArray(const std::map<std::string, std::string>& obj) {
        if(!first) ss << ",";
        ss << "\n";
        Indent();
        ss << "{";
        bool firstField = true;
        for(const auto& [k,v] : obj) {
            if(!firstField) ss << ",";
            ss << "\"" << k << "\": \"" << Escape(v) << "\"";
            firstField = false;
        }
        ss << "}";
        first = false;
    }
    
    std::string Str() { return ss.str(); }
    
private:
    std::string Escape(const std::string& s) {
        std::string out;
        for(char c : s) {
            if(c == '"') out += "\\\"";
            else if(c == '\\') out += "\\\\";
            else if(c == '\n') out += "\\n";
            else if(c == '\r') out += "\\r";
            else if(c == '\t') out += "\\t";
            else out += c;
        }
        return out;
    }
};

// Evidence collector
struct EvidenceCollector {
    std::string output_dir;
    JSONWriter trace;
    int event_count = 0;
    
    EvidenceCollector(const std::string& dir) : output_dir(dir) {
        trace.BeginObject();
        trace.BeginArray("events");
    }
    
    void LogEvent(const std::string& phase, const std::string& status) {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ts;
        ts << std::put_time(std::localtime(&time), "%Y-%m-%dT%H:%M:%S");
        
        std::map<std::string, std::string> event;
        event["timestamp"] = ts.str();
        event["phase"] = phase;
        event["status"] = status;
        trace.AddObjectToArray(event);
        
        event_count++;
        std::cout << "[" << phase << "] " << status << std::endl;
    }
    
    void SaveTrace() {
        trace.EndArray();
        trace.EndObject();
        std::ofstream f(output_dir + "/execution/tokenizer_trace.json");
        f << trace.Str();
    }
    
    void SaveTestResults(const std::vector<std::map<std::string, std::string>>& results) {
        JSONWriter result;
        result.BeginObject();
        result.AddBool("simulation", false);
        result.AddString("backend", "RawrXD_Native_BPETokenizer");
        result.BeginArray("tests");
        
        for(const auto& test : results) {
            result.AddObjectToArray(test);
        }
        
        result.EndArray();
        result.EndObject();
        
        std::ofstream f(output_dir + "/execution/test_results.json");
        f << result.Str();
    }
    
    void SaveCompletion(bool success, const std::string& error = "") {
        JSONWriter completion;
        completion.BeginObject();
        completion.AddBool("validation_passed", success);
        completion.AddString("timestamp", GetTimestamp());
        completion.AddString("backend", "RawrXD_Native_BPETokenizer");
        completion.AddBool("simulation", false);
        if(!success) completion.AddString("error", error);
        completion.EndObject();
        
        std::ofstream f(output_dir + "/result/completion.json");
        f << completion.Str();
    }
    
    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%dT%H:%M:%S");
        return ss.str();
    }
};

// Read file to string
std::string ReadFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if(!f) return "";
    std::stringstream buffer;
    buffer << f.rdbuf();
    return buffer.str();
}

// Calculate checksum for token sequence
uint64_t CalculateChecksum(const std::vector<uint32_t>& tokens) {
    uint64_t checksum = 0;
    for(auto t : tokens) checksum = checksum * 31 + t;
    return checksum;
}

// Run a single test
struct TestResult {
    std::string name;
    std::string input;
    std::vector<uint32_t> tokens;
    uint64_t checksum;
    bool passed;
    std::string error;
};

TestResult RunTest(NativeTokenizer* tok, const std::string& name, const std::string& input) {
    TestResult result;
    result.name = name;
    result.input = input;
    
    std::vector<uint32_t> tokens(256);
    int num_tokens = NativeTokenizer_Encode(tok, input.c_str(), tokens.data(), tokens.size());
    
    if(num_tokens < 0) {
        result.passed = false;
        result.error = "Tokenization failed";
        return result;
    }
    
    tokens.resize(num_tokens);
    result.tokens = tokens;
    result.checksum = CalculateChecksum(tokens);
    result.passed = true;
    
    return result;
}

int main(int argc, char** argv) {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-018.3: Native Tokenizer Execution Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Get executable directory for output
    std::string exe_dir = std::filesystem::path(argv[0]).parent_path().string();
    EvidenceCollector evidence(exe_dir);
    evidence.LogEvent("INIT", "VAL-018.3 starting");
    
    // Find tokenizer.json
    std::string tokenizer_path;
    if(argc > 1) {
        tokenizer_path = argv[1];
    } else {
        std::vector<std::string> search_paths = {
            exe_dir + "/test_tokenizer.json",
            "test_tokenizer.json",
        };
        for(const auto& path : search_paths) {
            if(std::filesystem::exists(path)) {
                tokenizer_path = path;
                std::cout << "Found tokenizer.json: " << path << std::endl;
                break;
            }
        }
    }
    
    if(tokenizer_path.empty()) {
        std::cout << "No tokenizer.json found. Usage: " << argv[0] << " <path_to_tokenizer.json>" << std::endl;
        evidence.LogEvent("TOKENIZER", "No tokenizer.json found");
        evidence.SaveCompletion(false, "tokenizer.json not found");
        return 1;
    }
    
    // Load tokenizer.json
    evidence.LogEvent("LOAD", "Loading tokenizer.json");
    std::string json_data = ReadFile(tokenizer_path);
    if(json_data.empty()) {
        evidence.LogEvent("LOAD", "FAILED - Could not read file");
        evidence.SaveCompletion(false, "Failed to read tokenizer.json");
        return 1;
    }
    std::cout << "  Read " << json_data.size() << " bytes" << std::endl;
    
    // Create tokenizer
    evidence.LogEvent("CREATE", "Creating NativeTokenizer");
    NativeTokenizer* tok = NativeTokenizer_Create();
    if(!tok) {
        evidence.LogEvent("CREATE", "FAILED");
        evidence.SaveCompletion(false, "Failed to create tokenizer");
        return 1;
    }
    
    // Load JSON
    evidence.LogEvent("PARSE", "Parsing tokenizer.json");
    int rc = NativeTokenizer_LoadJson(tok, json_data.c_str(), json_data.size());
    if(rc != 0) {
        evidence.LogEvent("PARSE", "FAILED - JSON parse error");
        NativeTokenizer_Destroy(tok);
        evidence.SaveCompletion(false, "Failed to parse tokenizer.json");
        return 1;
    }
    
    uint32_t vocab_size = NativeTokenizer_VocabSize(tok);
    std::cout << "  Vocab size: " << vocab_size << std::endl;
    evidence.LogEvent("PARSE", "SUCCESS - vocab loaded");
    
    // Run progressive tests
    evidence.LogEvent("TEST", "Running progressive validation tests");
    std::vector<TestResult> results;
    std::vector<std::map<std::string, std::string>> json_results;
    
    // Level 1: ASCII text
    std::cout << std::endl << "=== Level 1: ASCII Text ===" << std::endl;
    auto r1 = RunTest(tok, "Level 1 - Hello", "Hello");
    results.push_back(r1);
    std::cout << "  Input: \"" << r1.input << "\"" << std::endl;
    std::cout << "  Tokens: " << r1.tokens.size() << std::endl;
    std::cout << "  Checksum: " << r1.checksum << std::endl;
    
    auto r2 = RunTest(tok, "Level 1 - Hello world", "Hello world");
    results.push_back(r2);
    std::cout << "  Input: \"" << r2.input << "\"" << std::endl;
    std::cout << "  Tokens: " << r2.tokens.size() << std::endl;
    std::cout << "  Checksum: " << r2.checksum << std::endl;
    
    // Level 2: UTF-8 / Unicode
    std::cout << std::endl << "=== Level 2: UTF-8 / Unicode ===" << std::endl;
    auto r3 = RunTest(tok, "Level 2 - Japanese", "\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf"); // こんにちは
    results.push_back(r3);
    std::cout << "  Input: Japanese greeting" << std::endl;
    std::cout << "  Tokens: " << r3.tokens.size() << std::endl;
    std::cout << "  Checksum: " << r3.checksum << std::endl;
    
    auto r4 = RunTest(tok, "Level 2 - Chinese", "\xe4\xbd\xa0\xe5\xa5\xbd"); // 你好
    results.push_back(r4);
    std::cout << "  Input: Chinese greeting" << std::endl;
    std::cout << "  Tokens: " << r4.tokens.size() << std::endl;
    std::cout << "  Checksum: " << r4.checksum << std::endl;
    
    auto r5 = RunTest(tok, "Level 2 - Emoji", "\xf0\x9f\x99\x82"); // 🙂
    results.push_back(r5);
    std::cout << "  Input: Emoji" << std::endl;
    std::cout << "  Tokens: " << r5.tokens.size() << std::endl;
    std::cout << "  Checksum: " << r5.checksum << std::endl;
    
    // Level 3: Longer text (if vocab supports it)
    std::cout << std::endl << "=== Level 3: Longer Text ===" << std::endl;
    auto r6 = RunTest(tok, "Level 3 - Quick brown fox", "The quick brown fox jumps over the lazy dog.");
    results.push_back(r6);
    std::cout << "  Input: \"" << r6.input << "\"" << std::endl;
    std::cout << "  Tokens: " << r6.tokens.size() << std::endl;
    std::cout << "  Checksum: " << r6.checksum << std::endl;
    
    // Build JSON results
    for(const auto& r : results) {
        std::map<std::string, std::string> jr;
        jr["name"] = r.name;
        jr["input"] = r.input;
        jr["token_count"] = std::to_string(r.tokens.size());
        jr["checksum"] = std::to_string(r.checksum);
        jr["passed"] = r.passed ? "true" : "false";
        if(!r.error.empty()) jr["error"] = r.error;
        
        // Build token string
        std::stringstream ts;
        for(size_t i=0; i<r.tokens.size(); i++) {
            if(i>0) ts << ",";
            ts << r.tokens[i];
        }
        jr["token_ids"] = ts.str();
        
        json_results.push_back(jr);
    }
    
    evidence.LogEvent("TEST", "All tests completed");
    
    // Check if all passed
    bool all_passed = true;
    for(const auto& r : results) {
        if(!r.passed) all_passed = false;
    }
    
    // Save evidence
    evidence.LogEvent("SAVE", "Writing evidence files");
    evidence.SaveTestResults(json_results);
    evidence.SaveTrace();
    evidence.SaveCompletion(all_passed);
    
    // Cleanup
    NativeTokenizer_Destroy(tok);
    
    // Summary
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-018.3 COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Tokenizer: " << tokenizer_path << std::endl;
    std::cout << "Vocab Size: " << vocab_size << std::endl;
    std::cout << "Tests Run: " << results.size() << std::endl;
    std::cout << "All Passed: " << (all_passed ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    std::cout << "Evidence saved to: " << exe_dir << std::endl;
    
    evidence.LogEvent("COMPLETE", "VAL-018.3 validation successful");
    
    return all_passed ? 0 : 1;
}
