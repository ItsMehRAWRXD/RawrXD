// VAL-018.3: Native Tokenizer Validation
// Exercises RawrXD-native BPE tokenizer on real tokenizer.json

#include "native_tokenizer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <filesystem>

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
    
    void SaveTokenizationResult(const std::string& input, 
                                const std::vector<uint32_t>& tokens,
                                uint32_t vocab_size) {
        JSONWriter result;
        result.BeginObject();
        result.AddString("input_text", input);
        result.AddInt("token_count", (int)tokens.size());
        result.AddInt("vocab_size", (int)vocab_size);
        result.AddBool("simulation", false);
        
        // Build token string
        std::stringstream tokenStr;
        for(size_t i=0; i<tokens.size(); i++) {
            if(i>0) tokenStr << ",";
            tokenStr << tokens[i];
        }
        result.AddString("token_ids", tokenStr.str());
        
        // Calculate simple checksum
        uint64_t checksum = 0;
        for(auto t : tokens) checksum = checksum * 31 + t;
        result.AddString("checksum", std::to_string(checksum));
        
        result.EndObject();
        
        std::ofstream f(output_dir + "/execution/tokenization_result.json");
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

int main(int argc, char** argv) {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-018.3: Native Tokenizer Validation" << std::endl;
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
            "f:/OllamaModels/tokenizer.json",
            "d:/models/tokenizer.json",
            "f:/OllamaModels/phi3/tokenizer.json",
            "validation/val-018-3/test_tokenizer.json",
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
    
    // Step 1: Load tokenizer.json
    evidence.LogEvent("LOAD", "Loading tokenizer.json");
    std::string json_data = ReadFile(tokenizer_path);
    if(json_data.empty()) {
        evidence.LogEvent("LOAD", "FAILED - Could not read file");
        evidence.SaveCompletion(false, "Failed to read tokenizer.json");
        return 1;
    }
    std::cout << "  Read " << json_data.size() << " bytes" << std::endl;
    
    // Step 2: Create tokenizer
    evidence.LogEvent("CREATE", "Creating NativeTokenizer");
    NativeTokenizer* tok = NativeTokenizer_Create();
    if(!tok) {
        evidence.LogEvent("CREATE", "FAILED");
        evidence.SaveCompletion(false, "Failed to create tokenizer");
        return 1;
    }
    
    // Step 3: Load JSON
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
    
    // Step 4: Encode test prompt
    evidence.LogEvent("ENCODE", "Tokenizing input text");
    const char* test_input = "Hello";
    std::vector<uint32_t> tokens(256);
    int num_tokens = NativeTokenizer_Encode(tok, test_input, tokens.data(), tokens.size());
    
    if(num_tokens < 0) {
        evidence.LogEvent("ENCODE", "FAILED");
        NativeTokenizer_Destroy(tok);
        evidence.SaveCompletion(false, "Tokenization failed");
        return 1;
    }
    
    tokens.resize(num_tokens);
    std::cout << "  Input: \"" << test_input << "\"" << std::endl;
    std::cout << "  Tokens: ";
    for(auto t : tokens) std::cout << t << " ";
    std::cout << std::endl;
    evidence.LogEvent("ENCODE", "SUCCESS - " + std::to_string(num_tokens) + " tokens");
    
    // Step 5: Save evidence
    evidence.LogEvent("SAVE", "Writing evidence files");
    evidence.SaveTokenizationResult(test_input, tokens, vocab_size);
    evidence.SaveTrace();
    evidence.SaveCompletion(true);
    
    // Cleanup
    NativeTokenizer_Destroy(tok);
    
    // Summary
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-018.3 COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Tokenizer: " << tokenizer_path << std::endl;
    std::cout << "Vocab Size: " << vocab_size << std::endl;
    std::cout << "Input: \"" << test_input << "\"" << std::endl;
    std::cout << "Output Tokens: " << num_tokens << std::endl;
    std::cout << std::endl;
    std::cout << "Evidence saved to: validation/val-018-3/" << std::endl;
    
    evidence.LogEvent("COMPLETE", "VAL-018.3 validation successful");
    
    return 0;
}
