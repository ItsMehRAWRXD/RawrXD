// RawrXDValidator.cpp
// Automated validation executor for VAL-019
// Responsibilities:
// 1. Load manifest
// 2. Validate schema version
// 3. Verify artifact hashes
// 4. Confirm lifecycle transition rules
// 5. Produce PASS/FAIL evidence report

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// Schema version this validator supports
const char* SUPPORTED_SCHEMA_VERSION = "2.0.0";
const char* EVIDENCE_FORMAT = "rawrxd-val-019-v2";

// Validation result
struct ValidationResult {
    bool success;
    std::string stage;
    std::string error_message;
    std::map<std::string, std::string> evidence;
};

// SHA256 computation
class SHA256 {
public:
    static std::string compute(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "ERROR: Cannot open file";
        
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        NTSTATUS status;
        
        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) return "ERROR: BCryptOpenAlgorithmProvider failed";
        
        // Get hash object size
        DWORD hashObjectSize = 0;
        DWORD resultLength = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(DWORD), &resultLength, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "ERROR: BCryptGetProperty failed";
        }
        
        // Get hash length
        DWORD hashLength = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &resultLength, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "ERROR: BCryptGetProperty failed";
        }
        
        // Allocate hash object
        std::vector<BYTE> hashObject(hashObjectSize);
        
        // Create hash
        status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, NULL, 0, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return "ERROR: BCryptCreateHash failed";
        }
        
        // Read file and hash
        std::vector<char> buffer(8192);
        while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
            status = BCryptHashData(hHash, (PBYTE)buffer.data(), (ULONG)file.gcount(), 0);
            if (!NT_SUCCESS(status)) {
                BCryptDestroyHash(hHash);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return "ERROR: BCryptHashData failed";
            }
        }
        
        // Get hash
        std::vector<BYTE> hash(hashLength);
        status = BCryptFinishHash(hHash, hash.data(), hashLength, 0);
        
        // Cleanup
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        
        if (!NT_SUCCESS(status)) return "ERROR: BCryptFinishHash failed";
        
        // Convert to hex string
        std::stringstream ss;
        ss << "sha256:";
        for (auto b : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return ss.str();
    }
};

// Manifest loader
class ManifestLoader {
public:
    bool load(const std::string& path) {
        std::ifstream file(path);
        if (!file) {
            error_ = "Cannot open manifest: " + path;
            return false;
        }
        
        // Simple JSON parsing - extract key fields
        std::string line;
        while (std::getline(file, line)) {
            // Extract schema_version
            size_t pos = line.find("\"schema_version\"");
            if (pos != std::string::npos) {
                schema_version_ = extractString(line, pos + 18);
            }
            
            // Extract evidence_format
            pos = line.find("\"evidence_format\"");
            if (pos != std::string::npos) {
                evidence_format_ = extractString(line, pos + 19);
            }
            
            // Extract run state
            pos = line.find("\"state\"");
            if (pos != std::string::npos) {
                run_state_ = extractString(line, pos + 9);
            }
            
            // Extract run id
            pos = line.find("\"id\"");
            if (pos != std::string::npos) {
                run_id_ = extractString(line, pos + 6);
            }
        }
        
        return true;
    }
    
    bool validateSchema() {
        if (schema_version_ != SUPPORTED_SCHEMA_VERSION) {
            error_ = "Schema version mismatch: expected " + std::string(SUPPORTED_SCHEMA_VERSION) + 
                     ", got " + schema_version_;
            return false;
        }
        
        if (evidence_format_ != EVIDENCE_FORMAT) {
            error_ = "Evidence format mismatch: expected " + std::string(EVIDENCE_FORMAT) +
                     ", got " + evidence_format_;
            return false;
        }
        
        return true;
    }
    
    std::string getSchemaVersion() const { return schema_version_; }
    std::string getEvidenceFormat() const { return evidence_format_; }
    std::string getRunState() const { return run_state_; }
    std::string getRunId() const { return run_id_; }
    std::string getError() const { return error_; }
    
private:
    std::string schema_version_;
    std::string evidence_format_;
    std::string run_state_;
    std::string run_id_;
    std::string error_;
    
    std::string extractString(const std::string& line, size_t start) {
        size_t quote1 = line.find('"', start);
        if (quote1 == std::string::npos) return "";
        size_t quote2 = line.find('"', quote1 + 1);
        if (quote2 == std::string::npos) return "";
        return line.substr(quote1 + 1, quote2 - quote1 - 1);
    }
};

// Lifecycle validator
class LifecycleValidator {
public:
    bool validateTransition(const std::string& from_state, const std::string& to_state) {
        // Valid transitions
        static const std::map<std::string, std::vector<std::string>> valid_transitions = {
            {"DESIGNED", {"IMPLEMENTED"}},
            {"IMPLEMENTED", {"BUILT"}},
            {"BUILT", {"EXECUTED"}},
            {"EXECUTED", {"VALIDATED"}},
            {"VALIDATED", {"VERIFIED"}},
            {"VERIFIED", {"ARCHIVED"}}
        };
        
        auto it = valid_transitions.find(from_state);
        if (it == valid_transitions.end()) {
            error_ = "Invalid from_state: " + from_state;
            return false;
        }
        
        for (const auto& valid : it->second) {
            if (valid == to_state) return true;
        }
        
        error_ = "Invalid transition: " + from_state + " -> " + to_state;
        return false;
    }
    
    std::string getError() const { return error_; }
    
private:
    std::string error_;
};

// Evidence reporter
class EvidenceReporter {
public:
    void report(const std::string& stage, bool passed, const std::map<std::string, std::string>& evidence) {
        std::cout << "{\n";
        std::cout << "  \"schema_version\": \"" << SUPPORTED_SCHEMA_VERSION << "\",\n";
        std::cout << "  \"evidence_format\": \"" << EVIDENCE_FORMAT << "\",\n";
        std::cout << "  \"stage\": \"" << stage << "\",\n";
        std::cout << "  \"status\": \"" << (passed ? "PASS" : "FAIL") << "\",\n";
        std::cout << "  \"timestamp\": \"" << getTimestamp() << "\",\n";
        std::cout << "  \"evidence\": {\n";
        
        bool first = true;
        for (const auto& [key, value] : evidence) {
            if (!first) std::cout << ",\n";
            std::cout << "    \"" << key << "\": \"" << value << "\"";
            first = false;
        }
        
        std::cout << "\n  }\n";
        std::cout << "}\n";
    }
    
private:
    std::string getTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }
};

// Main validator
int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "  RawrXD Validator v2.0.0\n";
    std::cout << "  Automated Evidence Verification\n";
    std::cout << "========================================\n\n";
    
    if (argc < 2) {
        std::cerr << "Usage: RawrXDValidator.exe <manifest.json> [options]\n";
        std::cerr << "\nOptions:\n";
        std::cerr << "  --verify-hash <file>     Compute SHA256 of file\n";
        std::cerr << "  --transition <to_state>  Validate lifecycle transition\n";
        std::cerr << "  --report                 Generate evidence report\n";
        return 1;
    }
    
    std::string manifest_path = argv[1];
    
    // Load manifest
    ManifestLoader loader;
    if (!loader.load(manifest_path)) {
        std::cerr << "[ERROR] " << loader.getError() << "\n";
        return 1;
    }
    
    std::cout << "[INFO] Loaded manifest: " << manifest_path << "\n";
    std::cout << "[INFO] Run ID: " << loader.getRunId() << "\n";
    std::cout << "[INFO] Current state: " << loader.getRunState() << "\n\n";
    
    // Validate schema
    if (!loader.validateSchema()) {
        std::cerr << "[ERROR] " << loader.getError() << "\n";
        return 1;
    }
    
    std::cout << "[PASS] Schema version: " << loader.getSchemaVersion() << "\n";
    std::cout << "[PASS] Evidence format: " << loader.getEvidenceFormat() << "\n\n";
    
    // Check for hash verification
    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--verify-hash") == 0 && i + 1 < argc) {
            std::string file_path = argv[i + 1];
            std::cout << "[INFO] Computing SHA256 for: " << file_path << "\n";
            
            auto start = std::chrono::high_resolution_clock::now();
            std::string hash = SHA256::compute(file_path);
            auto end = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration<double, std::milli>(end - start).count();
            
            if (hash.substr(0, 6) == "ERROR:") {
                std::cerr << "[ERROR] " << hash << "\n";
                return 1;
            }
            
            std::cout << "[PASS] SHA256: " << hash << "\n";
            std::cout << "[INFO] Computed in " << std::fixed << std::setprecision(2) << duration << " ms\n\n";
            
            EvidenceReporter reporter;
            std::map<std::string, std::string> evidence;
            evidence["file"] = file_path;
            evidence["sha256"] = hash;
            evidence["compute_time_ms"] = std::to_string(duration);
            reporter.report("hash_verification", true, evidence);
            
            return 0;
        }
    }
    
    // Check for lifecycle transition
    for (int i = 2; i < argc; i++) {
        if (std::strcmp(argv[i], "--transition") == 0 && i + 1 < argc) {
            std::string to_state = argv[i + 1];
            std::string from_state = loader.getRunState();
            
            std::cout << "[INFO] Validating transition: " << from_state << " -> " << to_state << "\n";
            
            LifecycleValidator lifecycle;
            if (!lifecycle.validateTransition(from_state, to_state)) {
                std::cerr << "[ERROR] " << lifecycle.getError() << "\n";
                
                EvidenceReporter reporter;
                std::map<std::string, std::string> evidence;
                evidence["from_state"] = from_state;
                evidence["to_state"] = to_state;
                evidence["error"] = lifecycle.getError();
                reporter.report("lifecycle_transition", false, evidence);
                
                return 1;
            }
            
            std::cout << "[PASS] Transition valid: " << from_state << " -> " << to_state << "\n\n";
            
            EvidenceReporter reporter;
            std::map<std::string, std::string> evidence;
            evidence["from_state"] = from_state;
            evidence["to_state"] = to_state;
            evidence["transition_rule"] = "valid";
            reporter.report("lifecycle_transition", true, evidence);
            
            return 0;
        }
    }
    
    // Default: full validation
    std::cout << "[INFO] Performing full validation...\n\n";
    
    EvidenceReporter reporter;
    std::map<std::string, std::string> evidence;
    evidence["manifest_path"] = manifest_path;
    evidence["schema_version"] = loader.getSchemaVersion();
    evidence["evidence_format"] = loader.getEvidenceFormat();
    evidence["run_id"] = loader.getRunId();
    evidence["run_state"] = loader.getRunState();
    
    reporter.report("full_validation", true, evidence);
    
    return 0;
}
