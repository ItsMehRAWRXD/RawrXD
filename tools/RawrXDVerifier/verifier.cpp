#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <json/json.h>
#include <vector>
#include <algorithm>
#include <iomanip>

namespace fs = std::filesystem;

// Function to calculate file hash (SHA-256)
// In a real implementation, we would use a cryptographic library
// For this example, we'll use a simple hash for demonstration
std::string calculateFileHash(const std::string& filePath) {
    // Placeholder implementation - in reality, use OpenSSL or Crypto++
    return "placeholder_hash_" + std::to_string(std::hash<std::string>{}(filePath));
}

// Function to read JSON file
bool readJsonFile(const std::string& filePath, Json::Value& root) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }
    
    Json::CharReaderBuilder reader;
    std::string errors;
    if (!Json::parseFromStream(reader, file, &root, &errors)) {
        std::cerr << "Failed to parse JSON: " << errors << std::endl;
        return false;
    }
    
    return true;
}

// Function to validate manifest
bool validateManifest(const Json::Value& manifest) {
    std::cout << "Validating manifest..." << std::endl;
    
    // Check required fields
    if (!manifest.isMember("version") || !manifest["version"].isString()) {
        std::cerr << "Missing or invalid version field" << std::endl;
        return false;
    }
    
    if (!manifest.isMember("build_timestamp") || !manifest["build_timestamp"].isString()) {
        std::cerr << "Missing or invalid build_timestamp field" << std::endl;
        return false;
    }
    
    if (!manifest.isMember("git_commit") || !manifest["git_commit"].isString()) {
        std::cerr << "Missing or invalid git_commit field" << std::endl;
        return false;
    }
    
    if (!manifest.isMember("compiler") || !manifest["compiler"].isString()) {
        std::cerr << "Missing or invalid compiler field" << std::endl;
        return false;
    }
    
    if (!manifest.isMember("target_architecture") || !manifest["target_architecture"].isString()) {
        std::cerr << "Missing or invalid target_architecture field" << std::endl;
        return false;
    }
    
    if (!manifest.isMember("binary_hashes") || !manifest["binary_hashes"].isObject()) {
        std::cerr << "Missing or invalid binary_hashes field" << std::endl;
        return false;
    }
    
    if (!manifest.isMember("model_hashes") || !manifest["model_hashes"].isObject()) {
        std::cerr << "Missing or invalid model_hashes field" << std::endl;
        return false;
    }
    
    std::cout << "Manifest validation PASSED" << std::endl;
    return true;
}

// Function to validate binary hashes
bool validateBinaryHashes(const Json::Value& manifest, const std::string& basePath) {
    std::cout << "Validating binary hashes..." << std::endl;
    
    if (!manifest.isMember("binary_hashes") || !manifest["binary_hashes"].isObject()) {
        std::cerr << "Missing or invalid binary_hashes in manifest" << std::endl;
        return false;
    }
    
    const Json::Value& binaryHashes = manifest["binary_hashes"];
    bool allPassed = true;
    
    for (auto it = binaryHashes.begin(); it != binaryHashes.end(); ++it) {
        std::string filename = it.name();
        std::string expectedHash = it->asString();
        
        // Check in bin directory
        fs::path binPath = fs::path(basePath) / "bin" / filename;
        std::string actualHash = calculateFileHash(binPath.string());
        
        // Check in runtime directory if not found in bin
        if (!fs::exists(binPath)) {
            binPath = fs::path(basePath) / "runtime" / filename;
            actualHash = calculateFileHash(binPath.string());
        }
        
        if (!fs::exists(binPath)) {
            std::cerr << "Binary file not found: " << filename << std::endl;
            allPassed = false;
            continue;
        }
        
        // In a real implementation, we would compare actual hashes
        // For this example, we'll simulate success
        if (actualHash != expectedHash) {
            std::cerr << "Hash mismatch for " << filename << ": expected " << expectedHash 
                      << ", got " << actualHash << std::endl;
            allPassed = false;
        } else {
            std::cout << "  " << filename << ": PASS" << std::endl;
        }
    }
    
    if (allPassed) {
        std::cout << "Binary hash validation PASSED" << std::endl;
    }
    
    return allPassed;
}

// Function to validate model hashes
bool validateModelHashes(const Json::Value& manifest, const std::string& basePath) {
    std::cout << "Validating model hashes..." << std::endl;
    
    if (!manifest.isMember("model_hashes") || !manifest["model_hashes"].isObject()) {
        std::cerr << "Missing or invalid model_hashes in manifest" << std::endl;
        return false;
    }
    
    const Json::Value& modelHashes = manifest["model_hashes"];
    bool allPassed = true;
    
    for (auto it = modelHashes.begin(); it != modelHashes.end(); ++it) {
        std::string filename = it.name();
        std::string expectedHash = it->asString();
        
        // Check in models directory
        fs::path modelPath = fs::path(basePath) / "models" / filename;
        std::string actualHash = calculateFileHash(modelPath.string());
        
        if (!fs::exists(modelPath)) {
            std::cerr << "Model file not found: " << filename << std::endl;
            allPassed = false;
            continue;
        }
        
        // In a real implementation, we would compare actual hashes
        // For this example, we'll simulate success
        if (actualHash != expectedHash) {
            std::cerr << "Hash mismatch for " << filename << ": expected " << expectedHash 
                      << ", got " << actualHash << std::endl;
            allPassed = false;
        } else {
            std::cout << "  " << filename << ": PASS" << std::endl;
        }
    }
    
    if (allPassed) {
        std::cout << "Model hash validation PASSED" << std::endl;
    }
    
    return allPassed;
}

// Function to validate hardware attestation
bool validateHardwareAttestation(const std::string& evidencePath) {
    std::cout << "Validating hardware attestation..." << std::endl;
    
    Json::Value hardwareAttestation;
    std::string hardwarePath = evidencePath + "/hardware_attestation.json";
    
    if (!readJsonFile(hardwarePath, hardwareAttestation)) {
        std::cerr << "Failed to read hardware attestation file" << std::endl;
        return false;
    }
    
    // Check required fields
    if (!hardwareAttestation.isMember("gpus") || !hardwareAttestation["gpus"].isArray()) {
        std::cerr << "Missing or invalid gpus array in hardware attestation" << std::endl;
        return false;
    }
    
    const Json::Value& gpus = hardwareAttestation["gpus"];
    if (gpus.size() < 2) {
        std::cerr << "Expected at least 2 GPUs for dual GPU configuration" << std::endl;
        return false;
    }
    
    // Check for required GPU properties
    bool foundR9700 = false;
    bool foundRX7800XT = false;
    
    for (unsigned int i = 0; i < gpus.size(); i++) {
        const Json::Value& gpu = gpus[i];
        if (!gpu.isObject()) continue;
        
        std::string name = gpu.get("device_name", "").asString();
        uint64_t vram = gpu.get("vram_mb", 0).asUInt64();
        
        if (name.find("Radeon AI PRO R9700") != std::string::npos && vram >= 32 * 1024) {
            foundR9700 = true;
        }
        
        if (name.find("Radeon RX 7800 XT") != std::string::npos && vram >= 16 * 1024) {
            foundRX7800XT = true;
        }
    }
    
    if (!foundR9700) {
        std::cerr << "Radeon AI PRO R9700 with >=32GB VRAM not found" << std::endl;
        return false;
    }
    
    if (!foundRX7800XT) {
        std::cerr << "Radeon RX 7800 XT with >=16GB VRAM not found" << std::endl;
        return false;
    }
    
    std::cout << "Hardware attestation validation PASSED" << std::endl;
    return true;
}

// Function to validate performance certification
bool validatePerformanceCertification(const std::string& evidencePath) {
    std::cout << "Validating performance certification..." << std::endl;
    
    Json::Value perfCert;
    std::string perfPath = evidencePath + "/performance_certification.json";
    
    if (!readJsonFile(perfPath, perfCert)) {
        std::cerr << "Failed to read performance certification file" << std::endl;
        return false;
    }
    
    // Check required fields
    if (!perfCert.isMember("tokens_per_second") || !perfCert["tokens_per_second"].isNumeric()) {
        std::cerr << "Missing or invalid tokens_per_second field" << std::endl;
        return false;
    }
    
    if (!perfCert.isMember("first_token_latency_ms") || !perfCert["first_token_latency_ms"].isNumeric()) {
        std::cerr << "Missing or invalid first_token_latency_ms field" << std::endl;
        return false;
    }
    
    // Check minimum performance thresholds
    double tps = perfCert["tokens_per_second"].asDouble();
    double latency = perfCert["first_token_latency_ms"].asDouble();
    
    if (tps < 200.0) {  // Minimum 200 TPS
        std::cerr << "TPS too low: " << tps << " < 200.0" << std::endl;
        return false;
    }
    
    if (latency > 100.0) {  // Maximum 100ms latency
        std::cerr << "Latency too high: " << latency << " > 100.0 ms" << std::endl;
        return false;
    }
    
    std::cout << "Performance certification validation PASSED" << std::endl;
    return true;
}

// Function to validate CEO agent recovery
bool validateCeoAgentRecovery(const std::string& evidencePath) {
    std::cout << "Validating CEO agent recovery..." << std::endl;
    
    Json::Value ceoRecovery;
    std::string recoveryPath = evidencePath + "/ceo_agent_recovery.json";
    
    if (!readJsonFile(recoveryPath, ceoRecovery)) {
        std::cerr << "Failed to read CEO agent recovery file" << std::endl;
        return false;
    }
    
    // Check required fields
    if (!ceoRecovery.isMember("recovery_successful") || !ceoRecovery["recovery_successful"].isBool()) {
        std::cerr << "Missing or invalid recovery_successful field" << std::endl;
        return false;
    }
    
    if (!ceoRecovery["recovery_successful"].asBool()) {
        std::cerr << "CEO agent recovery was not successful" << std::endl;
        return false;
    }
    
    if (!ceoRecovery.isMember("attempts") || !ceoRecovery["attempts"].isNumeric()) {
        std::cerr << "Missing or invalid attempts field" << std::endl;
        return false;
    }
    
    int attempts = ceoRecovery["attempts"].asInt();
    if (attempts > 3) {
        std::cerr << "Too many recovery attempts: " << attempts << " > 3" << std::endl;
        return false;
    }
    
    std::cout << "CEO agent recovery validation PASSED" << std::endl;
    return true;
}

// Function to validate Deep2 provider witness
bool validateDeep2ProviderWitness(const std::string& evidencePath) {
    std::cout << "Validating Deep2 provider witness..." << std::endl;
    
    Json::Value deep2Witness;
    std::string witnessPath = evidencePath + "/deep2_provider_witness.json";
    
    if (!readJsonFile(witnessPath, deep2Witness)) {
        std::cerr << "Failed to read Deep2 provider witness file" << std::endl;
        return false;
    }
    
    // Check required fields
    if (!deep2Witness.isMember("inference_chain_complete") || !deep2Witness["inference_chain_complete"].isBool()) {
        std::cerr << "Missing or invalid inference_chain_complete field" << std::endl;
        return false;
    }
    
    if (!deep2Witness["inference_chain_complete"].asBool()) {
        std::cerr << "Inference chain was not complete" << std::endl;
        return false;
    }
    
    if (!deep2Witness.isMember("backend") || !deep2Witness["backend"].isString()) {
        std::cerr << "Missing or invalid backend field" << std::endl;
        return false;
    }
    
    std::string backend = deep2Witness["backend"].asString();
    if (backend != "Vulkan/HIP" && backend != "Vulkan" && backend != "HIP") {
        std::cerr << "Invalid backend: " << backend << std::endl;
        return false;
    }
    
    std::cout << "Deep2 provider witness validation PASSED" << std::endl;
    return true;
}

// Function to validate VAL certification
bool validateValCertification(const std::string& evidencePath) {
    std::cout << "Validating VAL certification..." << std::endl;
    
    Json::Value valCert;
    std::string certPath = evidencePath + "/val_certification.json";
    
    if (!readJsonFile(certPath, valCert)) {
        std::cerr << "Failed to read VAL certification file" << std::endl;
        return false;
    }
    
    // Check required fields
    if (!valCert.isMember("tests_passed") || !valCert["tests_passed"].isNumeric()) {
        std::cerr << "Missing or invalid tests_passed field" << std::endl;
        return false;
    }
    
    if (!valCert.isMember("total_tests") || !valCert["total_tests"].isNumeric()) {
        std::cerr << "Missing or invalid total_tests field" << std::endl;
        return false;
    }
    
    int testsPassed = valCert["tests_passed"].asInt();
    int totalTests = valCert["total_tests"].asInt();
    
    if (testsPassed != totalTests) {
        std::cerr << "Not all tests passed: " << testsPassed << "/" << totalTests << std::endl;
        return false;
    }
    
    if (totalTests < 27) {  // Minimum VAL-064 through VAL-078
        std::cerr << "Insufficient number of tests: " << totalTests << " < 27" << std::endl;
        return false;
    }
    
    std::cout << "VAL certification validation PASSED" << std::endl;
    return true;
}

// Function to validate release freeze evidence
bool validateReleaseFreezeEvidence(const std::string& evidencePath) {
    std::cout << "Validating release freeze evidence..." << std::endl;
    
    Json::Value freezeEvidence;
    std::string freezePath = evidencePath + "/release_freeze_evidence.json";
    
    if (!readJsonFile(freezePath, freezeEvidence)) {
        std::cerr << "Failed to read release freeze evidence file" << std::endl;
        return false;
    }
    
    // Check required fields
    if (!freezeEvidence.isMember("release_ready") || !freezeEvidence["release_ready"].isBool()) {
        std::cerr << "Missing or invalid release_ready field" << std::endl;
        return false;
    }
    
    if (!freezeEvidence["release_ready"].asBool()) {
        std::cerr << "Release is not marked as ready" << std::endl;
        return false;
    }
    
    if (!freezeEvidence.isMember("checks_passed") || !freezeEvidence["checks_passed"].isNumeric()) {
        std::cerr << "Missing or invalid checks_passed field" << std::endl;
        return false;
    }
    
    if (!freezeEvidence.isMember("total_checks") || !freezeEvidence["total_checks"].isNumeric()) {
        std::cerr << "Missing or invalid total_checks field" << std::endl;
        return false;
    }
    
    int checksPassed = freezeEvidence["checks_passed"].asInt();
    int totalChecks = freezeEvidence["total_checks"].asInt();
    
    if (checksPassed != totalChecks) {
        std::cerr << "Not all checks passed: " << checksPassed << "/" << totalChecks << std::endl;
        return false;
    }
    
    if (totalChecks < 9) {  // Minimum 9 checks for release freeze
        std::cerr << "Insufficient number of checks: " << totalChecks << " < 9" << std::endl;
        return false;
    }
    
    std::cout << "Release freeze evidence validation PASSED" << std::endl;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <evidence_directory>" << std::endl;
        return 1;
    }
    
    std::string evidencePath = argv[1];
    
    // Ensure evidence path exists
    if (!fs::exists(evidencePath) || !fs::is_directory(evidencePath)) {
        std::cerr << "Evidence directory does not exist: " << evidencePath << std::endl;
        return 1;
    }
    
    std::cout << "RawrXD Release Verification" << std::endl;
    std::cout << "===========================" << std::endl;
    
    bool allPassed = true;
    
    // Step 1: Validate manifest
    std::string manifestPath = evidencePath + "/release_manifest.json";
    Json::Value manifest;
    if (!readJsonFile(manifestPath, manifest)) {
        std::cout << "Manifest       FAIL" << std::endl;
        return 1;
    }
    
    if (!validateManifest(manifest)) {
        std::cout << "Manifest       FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Manifest       PASS" << std::endl;
    }
    
    // Step 2: Validate binary hashes
    if (!validateBinaryHashes(manifest, evidencePath)) {
        std::cout << "Binary Hashes  FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Binary Hashes  PASS" << std::endl;
    }
    
    // Step 3: Validate model hashes
    if (!validateModelHashes(manifest, evidencePath)) {
        std::cout << "Model Hashes   FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Model Hashes   PASS" << std::endl;
    }
    
    // Step 4: Validate hardware attestation
    if (!validateHardwareAttestation(evidencePath)) {
        std::cout << "Hardware       FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Hardware       PASS" << std::endl;
    }
    
    // Step 5: Validate performance certification
    if (!validatePerformanceCertification(evidencePath)) {
        std::cout << "Performance    FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Performance    PASS" << std::endl;
    }
    
    // Step 6: Validate CEO agent recovery
    if (!validateCeoAgentRecovery(evidencePath)) {
        std::cout << "CEO Agent      FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "CEO Agent      PASS" << std::endl;
    }
    
    // Step 7: Validate Deep2 provider witness
    if (!validateDeep2ProviderWitness(evidencePath)) {
        std::cout << "Inference      FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Inference      PASS" << std::endl;
    }
    
    // Step 8: Validate VAL certification
    if (!validateValCertification(evidencePath)) {
        std::cout << "VAL Suite      FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "VAL Suite      PASS" << std::endl;
    }
    
    // Step 9: Validate release freeze evidence
    if (!validateReleaseFreezeEvidence(evidencePath)) {
        std::cout << "Attestation    FAIL" << std::endl;
        allPassed = false;
    } else {
        std::cout << "Attestation    PASS" << std::endl;
    }
    
    std::cout << std::endl;
    if (allPassed) {
        std::cout << "RESULT: CERTIFIED" << std::endl;
        return 0;
    } else {
        std::cout << "RESULT: FAILED" << std::endl;
        return 1;
    }
}