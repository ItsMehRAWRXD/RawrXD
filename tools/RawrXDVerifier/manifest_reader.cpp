#include <iostream>
#include <fstream>
#include <json/json.h>
#include <string>

namespace fs = std::filesystem;

// Function to read and parse JSON file
bool readJsonFile(const std::string& filePath, Json::Value& root) {
    std::ifstream file(filePath(file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
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

// Function to validate manifest structure
bool validateManifest(const Json::Value& manifest) {
    // Check required top-level fields
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
    
    return true;
}

// Function to get manifest value with default
std::string getManifestString(const Json::Value& manifest, const std::string& key, const std::string& defaultValue = "") {
    if (manifest.isMember(key) && manifest[key].isString()) {
        return manifest[key].asString();
    }
    return defaultValue;
}

int getManifestInt(const Json::Value& manifest, const std::string& key, int defaultValue = 0) {
    if (manifest.isMember(key) && manifest[key].isInt()) {
        return manifest[key].asInt();
    }
    return defaultValue;
}

bool getManifestBool(const Json::Value& manifest, const std::string& key, bool defaultValue = false) {
    if (manifest.isMember(key) && manifest[key].isBool()) {
        return manifest[key].asBool();
    }
    return defaultValue;
}

Json::Value getManifestObject(const Json::Value& manifest, const std::string& key) {
    if (manifest.isMember(key) && manifest[key].isObject()) {
        return manifest[key];
    }
    return Json::Value(Json::objectValue);
}