#pragma once

#include "digestion_reverse_engineering.h"
<<<<<<< HEAD
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

struct DigestionModuleConfig {
    DigestionConfig engineConfig;
    std::string databasePath;
    std::string schemaPath;
    std::string outputPath;
<<<<<<< HEAD
    std::vector<std::string> flags;
=======
    std::stringList flags;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    bool enableDatabase = true;
    bool enableMetrics = true;
};

class DigestionConfigManager {
public:
<<<<<<< HEAD
    static DigestionModuleConfig loadFromFile(const std::string& path, std::string* error = nullptr);
    static DigestionModuleConfig loadFromJson(const nlohmann::json& json, std::string* error = nullptr);
    static DigestionModuleConfig loadFromYaml(const std::string& yamlText, std::string* error = nullptr);

    static nlohmann::json parseYamlToJson(const std::string& yamlText, std::string* error = nullptr);

private:
    static nlohmann::json parseScalar(const std::string& value);
    static void assignValue(nlohmann::json& root, const std::string& section, const std::string& key, const nlohmann::json& value);
    static std::vector<std::string> parseInlineList(const std::string& value);
=======
    static DigestionModuleConfig loadFromFile(const std::string &path, std::string *error = nullptr);
    static DigestionModuleConfig loadFromJson(const void* &json, std::string *error = nullptr);
    static DigestionModuleConfig loadFromYaml(const std::string &yamlText, std::string *error = nullptr);

    static void* parseYamlToJson(const std::string &yamlText, std::string *error = nullptr);

private:
    static void* parseScalar(const std::string &value);
    static void assignValue(void* &root, const std::string &section, const std::string &key, const void* &value);
    static std::stringList parseInlineList(const std::string &value);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

