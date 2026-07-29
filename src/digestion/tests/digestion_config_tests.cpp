<<<<<<< HEAD
// digestion_config_tests.cpp — C++20, no Qt. Uses nlohmann::json.

#include "../digestion_config_manager.h"
#include <cassert>
#include <string>

static void loadJsonConfig() {
    nlohmann::json j;
    j["digestion"] = nlohmann::json::object({
        {"chunk_size", 1024},
        {"threads", 2},
        {"apply_fixes", true},
        {"flags", nlohmann::json::array({"DEFLATE", "CRC"})}
    });
    j["database"] = nlohmann::json::object({
        {"path", "test.db"},
        {"enabled", true}
    });

    std::string error;
    DigestionModuleConfig cfg = DigestionConfigManager::loadFromJson(j, &error);
    assert(error.empty());
    assert(cfg.engineConfig.chunkSize == 1024);
    assert(cfg.engineConfig.threadCount == 2);
    assert(cfg.engineConfig.applyExtensions == true);
    assert(cfg.flags.size() == 2);
    assert(cfg.databasePath == "test.db");
}

static void loadYamlConfig() {
    const std::string yaml = R"(
digestion:
  chunk_size: 2048
  threads: 4
  flags: [DEFLATE, CRC]
database:
  path: digestion_results.db
  enabled: true
)";

    std::string error;
    DigestionModuleConfig cfg = DigestionConfigManager::loadFromYaml(yaml, &error);
    assert(error.empty());
    assert(cfg.engineConfig.chunkSize == 2048);
    assert(cfg.engineConfig.threadCount == 4);
    assert(cfg.flags.size() == 2);
    assert(cfg.databasePath == "digestion_results.db");
}

int main() {
    loadJsonConfig();
    loadYamlConfig();
    return 0;
}
=======
#include "../digestion_config_manager.h"

class DigestionConfigTests  {private s:
    void loadJsonConfig();
    void loadYamlConfig();
};

void DigestionConfigTests::loadJsonConfig() {
    void* json;
    json["digestion"] = void*{
        {"chunk_size", 1024},
        {"threads", 2},
        {"apply_fixes", true},
        {"flags", void*{"DEFLATE", "CRC"}}
    };
    json["database"] = void*{
        {"path", "test.db"},
        {"enabled", true}
    };

    std::string error;
    DigestionModuleConfig cfg = DigestionConfigManager::loadFromJson(json, &error);
    QVERIFY(error.empty());
    QCOMPARE(cfg.engineConfig.chunkSize, 1024);
    QCOMPARE(cfg.engineConfig.threadCount, 2);
    QCOMPARE(cfg.engineConfig.applyExtensions, true);
    QCOMPARE(cfg.flags.size(), 2);
    QCOMPARE(cfg.databasePath, std::string("test.db"));
}

void DigestionConfigTests::loadYamlConfig() {
    const std::string yaml = std::stringLiteral(
        "digestion:\n"
        "  chunk_size: 2048\n"
        "  threads: 4\n"
        "  flags: [DEFLATE, CRC]\n"
        "database:\n"
        "  path: digestion_results.db\n"
        "  enabled: true\n");

    std::string error;
    DigestionModuleConfig cfg = DigestionConfigManager::loadFromYaml(yaml, &error);
    QVERIFY(error.empty());
    QCOMPARE(cfg.engineConfig.chunkSize, 2048);
    QCOMPARE(cfg.engineConfig.threadCount, 4);
    QCOMPARE(cfg.flags.size(), 2);
    QCOMPARE(cfg.databasePath, std::string("digestion_results.db"));
}

// Test removed
// MOC removed

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
