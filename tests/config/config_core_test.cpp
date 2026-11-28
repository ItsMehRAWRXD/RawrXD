#include "rawrxd/config/AppPaths.h"
#include "rawrxd/config/ConfigStore.h"
#include "rawrxd/config/ModelDiscovery.h"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;
using namespace rawrxd::config;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::cerr << "FAIL: " #cond " (line " << __LINE__ << ")\n"; ++failures; } } while (0)

static fs::path tempRoot() {
    fs::path p = fs::temp_directory_path() / "rawrxd_config_test";
    std::error_code ec;
    fs::remove_all(p, ec);
    fs::create_directories(p, ec);
    return p;
}

static void writeFile(const fs::path& p, const std::string& text) {
    std::ofstream out(p, std::ios::binary);
    out << text;
}

int main() {
    const fs::path root = tempRoot();

    // M-CFG-02: portable path resolution honours environment overrides.
    _putenv_s("RAWRXD_HOME", root.string().c_str());
    _putenv_s("RAWRXD_CONFIG_DIR", (root / "cfg").string().c_str());
    _putenv_s("RAWRXD_CACHE_DIR", (root / "cache").string().c_str());
    _putenv_s("RAWRXD_LOG_DIR", (root / "logs").string().c_str());
    _putenv_s("RAWRXD_MODELS_DIR", (root / "models").string().c_str());
    AppPaths paths = AppPaths::resolve();
    CHECK(paths.applicationRoot == root.string());
    CHECK(paths.configFile() == (root / "cfg" / "rawrxd.config.json").string());
    CHECK(paths.modelDir == (root / "models").string());

    // M-CFG-03: v1 configuration migrates, drive letters are removed.
    const fs::path cfg = root / "cfg" / "rawrxd.config.json";
    fs::create_directories(root / "cfg");
    writeFile(cfg, R"({"editor":{"fontFamily":"Consolas"},"inference":{"contextSize":4096,"threads":8},"modelServer":{"configPath":"D:\\rawrxd\\ide\\config.json","gguf":{"command":"D:\\rawrxd\\bin\\x.exe"}},"features":{"agenticBridge":true}})");
    ConfigStore store(cfg.string());
    ConfigResult migrated = store.load();
    CHECK(migrated.status == ConfigStatus::MigrationApplied);
    CHECK(migrated.version == 2);
    if (migrated.document.contains("modelServer") && migrated.document["modelServer"].contains("configPath")) {
        CHECK(migrated.document["modelServer"]["configPath"].get<std::string>().find("D:") == std::string::npos);
    }
    CHECK(migrated.diagnostics.empty());

    // M-CFG-03: invalid configuration is rejected with actionable diagnostics.
    const fs::path bad = root / "cfg" / "bad.json";
    writeFile(bad, R"({"version":2,"inference":{"contextSize":4},"modelServer":{"gguf":{"command":"E:\\x.exe"}}})");
    ConfigResult rejected = ConfigStore(bad.string()).load();
    CHECK(rejected.status == ConfigStatus::ValidationError);
    CHECK(!rejected.diagnostics.empty());

    // M-CFG-03: atomic save round-trips.
    json doc = migrated.document;
    doc["inference"]["threads"] = 12;
    CHECK(store.saveAtomic(doc));
    ConfigResult reloaded = store.load();
    CHECK(reloaded.status == ConfigStatus::Ok);
    CHECK(reloaded.document["inference"]["threads"].get<int>() == 12);

    // M-CFG-04: dynamic discovery extracts real GGUF header metadata.
    const fs::path models = root / "models";
    fs::create_directories(models);
    const fs::path gguf = models / "tiny.gguf";
    std::string header;
    auto put32 = [&](uint32_t v) { header.append(reinterpret_cast<char*>(&v), 4); };
    auto put64 = [&](uint64_t v) { header.append(reinterpret_cast<char*>(&v), 8); };
    auto putStr = [&](const std::string& s) { put64(s.size()); header += s; };
    header += "GGUF";
    put32(2);
    put64(1); // tensor count
    put64(3); // kv count
    putStr("general.architecture"); put32(8); putStr("llama");
    putStr("llama.context_length"); put32(4); put32(2048);
    putStr("general.name"); put32(8); putStr("tiny");
    putStr("blk.0.weight"); put64(0); put64(1); put64(1); put64(1); put64(1);
    writeFile(gguf, header);

    std::vector<ModelInfo> found = discoverModels(models.string());
    CHECK(found.size() == 1);
    if (!found.empty()) {
        CHECK(found[0].valid);
        CHECK(found[0].architecture == "llama");
        CHECK(found[0].contextLength == 2048);
        CHECK(found[0].sizeBytes == static_cast<uint64_t>(header.size()));
    }

    std::error_code ec;
    fs::remove_all(root, ec);
    if (failures == 0) {
        std::cout << "config_core_test: PASS\n";
        return 0;
    }
    std::cerr << "config_core_test: " << failures << " failure(s)\n";
    return 1;
}