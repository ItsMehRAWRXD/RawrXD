/**
 * GA Blocker: Plugin SDK L3 Validation
 * 
 * Validates that the Plugin SDK can be loaded, initialized,
 * and execute basic operations without crashes.
 */

#include <gtest/gtest.h>
#include <rawrxd/plugin/PluginSDK.hpp>
#include <rawrxd/plugin/PluginManager.hpp>
#include <filesystem>
#include <fstream>

using namespace rawrxd;
namespace fs = std::filesystem;

class PluginSDKValidation : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test plugin directory
        testDir = fs::temp_directory_path() / "rawrxd_test_plugins";
        fs::create_directories(testDir);
    }

    void TearDown() override {
        // Cleanup
        fs::remove_all(testDir);
    }

    fs::path testDir;
};

// L3 Validation: Plugin SDK loads without crash
TEST_F(PluginSDKValidation, PluginManager_Initialize) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    PluginManagerConfig config;
    config.pluginDirectory = testDir.string();
    
    // Should initialize without throwing
    EXPECT_NO_THROW({
        auto result = manager->Initialize(config);
        EXPECT_TRUE(result.IsOk());
    });
}

// L3 Validation: Plugin can be loaded
TEST_F(PluginSDKValidation, Plugin_LoadAndUnload) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    PluginManagerConfig config;
    config.pluginDirectory = testDir.string();
    
    auto initResult = manager->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Create a minimal test plugin
    auto pluginPath = testDir / "test_plugin.rawr";
    {
        std::ofstream file(pluginPath, std::ios::binary);
        // Minimal plugin header
        const char header[] = "RAWRPLUGIN\x01\x00\x00\x00";
        file.write(header, sizeof(header) - 1);
    }
    
    // Load plugin
    auto loadResult = manager->LoadPlugin(pluginPath.string());
    EXPECT_TRUE(loadResult.IsOk());
    
    if (loadResult.IsOk()) {
        auto plugin = loadResult.Value();
        EXPECT_NE(plugin, nullptr);
        
        // Unload plugin
        auto unloadResult = manager->UnloadPlugin(plugin->GetId());
        EXPECT_TRUE(unloadResult.IsOk());
    }
}

// L3 Validation: Plugin manifest parsing
TEST_F(PluginSDKValidation, Plugin_ManifestParsing) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    // Create plugin with manifest
    auto manifestPath = testDir / "plugin.json";
    {
        std::ofstream file(manifestPath);
        file << R"({
            "name": "TestPlugin",
            "version": "1.0.0",
            "api_version": "1.0.0",
            "entry_point": "test_plugin.rawr",
            "permissions": ["inference", "filesystem"]
        })";
    }
    
    auto result = manager->ParseManifest(manifestPath.string());
    EXPECT_TRUE(result.IsOk());
    
    if (result.IsOk()) {
        auto manifest = result.Value();
        EXPECT_EQ(manifest.name, "TestPlugin");
        EXPECT_EQ(manifest.version, "1.0.0");
        EXPECT_EQ(manifest.apiVersion, "1.0.0");
    }
}

// L3 Validation: Plugin API version compatibility
TEST_F(PluginSDKValidation, Plugin_APICompatibility) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    // Test version compatibility check
    EXPECT_TRUE(manager->IsAPICompatible("1.0.0", "1.0.0"));
    EXPECT_TRUE(manager->IsAPICompatible("1.0.0", "1.0.1"));
    EXPECT_TRUE(manager->IsAPICompatible("1.0.0", "1.1.0"));
    EXPECT_FALSE(manager->IsAPICompatible("1.0.0", "2.0.0"));
}

// L3 Validation: Plugin lifecycle
TEST_F(PluginSDKValidation, Plugin_Lifecycle) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    PluginManagerConfig config;
    config.pluginDirectory = testDir.string();
    
    auto initResult = manager->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Create test plugin
    auto pluginPath = testDir / "lifecycle_plugin.rawr";
    {
        std::ofstream file(pluginPath, std::ios::binary);
        const char header[] = "RAWRPLUGIN\x01\x00\x00\x00";
        file.write(header, sizeof(header) - 1);
    }
    
    // Load
    auto loadResult = manager->LoadPlugin(pluginPath.string());
    ASSERT_TRUE(loadResult.IsOk());
    
    auto plugin = loadResult.Value();
    ASSERT_NE(plugin, nullptr);
    
    // Initialize
    auto pluginInit = plugin->Initialize();
    EXPECT_TRUE(pluginInit.IsOk());
    
    // Get capabilities
    auto caps = plugin->GetCapabilities();
    EXPECT_NO_THROW({
        (void)caps.size();
    });
    
    // Shutdown
    auto pluginShutdown = plugin->Shutdown();
    EXPECT_TRUE(pluginShutdown.IsOk());
    
    // Unload
    auto unloadResult = manager->UnloadPlugin(plugin->GetId());
    EXPECT_TRUE(unloadResult.IsOk());
}

// L3 Validation: Plugin isolation
TEST_F(PluginSDKValidation, Plugin_Isolation) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    PluginManagerConfig config;
    config.pluginDirectory = testDir.string();
    config.enableSandbox = true;
    
    auto initResult = manager->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Verify sandbox is enabled
    EXPECT_TRUE(manager->IsSandboxEnabled());
}

// L3 Validation: Error handling
TEST_F(PluginSDKValidation, Plugin_ErrorHandling) {
    auto manager = PluginManager::Create();
    ASSERT_NE(manager, nullptr);
    
    // Try to load non-existent plugin
    auto result = manager->LoadPlugin("/nonexistent/plugin.rawr");
    EXPECT_FALSE(result.IsOk());
    EXPECT_EQ(result.Error().code, ErrorCode::FileNotFound);
}

// Main entry point for standalone execution
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
