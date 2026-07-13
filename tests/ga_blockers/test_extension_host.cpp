/**
 * GA Blocker: Extension Host L3 Validation
 *
 * Validates that the extension host can load, initialize,
 * and communicate with extensions.
 */

#include <gtest/gtest.h>
#include <rawrxd/extension/ExtensionHost.hpp>
#include <rawrxd/extension/ExtensionAPI.hpp>
#include <filesystem>
#include <fstream>

using namespace rawrxd;
namespace fs = std::filesystem;

class ExtensionHostValidation : public ::testing::Test {
protected:
    void SetUp() override {
        testDir = fs::temp_directory_path() / "rawrxd_test_extensions";
        fs::create_directories(testDir);
    }

    void TearDown() override {
        fs::remove_all(testDir);
    }

    fs::path testDir;
};

// L3 Validation: Extension host initializes
TEST_F(ExtensionHostValidation, ExtensionHost_Initialize) {
    auto host = ExtensionHost::Create();
    ASSERT_NE(host, nullptr);

    ExtensionHostConfig config;
    config.extensionDirectory = testDir.string();

    EXPECT_NO_THROW({
        auto result = host->Initialize(config);
        EXPECT_TRUE(result.IsOk());
    });
}

// L3 Validation: Extension can be loaded
TEST_F(ExtensionHostValidation, Extension_LoadAndUnload) {
    auto host = ExtensionHost::Create();
    ASSERT_NE(host, nullptr);

    ExtensionHostConfig config;
    config.extensionDirectory = testDir.string();

    auto initResult = host->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());

    // Create a minimal test extension
    auto extPath = testDir / "test_extension.js";
    {
        std::ofstream file(extPath);
        file << R"({
            "name": "test-extension",
            "version": "1.0.0",
            "main": "./index.js",
            "activationEvents": ["*"]
        })";
    }

    auto loadResult = host->LoadExtension(extPath.string());
    EXPECT_TRUE(loadResult.IsOk());

    if (loadResult.IsOk()) {
        auto ext = loadResult.Value();
        EXPECT_NE(ext, nullptr);

        auto unloadResult = host->UnloadExtension(ext->GetId());
        EXPECT_TRUE(unloadResult.IsOk());
    }
}

// L3 Validation: Extension API communication
TEST_F(ExtensionHostValidation, Extension_APICommunication) {
    auto host = ExtensionHost::Create();
    ASSERT_NE(host, nullptr);

    ExtensionHostConfig config;
    config.extensionDirectory = testDir.string();

    auto initResult = host->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());

    // Test API registration
    auto api = host->GetAPI();
    ASSERT_NE(api, nullptr);

    auto regResult = api->RegisterCommand("test.command", []() {
        return Result<std::string>(Ok("executed"));
    });
    EXPECT_TRUE(regResult.IsOk());
}

// L3 Validation: Extension isolation
TEST_F(ExtensionHostValidation, Extension_Isolation) {
    auto host = ExtensionHost::Create();
    ASSERT_NE(host, nullptr);

    ExtensionHostConfig config;
    config.extensionDirectory = testDir.string();
    config.enableSandbox = true;

    auto initResult = host->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());

    EXPECT_TRUE(host->IsSandboxEnabled());
}

// L3 Validation: Error handling
TEST_F(ExtensionHostValidation, Extension_ErrorHandling) {
    auto host = ExtensionHost::Create();
    ASSERT_NE(host, nullptr);

    // Try to load non-existent extension
    auto result = host->LoadExtension("/nonexistent/extension.js");
    EXPECT_FALSE(result.IsOk());
    EXPECT_EQ(result.Error().code, ErrorCode::FileNotFound);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
