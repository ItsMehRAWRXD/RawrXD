/**
 * GA Blocker: Packaging L3 Validation
 *
 * Validates that packaging and installation work correctly.
 */

#include <gtest/gtest.h>
#include <rawrxd/packaging/PackageManager.hpp>
#include <filesystem>
#include <fstream>

using namespace rawrxd;
namespace fs = std::filesystem;

class PackagingValidation : public ::testing::Test {
protected:
    void SetUp() override {
        testDir = fs::temp_directory_path() / "rawrxd_test_packages";
        fs::create_directories(testDir);
    }

    void TearDown() override {
        fs::remove_all(testDir);
    }

    fs::path testDir;
};

// L3 Validation: Package manager initializes
TEST_F(PackagingValidation, PackageManager_Initialize) {
    auto manager = PackageManager::Create();
    ASSERT_NE(manager, nullptr);

    EXPECT_NO_THROW({
        auto result = manager->Initialize();
        EXPECT_TRUE(result.IsOk());
    });
}

// L3 Validation: Package can be created
TEST_F(PackagingValidation, Package_Create) {
    auto manager = PackageManager::Create();
    ASSERT_NE(manager, nullptr);

    auto initResult = manager->Initialize();
    ASSERT_TRUE(initResult.IsOk());

    // Create a test package
    auto packagePath = testDir / "test_package.zip";
    
    PackageConfig config;
    config.name = "test-package";
    config.version = "1.0.0";
    config.files = {testDir / "file1.txt", testDir / "file2.txt"};

    // Create test files
    {
        std::ofstream f1(testDir / "file1.txt");
        f1 << "Test content 1";
        std::ofstream f2(testDir / "file2.txt");
        f2 << "Test content 2";
    }

    auto result = manager->CreatePackage(config, packagePath.string());
    EXPECT_TRUE(result.IsOk());
    EXPECT_TRUE(fs::exists(packagePath));
}

// L3 Validation: Package can be installed
TEST_F(PackagingValidation, Package_Install) {
    auto manager = PackageManager::Create();
    ASSERT_NE(manager, nullptr);

    auto initResult = manager->Initialize();
    ASSERT_TRUE(initResult.IsOk());

    // Create a test package first
    auto packagePath = testDir / "test_package.zip";
    auto installDir = testDir / "install";
    
    PackageConfig config;
    config.name = "test-package";
    config.version = "1.0.0";
    config.files = {testDir / "file1.txt"};

    {
        std::ofstream f1(testDir / "file1.txt");
        f1 << "Test content";
    }

    auto createResult = manager->CreatePackage(config, packagePath.string());
    ASSERT_TRUE(createResult.IsOk());

    // Install the package
    auto installResult = manager->InstallPackage(packagePath.string(), installDir.string());
    EXPECT_TRUE(installResult.IsOk());
    EXPECT_TRUE(fs::exists(installDir / "file1.txt"));
}

// L3 Validation: Package manifest parsing
TEST_F(PackagingValidation, Package_ManifestParsing) {
    auto manager = PackageManager::Create();
    ASSERT_NE(manager, nullptr);

    auto manifestPath = testDir / "manifest.json";
    {
        std::ofstream file(manifestPath);
        file << R"({
            "name": "test-package",
            "version": "1.0.0",
            "description": "Test package",
            "files": ["file1.txt", "file2.txt"]
        })";
    }

    auto result = manager->ParseManifest(manifestPath.string());
    EXPECT_TRUE(result.IsOk());

    if (result.IsOk()) {
        auto manifest = result.Value();
        EXPECT_EQ(manifest.name, "test-package");
        EXPECT_EQ(manifest.version, "1.0.0");
    }
}

// L3 Validation: Package uninstall
TEST_F(PackagingValidation, Package_Uninstall) {
    auto manager = PackageManager::Create();
    ASSERT_NE(manager, nullptr);

    auto initResult = manager->Initialize();
    ASSERT_TRUE(initResult.IsOk());

    // Create and install a package
    auto packagePath = testDir / "test_package.zip";
    auto installDir = testDir / "install";
    
    PackageConfig config;
    config.name = "test-package";
    config.version = "1.0.0";
    config.files = {testDir / "file1.txt"};

    {
        std::ofstream f1(testDir / "file1.txt");
        f1 << "Test content";
    }

    auto createResult = manager->CreatePackage(config, packagePath.string());
    ASSERT_TRUE(createResult.IsOk());

    auto installResult = manager->InstallPackage(packagePath.string(), installDir.string());
    ASSERT_TRUE(installResult.IsOk());

    // Uninstall
    auto uninstallResult = manager->UninstallPackage("test-package", installDir.string());
    EXPECT_TRUE(uninstallResult.IsOk());
    EXPECT_FALSE(fs::exists(installDir / "file1.txt"));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
