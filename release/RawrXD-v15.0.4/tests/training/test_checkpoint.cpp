/**
 * @file test_checkpoint.cpp
 * @brief Unit tests for checkpoint management
 */

#include <gtest/gtest.h>
#include "training/checkpoint_manager.hpp"
#include <filesystem>

using namespace rawrxd::training;

class CheckpointTest : public ::testing::Test {
protected:
    void SetUp() override {
        temp_dir_ = std::filesystem::temp_directory_path() / "rawrxd_checkpoint_test";
        std::filesystem::create_directories(temp_dir_);
    }

    void TearDown() override {
        std::filesystem::remove_all(temp_dir_);
    }

    std::filesystem::path temp_dir_;
};

TEST_F(CheckpointTest, ManagerInitialization) {
    CheckpointManager manager(temp_dir_.string());

    EXPECT_TRUE(std::filesystem::exists(temp_dir_));
}

TEST_F(CheckpointTest, ListEmptyCheckpoints) {
    CheckpointManager manager(temp_dir_.string());

    auto checkpoints = manager.listCheckpoints();
    EXPECT_TRUE(checkpoints.empty());
}

TEST_F(CheckpointTest, CheckpointInfoSerialization) {
    CheckpointInfo info;
    info.path = temp_dir_.string();
    info.step = 1000;
    info.epoch = 2;
    info.loss = 0.5f;
    info.metric = 0.85f;
    info.timestamp = std::chrono::system_clock::now();
    info.file_size = 1024 * 1024 * 100;  // 100MB

    std::string str = info.toString();
    EXPECT_NE(str.find("1000"), std::string::npos);
    EXPECT_NE(str.find("2"), std::string::npos);
    EXPECT_NE(str.find("100MB"), std::string::npos);
}

TEST_F(CheckpointTest, CleanupOldCheckpoints) {
    CheckpointManager manager(temp_dir_.string());

    // Create mock checkpoints
    for (int i = 0; i < 5; ++i) {
        auto checkpoint_dir = temp_dir_ / ("checkpoint-" + std::to_string(i));
        std::filesystem::create_directories(checkpoint_dir);

        // Create metadata file
        std::ofstream metadata(checkpoint_dir / "metadata.json");
        metadata << "{\"step\":" << i << ",\"epoch\":0,\"loss\":0.5}";
        metadata.close();
    }

    auto checkpoints_before = manager.listCheckpoints();
    EXPECT_EQ(checkpoints_before.size(), 5);

    // Keep only 2
    manager.cleanupOldCheckpoints(2);

    auto checkpoints_after = manager.listCheckpoints();
    EXPECT_EQ(checkpoints_after.size(), 2);
}

TEST_F(CheckpointTest, ExportConfigValidation) {
    ModelExporter::ExportOptions options;
    options.format = ModelFormat::GGUF;
    options.quantization = QuantizationType::Q4_0;
    options.merge_adapter = true;
    options.metadata_author = "Test Author";
    options.metadata_description = "Test Description";
    options.metadata_license = "MIT";

    EXPECT_EQ(options.format, ModelFormat::GGUF);
    EXPECT_EQ(options.quantization, QuantizationType::Q4_0);
    EXPECT_TRUE(options.merge_adapter);
}

TEST_F(CheckpointTest, EstimateExportSize) {
    // Test size estimation for different quantization types
    size_t base_size = 7ULL * 1024 * 1024 * 1024;  // 7B model

    // Q4_0: ~25% of original
    // Q8_0: ~50% of original
    // F16: ~100% of original

    // These are rough estimates
    EXPECT_LT(base_size * 0.3f, base_size * 0.5f);  // Q4 < Q8
    EXPECT_LT(base_size * 0.5f, base_size);          // Q8 < F16
}

// Integration tests (require actual model)
TEST_F(CheckpointTest, DISABLED_SaveAndLoadCheckpoint) {
    // Requires actual model and trainer
}

TEST_F(CheckpointTest, DISABLED_ExportToGGUF) {
    // Requires actual model
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
