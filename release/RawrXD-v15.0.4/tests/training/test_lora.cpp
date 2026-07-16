/**
 * @file test_lora.cpp
 * @brief Unit tests for LoRA functionality
 */

#include <gtest/gtest.h>
#include "training/lora_adapter.hpp"
#include "training/training_config.hpp"

using namespace rawrxd::training;

class LoRATest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.rank = 8;
        config_.alpha = 16;
        config_.target_modules = "q_proj,v_proj";
        config_.dropout = 0.0f;
    }

    LoRAConfig config_;
};

TEST_F(LoRATest, ConfigScaling) {
    // Test scaling factor calculation
    EXPECT_FLOAT_EQ(config_.getScaling(), 2.0f);  // alpha / rank = 16 / 8

    config_.rank = 16;
    config_.alpha = 32;
    EXPECT_FLOAT_EQ(config_.getScaling(), 2.0f);
}

TEST_F(LoRATest, ParameterCount) {
    // Test parameter count estimation
    int num_layers = 32;
    int hidden_size = 4096;
    int rank = 8;
    std::vector<std::string> targets = {"q_proj", "v_proj"};

    size_t count = lora_utils::estimateParameterCount(
        num_layers, hidden_size, rank, targets);

    // Each target: in * rank + rank * out = 4096 * 8 + 8 * 4096 = 65536
    // Per layer: 2 * 65536 = 131072
    // Total: 32 * 131072 = 4194304
    EXPECT_EQ(count, 4194304);
}

TEST_F(LoRATest, TargetModuleMatching) {
    std::vector<std::string> patterns = {"q_proj", "v_proj"};

    EXPECT_TRUE(lora_utils::matchesTargetModule("layer.0.q_proj", patterns));
    EXPECT_TRUE(lora_utils::matchesTargetModule("layer.0.v_proj", patterns));
    EXPECT_FALSE(lora_utils::matchesTargetModule("layer.0.k_proj", patterns));
    EXPECT_FALSE(lora_utils::matchesTargetModule("embed_tokens", patterns));
}

TEST_F(LoRATest, AdapterInitialization) {
    LoRAAdapter adapter(config_);
    EXPECT_FLOAT_EQ(adapter.getScaling(), 2.0f);

    // Initially no layers
    EXPECT_EQ(adapter.getLayerNames().size(), 0);
}

TEST_F(LoRATest, MultiLoRAManager) {
    MultiLoRAManager manager;

    auto adapter1 = std::make_shared<LoRAAdapter>(config_);
    auto adapter2 = std::make_shared<LoRAAdapter>(config_);

    manager.addAdapter("math", adapter1);
    manager.addAdapter("coding", adapter2);

    EXPECT_EQ(manager.listAdapters().size(), 2);
    EXPECT_EQ(manager.getActiveAdapter(), "math");  // First added

    manager.setActiveAdapter("coding");
    EXPECT_EQ(manager.getActiveAdapter(), "coding");

    manager.removeAdapter("math");
    EXPECT_EQ(manager.listAdapters().size(), 1);
}

// Integration test (requires model)
TEST_F(LoRATest, DISABLED_FullTrainingLoop) {
    // This test requires a loaded model
    // Skipped in unit tests
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
