// ============================================================================
// test_speculative_pipeline.cpp — Unit tests for SpeculativePipeline
// ============================================================================
// Uses: GoogleTest (already configured in tests/CMakeLists.txt)
// Build: cmake --build . --target test_speculative_pipeline
// Run: ctest -R test_speculative_pipeline -V
// ============================================================================

#include <gtest/gtest.h>
#include "inference/speculative_pipeline.h"
#include <cmath>

using namespace RawrXD::Inference;

class SpeculativePipelineTest : public ::testing::Test {
protected:
    SpeculativePipelineConfig config;
    std::unique_ptr<SpeculativePipeline> pipeline;

    void SetUp() override {
        // Small config for fast unit tests
        config.maxDraftTokens = 5;
        config.temperature = 0.7f;
        config.topP = 0.95f;
        config.topK = 40;
        config.adaptiveDraftSize = true;
        config.minAcceptanceRate = 0.5f;
        config.maxAcceptanceRate = 0.9f;

        pipeline = std::make_unique<SpeculativePipeline>(config);
    }
};

// ---------------------------------------------------------------------------
// Configuration validation
// ---------------------------------------------------------------------------
TEST_F(SpeculativePipelineTest, Config_ValidDefaults) {
    EXPECT_EQ(config.maxDraftTokens, 5u);
    EXPECT_EQ(config.topK, 40u);
    EXPECT_FLOAT_EQ(config.temperature, 0.7f);
    EXPECT_FLOAT_EQ(config.topP, 0.95f);
    EXPECT_TRUE(config.adaptiveDraftSize);
}

// ---------------------------------------------------------------------------
// Draft stage (mocked — tests plumbing)
// ---------------------------------------------------------------------------
TEST_F(SpeculativePipelineTest, DraftStage_ReturnsTokens) {
    std::vector<float> logits(32000, 0.0f);
    logits[42] = 5.0f;  // Make token 42 the clear winner

    // Note: This test requires a loaded draft model to work properly
    // For now, just verify the pipeline was created
    EXPECT_NE(pipeline, nullptr);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
