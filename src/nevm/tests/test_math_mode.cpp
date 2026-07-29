//============================================================================
// test_math_mode.cpp
// RawrXD N-EVM - Unit Tests for Math Mode Controller
//============================================================================

#include "../nevm_math_mode.hpp"

using namespace RawrXD::NEVM;

TEST(MathMode_StringConversion) {
    // Test Fast mode
    ASSERT_EQ(std::string("Fast"), MathModeToString(MathMode::Fast));
    ASSERT_EQ(MathMode::Fast, MathModeFromString("Fast"));
    ASSERT_EQ(MathMode::Fast, MathModeFromString("fast"));
    ASSERT_EQ(MathMode::Fast, MathModeFromString("FAST"));
    
    // Test Reproducible mode
    ASSERT_EQ(std::string("Reproducible"), MathModeToString(MathMode::Reproducible));
    ASSERT_EQ(MathMode::Reproducible, MathModeFromString("Reproducible"));
    ASSERT_EQ(MathMode::Reproducible, MathModeFromString("reproducible"));
    
    // Test BitExact mode
    ASSERT_EQ(std::string("BitExact"), MathModeToString(MathMode::BitExact));
    ASSERT_EQ(MathMode::BitExact, MathModeFromString("BitExact"));
    ASSERT_EQ(MathMode::BitExact, MathModeFromString("bitexact"));
    
    // Test invalid string returns Fast
    ASSERT_EQ(MathMode::Fast, MathModeFromString("invalid"));
    ASSERT_EQ(MathMode::Fast, MathModeFromString(""));
    
    return true;
}

TEST(MathMode_Configuration_Fast) {
    auto config = MathModeController::GetConfiguration(MathMode::Fast);
    
    ASSERT_TRUE(config.fma_enabled);
    ASSERT_FALSE(config.use_tree_reduction);
    ASSERT_FALSE(config.use_kahan_summation);
    ASSERT_EQ(0, config.denormal_mode);
    ASSERT_EQ(std::string("Fast"), config.ToString());
    
    return true;
}

TEST(MathMode_Configuration_Reproducible) {
    auto config = MathModeController::GetConfiguration(MathMode::Reproducible);
    
    ASSERT_TRUE(config.fma_enabled);
    ASSERT_TRUE(config.use_tree_reduction);
    ASSERT_FALSE(config.use_kahan_summation);
    ASSERT_EQ(1, config.denormal_mode);
    ASSERT_EQ(std::string("Reproducible"), config.ToString());
    
    return true;
}

TEST(MathMode_Configuration_BitExact) {
    auto config = MathModeController::GetConfiguration(MathMode::BitExact);
    
    ASSERT_FALSE(config.fma_enabled);
    ASSERT_TRUE(config.use_tree_reduction);
    ASSERT_TRUE(config.use_kahan_summation);
    ASSERT_EQ(1, config.denormal_mode);
    ASSERT_EQ(std::string("BitExact"), config.ToString());
    
    return true;
}

TEST(MathMode_Configuration_JSON) {
    auto config = MathModeController::GetConfiguration(MathMode::Reproducible);
    auto json = config.ToJSON();
    
    ASSERT_TRUE(json["fma_enabled"].asBool());
    ASSERT_TRUE(json["use_tree_reduction"].asBool());
    ASSERT_FALSE(json["use_kahan_summation"].asBool());
    ASSERT_EQ(1, json["denormal_mode"].asInt());
    ASSERT_EQ(std::string("Reproducible"), json["mode_name"].asString());
    
    return true;
}

TEST(MathMode_OverheadCalculation) {
    // Fast mode should have 0% overhead
    ASSERT_NEAR(0.0f, MathModeController::GetOverhead(MathMode::Fast), 0.01f);
    
    // Reproducible should have ~3.2% overhead
    float repro_overhead = MathModeController::GetOverhead(MathMode::Reproducible);
    ASSERT_GT(repro_overhead, 0.0f);
    ASSERT_LT(repro_overhead, 10.0f);
    
    // BitExact should have higher overhead than Reproducible
    float bitexact_overhead = MathModeController::GetOverhead(MathMode::BitExact);
    ASSERT_GT(bitexact_overhead, repro_overhead);
    
    return true;
}

TEST(MathMode_Validation) {
    // All modes should be valid
    ASSERT_TRUE(MathModeController::Validate(MathMode::Fast));
    ASSERT_TRUE(MathModeController::Validate(MathMode::Reproducible));
    ASSERT_TRUE(MathModeController::Validate(MathMode::BitExact));
    
    return true;
}

TEST(MathMode_Switching) {
    // Test mode switching
    ASSERT_TRUE(MathModeController::SwitchTo(MathMode::Fast));
    ASSERT_TRUE(MathModeController::SwitchTo(MathMode::Reproducible));
    ASSERT_TRUE(MathModeController::SwitchTo(MathMode::BitExact));
    
    return true;
}
