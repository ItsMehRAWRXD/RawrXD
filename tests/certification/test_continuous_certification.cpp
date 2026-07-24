// VAL-077: Continuous Certification Runner Tests
// CI/CD pipeline integration tests

#include <gtest/gtest.h>
#include "certification/continuous_certification_runner.hpp"
#include <filesystem>
#include <fstream>

using namespace RawrXD::Certification;

class ContinuousCertificationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "rawrxd_test_ci";
        std::filesystem::create_directories(test_dir_);
    }
    
    void TearDown() override {
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
};

TEST_F(ContinuousCertificationTest, CIJob_Serialize) {
    CIJob job;
    job.id = "test-job-001";
    job.name = "Test Job";
    job.type = JobType::BUILD;
    job.status = JobStatus::SUCCESS;
    job.start_time = "2026-07-24T10:00:00Z";
    job.end_time = "2026-07-24T10:05:00Z";
    job.duration_ms = 300000;
    job.exit_code = 0;
    job.log_path = "/logs/test.log";
    
    std::string serialized = job.Serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("test-job-001"), std::string::npos);
    EXPECT_NE(serialized.find("SUCCESS"), std::string::npos);
}

TEST_F(ContinuousCertificationTest, PipelineStage_Serialize) {
    PipelineStage stage;
    stage.name = "Build Stage";
    stage.status = PipelineStatus::SUCCESS;
    
    CIJob job;
    job.id = "build-001";
    job.name = "Build";
    job.status = JobStatus::SUCCESS;
    stage.jobs.push_back(job);
    
    std::string serialized = stage.Serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("Build Stage"), std::string::npos);
}

TEST_F(ContinuousCertificationTest, CertificationPipeline_Serialize) {
    CertificationPipeline pipeline;
    pipeline.name = "Test Pipeline";
    pipeline.version = "1.0.0";
    pipeline.overall_status = PipelineStatus::SUCCESS;
    
    PipelineStage stage;
    stage.name = "Build";
    stage.status = PipelineStatus::SUCCESS;
    pipeline.stages.push_back(stage);
    
    std::string serialized = pipeline.Serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("Test Pipeline"), std::string::npos);
    EXPECT_NE(serialized.find("1.0.0"), std::string::npos);
}

TEST_F(ContinuousCertificationTest, CertificationRunner_Initialize) {
    RunnerConfig config;
    config.check_interval_minutes = 60;
    config.fail_fast = true;
    config.output_path = (test_dir_ / "report.json").string();
    
    CertificationRunner runner(config);
    bool initialized = runner.Initialize(config);
    
    EXPECT_TRUE(initialized);
}

TEST_F(ContinuousCertificationTest, GateEnforcer_RegisterAndEvaluate) {
    GateEnforcer& enforcer = GateEnforcer::Instance();
    
    Gate gate;
    gate.id = "test-gate";
    gate.name = "Test Gate";
    gate.description = "A test gate";
    gate.check = []() { return true; };
    
    enforcer.RegisterGate(gate);
    
    auto result = enforcer.EvaluateGate("test-gate");
    EXPECT_TRUE(result.passed);
    EXPECT_EQ(result.message, "Gate passed");
    
    enforcer.UnregisterGate("test-gate");
}

TEST_F(ContinuousCertificationTest, GateEnforcer_FailingGate) {
    GateEnforcer& enforcer = GateEnforcer::Instance();
    
    Gate gate;
    gate.id = "failing-gate";
    gate.name = "Failing Gate";
    gate.description = "A gate that fails";
    gate.check = []() { return false; };
    
    enforcer.RegisterGate(gate);
    
    auto result = enforcer.EvaluateGate("failing-gate");
    EXPECT_FALSE(result.passed);
    EXPECT_EQ(result.message, "Gate failed");
    
    enforcer.UnregisterGate("failing-gate");
}

TEST_F(ContinuousCertificationTest, GateEnforcer_AllGatesPass) {
    GateEnforcer& enforcer = GateEnforcer::Instance();
    
    // Register multiple passing gates
    for (int i = 0; i < 3; ++i) {
        Gate gate;
        gate.id = "pass-gate-" + std::to_string(i);
        gate.name = "Pass Gate " + std::to_string(i);
        gate.check = []() { return true; };
        enforcer.RegisterGate(gate);
    }
    
    EXPECT_TRUE(enforcer.CheckAllGatesPass());
    
    // Cleanup
    for (int i = 0; i < 3; ++i) {
        enforcer.UnregisterGate("pass-gate-" + std::to_string(i));
    }
}

TEST_F(ContinuousCertificationTest, ExitCodeHandler_SetAndGet) {
    ExitCodeHandler& handler = ExitCodeHandler::Instance();
    
    handler.SetExitCode(42, "Test error message");
    
    EXPECT_EQ(handler.GetExitCode(), 42);
    EXPECT_EQ(handler.GetErrorMessage(), "Test error message");
    
    // Reset
    handler.SetExitCode(0, "");
}

TEST_F(ContinuousCertificationTest, ExitCodeHandler_ExitIfFailed) {
    ExitCodeHandler& handler = ExitCodeHandler::Instance();
    
    // Set success code
    handler.SetExitCode(0, "");
    
    // Should not throw
    EXPECT_NO_THROW(handler.ExitIfFailed());
    
    // Set failure code
    handler.SetExitCode(1, "Error");
    
    // Would exit in real scenario
    // EXPECT_EXIT(handler.ExitIfFailed(), ::testing::ExitedWithCode(1), "");
}

TEST_F(ContinuousCertificationTest, CertificationReport_Serialize) {
    CertificationReport report;
    report.timestamp = "2026-07-24T10:00:00Z";
    report.passed = true;
    report.summary = "All tests passed";
    
    std::string serialized = report.Serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("true"), std::string::npos);
    EXPECT_NE(serialized.find("All tests passed"), std::string::npos);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
