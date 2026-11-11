// VAL-075: Supply Chain Provenance Tests
// Build traceability and reproducibility verification

#include <gtest/gtest.h>
#include "certification/supply_chain_provenance.hpp"
#include <filesystem>
#include <fstream>

using namespace RawrXD::Certification;

class SupplyChainProvenanceTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "rawrxd_test_provenance";
        std::filesystem::create_directories(test_dir_);
    }
    
    void TearDown() override {
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
};

TEST_F(SupplyChainProvenanceTest, SourceCommit_ComputeIdentity) {
    SourceCommit commit;
    commit.hash = "abc123";
    commit.tree_hash = "def456";
    commit.message = "Test commit";
    commit.author = "Test Author";
    commit.timestamp = "2026-07-24T00:00:00Z";
    
    std::string identity = commit.ComputeIdentity();
    EXPECT_FALSE(identity.empty());
    EXPECT_NE(identity.find("abc123"), std::string::npos);
    EXPECT_NE(identity.find("def456"), std::string::npos);
}

TEST_F(SupplyChainProvenanceTest, SourceCommit_Serialize) {
    SourceCommit commit;
    commit.hash = "abc123";
    commit.message = "Test commit";
    commit.author = "Test Author";
    commit.timestamp = "2026-07-24T00:00:00Z";
    commit.tree_hash = "def456";
    
    std::string serialized = commit.Serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("abc123"), std::string::npos);
    EXPECT_NE(serialized.find("Test commit"), std::string::npos);
}

TEST_F(SupplyChainProvenanceTest, CompilerFingerprint_ComputeFingerprint) {
    CompilerFingerprint compiler;
    compiler.name = "GCC";
    compiler.version = "11.2.0";
    compiler.path = "/usr/bin/gcc";
    compiler.target_triple = "x86_64-linux-gnu";
    compiler.executable_hash = "hash123";
    
    std::string fingerprint = compiler.ComputeFingerprint();
    EXPECT_FALSE(fingerprint.empty());
    EXPECT_NE(fingerprint.find("GCC"), std::string::npos);
    EXPECT_NE(fingerprint.find("11.2.0"), std::string::npos);
}

TEST_F(SupplyChainProvenanceTest, BuildFlags_ComputeFlagsHash) {
    BuildFlags flags;
    flags.flags = {"-O3", "-march=native"};
    flags.defines["VERSION"] = "1.0.0";
    flags.defines["DEBUG"] = "0";
    
    std::string hash = flags.ComputeFlagsHash();
    EXPECT_FALSE(hash.empty());
    
    // Same flags should produce same hash
    std::string hash2 = flags.ComputeFlagsHash();
    EXPECT_EQ(hash, hash2);
}

TEST_F(SupplyChainProvenanceTest, DependencyHashes_ComputeDependenciesHash) {
    DependencyHashes deps;
    deps.dependencies["ggml"] = "v1.2.3";
    deps.dependencies["json"] = "v3.11.2";
    deps.lock_file_hash = "lock_hash";
    
    std::string hash = deps.ComputeDependenciesHash();
    EXPECT_FALSE(hash.empty());
    
    // Same dependencies should produce same hash
    std::string hash2 = deps.ComputeDependenciesHash();
    EXPECT_EQ(hash, hash2);
}

TEST_F(SupplyChainProvenanceTest, SupplyChainProvenance_ComputeProvenanceHash) {
    SupplyChainProvenance provenance;
    
    provenance.inputs.source.hash = "abc123";
    provenance.inputs.compiler.name = "GCC";
    provenance.inputs.flags.flags = {"-O3"};
    provenance.inputs.dependencies.dependencies["ggml"] = "v1.2.3";
    
    provenance.binary_path = "/build/rawrxd";
    provenance.binary_hash = "binary_hash";
    
    bool result = provenance.ComputeProvenanceHash();
    EXPECT_TRUE(result);
    EXPECT_FALSE(provenance.provenance_hash.empty());
}

TEST_F(SupplyChainProvenanceTest, SupplyChainProvenance_Serialize) {
    SupplyChainProvenance provenance;
    provenance.inputs.source.hash = "abc123";
    provenance.binary_path = "/build/rawrxd";
    provenance.binary_hash = "binary_hash";
    provenance.provenance_hash = "prov_hash";
    
    std::string serialized = provenance.Serialize();
    EXPECT_FALSE(serialized.empty());
    EXPECT_NE(serialized.find("abc123"), std::string::npos);
    EXPECT_NE(serialized.find("binary_hash"), std::string::npos);
}

TEST_F(SupplyChainProvenanceTest, ProvenanceCollector_CaptureSourceCommit) {
    ProvenanceCollector collector;
    
    // This will fail in test environment without git
    // but should handle gracefully
    SourceCommit commit = collector.CaptureSourceCommit();
    
    // In a real environment, these would be populated
    // In test, they may be empty but shouldn't crash
    EXPECT_NO_THROW(commit.Serialize());
}

TEST_F(SupplyChainProvenanceTest, ProvenanceCollector_CaptureCompilerFingerprint) {
    ProvenanceCollector collector;
    
    CompilerFingerprint compiler = collector.CaptureCompilerFingerprint();
    
    EXPECT_FALSE(compiler.name.empty());
    EXPECT_FALSE(compiler.version.empty());
}

TEST_F(SupplyChainProvenanceTest, ProvenanceCollector_CaptureBuildFlags) {
    ProvenanceCollector collector;
    
    BuildFlags flags = collector.CaptureBuildFlags();
    
    EXPECT_FALSE(flags.flags.empty());
    EXPECT_FALSE(flags.defines.empty());
}

TEST_F(SupplyChainProvenanceTest, ReproducibilityProofVerifier_Verify) {
    // Create a mock provenance
    SupplyChainProvenance provenance;
    provenance.inputs.source.hash = "abc123";
    provenance.inputs.compiler.version = "11.2.0";
    provenance.inputs.flags.flags = {"-O3"};
    provenance.binary_path = "/build/rawrxd";
    provenance.binary_hash = "binary_hash";
    provenance.ComputeProvenanceHash();
    
    // Create test binary
    std::filesystem::path test_binary = test_dir_ / "rawrxd";
    std::ofstream file(test_binary);
    file << "binary content";
    file.close();
    
    ReproducibilityProofVerifier verifier;
    auto result = verifier.VerifyReproducibility(provenance, test_binary.string());
    
    // In real test, would verify actual reproducibility
    EXPECT_FALSE(result.source_matches); // Different source
    EXPECT_FALSE(result.compiler_matches); // Different compiler
}

TEST_F(SupplyChainProvenanceTest, ReproducibilityProofVerifier_CompareBuilds) {
    SupplyChainProvenance build1;
    build1.binary_hash = "hash1";
    
    SupplyChainProvenance build2;
    build2.binary_hash = "hash1";
    
    SupplyChainProvenance build3;
    build3.binary_hash = "hash2";
    
    ReproducibilityProofVerifier verifier;
    
    EXPECT_TRUE(verifier.CompareBuilds(build1, build2));
    EXPECT_FALSE(verifier.CompareBuilds(build1, build3));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
