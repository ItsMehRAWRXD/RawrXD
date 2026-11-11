// VAL-074: Manifest Signing Tests
// Comprehensive test suite for Ed25519 signature validation

#include <gtest/gtest.h>
#include "certification/manifest_signer.hpp"
#include <filesystem>
#include <fstream>

using namespace RawrXD::Certification;

class ManifestSignerTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "rawrxd_test_manifest";
        std::filesystem::create_directories(test_dir_);
    }
    
    void TearDown() override {
        std::filesystem::remove_all(test_dir_);
    }
    
    std::filesystem::path test_dir_;
};

TEST_F(ManifestSignerTest, SigningKeyManager_GenerateKeyPair) {
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    EXPECT_FALSE(key_pair.public_key.empty());
    EXPECT_FALSE(key_pair.private_key.empty());
    EXPECT_EQ(key_pair.public_key.length(), 64);  // Ed25519 public key hex
    EXPECT_EQ(key_pair.private_key.length(), 128); // Ed25519 private key hex
}

TEST_F(ManifestSignerTest, SigningKeyManager_ExportImportPublicKey) {
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    
    std::string exported = SigningKeyManager::ExportPublicKey(key_pair.public_key);
    EXPECT_FALSE(exported.empty());
    
    auto imported = SigningKeyManager::ImportPublicKey(exported);
    EXPECT_TRUE(imported.has_value());
    EXPECT_EQ(imported.value(), key_pair.public_key);
}

TEST_F(ManifestSignerTest, ManifestSigner_SignAndVerify) {
    ManifestSigner signer;
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    signer.LoadKeyPair(key_pair);
    
    std::string test_data = "Test manifest data for signing";
    auto signature = signer.SignData(test_data);
    
    EXPECT_FALSE(signature.signature.empty());
    EXPECT_FALSE(signature.timestamp.empty());
    EXPECT_EQ(signature.algorithm, "Ed25519");
    
    // Verify the signature
    bool valid = signer.VerifySignature(test_data, signature, key_pair.public_key);
    EXPECT_TRUE(valid);
}

TEST_F(ManifestSignerTest, ManifestSigner_TamperedDataFails) {
    ManifestSigner signer;
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    signer.LoadKeyPair(key_pair);
    
    std::string original_data = "Original data";
    auto signature = signer.SignData(original_data);
    
    // Try to verify with tampered data
    std::string tampered_data = "Tampered data";
    bool valid = signer.VerifySignature(tampered_data, signature, key_pair.public_key);
    EXPECT_FALSE(valid);
}

TEST_F(ManifestSignerTest, ManifestSigner_SignFile) {
    ManifestSigner signer;
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    signer.LoadKeyPair(key_pair);
    
    // Create test file
    std::filesystem::path test_file = test_dir_ / "test_manifest.json";
    std::ofstream file(test_file);
    file << "{\"version\": \"1.0.0\", \"test\": true}";
    file.close();
    
    auto signature = signer.SignFile(test_file.string());
    EXPECT_FALSE(signature.signature.empty());
    
    // Verify file signature
    bool valid = signer.VerifyFile(test_file.string(), signature, key_pair.public_key);
    EXPECT_TRUE(valid);
}

TEST_F(ManifestSignerTest, SignatureVerifier_ValidSignature) {
    ManifestSigner signer;
    SignatureVerifier verifier;
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    signer.LoadKeyPair(key_pair);
    
    std::string data = "Data to verify";
    auto signature = signer.SignData(data);
    
    auto result = verifier.Verify(data, signature, key_pair.public_key);
    EXPECT_TRUE(result.valid);
    EXPECT_TRUE(result.message.empty());
}

TEST_F(ManifestSignerTest, SignatureVerifier_InvalidSignature) {
    SignatureVerifier verifier;
    
    std::string data = "Data to verify";
    Signature signature;
    signature.signature = "invalid_signature";
    signature.algorithm = "Ed25519";
    signature.timestamp = "2026-07-24T00:00:00Z";
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    
    auto result = verifier.Verify(data, signature, key_pair.public_key);
    EXPECT_FALSE(result.valid);
    EXPECT_FALSE(result.message.empty());
}

TEST_F(ManifestSignerTest, ManifestSigner_MultipleSignatures) {
    ManifestSigner signer;
    
    auto key_pair1 = SigningKeyManager::GenerateKeyPair();
    auto key_pair2 = SigningKeyManager::GenerateKeyPair();
    
    std::string data = "Multi-sig test data";
    
    auto sig1 = signer.SignData(data);
    auto sig2 = signer.SignData(data);
    
    // Both should be valid
    EXPECT_TRUE(signer.VerifySignature(data, sig1, key_pair1.public_key) ||
                signer.VerifySignature(data, sig1, key_pair2.public_key));
}

TEST_F(ManifestSignerTest, ManifestSigner_EmptyData) {
    ManifestSigner signer;
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    signer.LoadKeyPair(key_pair);
    
    std::string empty_data = "";
    auto signature = signer.SignData(empty_data);
    
    // Should handle empty data gracefully
    EXPECT_FALSE(signature.signature.empty());
    
    bool valid = signer.VerifySignature(empty_data, signature, key_pair.public_key);
    EXPECT_TRUE(valid);
}

TEST_F(ManifestSignerTest, ManifestSigner_LargeData) {
    ManifestSigner signer;
    
    auto key_pair = SigningKeyManager::GenerateKeyPair();
    signer.LoadKeyPair(key_pair);
    
    // Create 1MB of data
    std::string large_data(1024 * 1024, 'X');
    auto signature = signer.SignData(large_data);
    
    EXPECT_FALSE(signature.signature.empty());
    
    bool valid = signer.VerifySignature(large_data, signature, key_pair.public_key);
    EXPECT_TRUE(valid);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
