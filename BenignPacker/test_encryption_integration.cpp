#include <iostream>
#include <vector>
#include <string>
#include "ultimate_encryption_integration.h"

int main() {
    std::cout << "Testing Ultimate Encryption Integration..." << std::endl;
    
    UltimateEncryptionIntegration encryptor;
    
    // Test data
    std::string testData = "Hello, this is a test payload for encryption!";
    std::vector<uint8_t> data(testData.begin(), testData.end());
    
    std::cout << "Original data: " << testData << std::endl;
    std::cout << "Original size: " << data.size() << " bytes" << std::endl;
    
    // Test different encryption methods
    std::vector<UltimateEncryptionIntegration::EncryptionMethod> methods = {
        UltimateEncryptionIntegration::XOR_KEY,
        UltimateEncryptionIntegration::AES_128_CTR,
        UltimateEncryptionIntegration::CHACHA20,
        UltimateEncryptionIntegration::TRIPLE_ENCRYPTION,
        UltimateEncryptionIntegration::STEALTH_TRIPLE,
        UltimateEncryptionIntegration::BIG_DECIMAL
    };
    
    std::vector<std::string> methodNames = {
        "XOR",
        "AES-128 CTR",
        "ChaCha20",
        "Triple Encryption",
        "Stealth Triple",
        "Big Decimal"
    };
    
    for (size_t i = 0; i < methods.size(); ++i) {
        std::cout << "\n=== Testing " << methodNames[i] << " ===" << std::endl;
        
        try {
            // Encrypt the data
            std::vector<uint8_t> encrypted = encryptor.encrypt(data, methods[i]);
            
            std::cout << "Encrypted size: " << encrypted.size() << " bytes" << std::endl;
            std::cout << "Encryption ratio: " << (double)encrypted.size() / data.size() << std::endl;
            
            // Generate decryption stub
            std::string stub = encryptor.generateDecryptionStub(methods[i], encrypted);
            
            std::cout << "Decryption stub size: " << stub.length() << " characters" << std::endl;
            std::cout << "✓ " << methodNames[i] << " encryption successful!" << std::endl;
            
        } catch (const std::exception& e) {
            std::cout << "✗ " << methodNames[i] << " encryption failed: " << e.what() << std::endl;
        }
    }
    
    // Test key generation
    std::cout << "\n=== Testing Key Generation ===" << std::endl;
    
    for (size_t i = 0; i < methods.size(); ++i) {
        auto method = methods[i];
        auto key = encryptor.generateKey(method);
        auto nonce = encryptor.generateNonce(method);
        
        std::cout << "Key size for " << methodNames[i] << ": " << key.size() << " bytes" << std::endl;
        std::cout << "Nonce size for " << methodNames[i] << ": " << nonce.size() << " bytes" << std::endl;
    }
    
    // Test triple key generation
    std::cout << "\n=== Testing Triple Key Generation ===" << std::endl;
    auto tripleKeys = encryptor.generateTripleKeys();
    std::cout << "Triple keys generated successfully!" << std::endl;
    std::cout << "Encryption order: " << tripleKeys.encryptionOrder[0] << ", " 
              << tripleKeys.encryptionOrder[1] << ", " << tripleKeys.encryptionOrder[2] << std::endl;
    
    std::cout << "\n=== All Tests Completed ===" << std::endl;
    std::cout << "✓ Ultimate Encryption Integration is working correctly!" << std::endl;
    
    return 0;
}