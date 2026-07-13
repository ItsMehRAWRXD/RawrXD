// Phase D.15 Batch 2/5: Lattice-Based Cryptography
// Advanced lattice-based encryption and signatures
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Crypto {

// Forward declarations
struct LatticeParams;
struct LatticeCiphertext;
struct LatticeSignature;

// ============================================================================
// Lattice Types
// ============================================================================

enum class LatticeScheme {
    // Learning With Errors (LWE) based
    LWE = 0,
    
    // Ring-LWE based
    RING_LWE = 1,
    
    // Module-LWE based (used in Kyber/Dilithium)
    MODULE_LWE = 2,
    
    // NTRU based
    NTRU = 3,
    
    // FALCON (Fast Fourier lattice-based compact signatures)
    FALCON = 4,
    
    // CRYSTALS-Kyber internal
    CRYSTALS_KYBER = 10,
    
    // CRYSTALS-Dilithium internal
    CRYSTALS_DILITHIUM = 11
};

enum class PolynomialRing {
    ZQ_X_N = 0,           // Z_q[x]/(x^n - 1)
    ZQ_X_N_PLUS_1 = 1,    // Z_q[x]/(x^n + 1) - Power-of-2 cyclotomic
    ZQ_X_PHI_N = 2        // Z_q[x]/Phi_n(x) - General cyclotomic
};

struct LatticeParams {
    int n;                    // Polynomial degree
    int q;                    // Modulus
    int k;                    // Module rank (for Module-LWE)
    double sigma;             // Error distribution width
    PolynomialRing ring;
    std::string hash_function;
    int security_bits;
};

struct LatticeKeyPair {
    LatticeScheme scheme;
    std::vector<std::vector<int64_t>> public_key;   // Polynomial coefficients
    std::vector<std::vector<int64_t>> secret_key;
    LatticeParams params;
    std::chrono::steady_clock::time_point created_at;
};

struct LatticeCiphertext {
    std::vector<std::vector<int64_t>> u;  // First component
    std::vector<int64_t> v;               // Second component
    LatticeParams params;
};

struct LatticeSignature {
    LatticeScheme scheme;
    std::vector<std::vector<int64_t>> z;  // Signature polynomial
    std::vector<uint8_t> challenge;       // Hash challenge
    std::vector<uint8_t> hint;           // Compression hint (for some schemes)
};

// ============================================================================
// Polynomial Operations
// ============================================================================

class PolynomialRing {
public:
    explicit PolynomialRing(const LatticeParams& params);
    
    // Ring operations
    std::vector<int64_t> Add(const std::vector<int64_t>& a, 
                             const std::vector<int64_t>& b) const;
    std::vector<int64_t> Subtract(const std::vector<int64_t>& a,
                                   const std::vector<int64_t>& b) const;
    std::vector<int64_t> Multiply(const std::vector<int64_t>& a,
                                   const std::vector<int64_t>& b) const;
    std::vector<int64_t> ScalarMultiply(const std::vector<int64_t>& a,
                                        int64_t scalar) const;
    
    // NTT (Number Theoretic Transform) for fast multiplication
    std::vector<int64_t> NTT(const std::vector<int64_t>& poly) const;
    std::vector<int64_t> InverseNTT(const std::vector<int64_t>& ntt_poly) const;
    std::vector<int64_t> NTTMultiply(const std::vector<int64_t>& a,
                                      const std::vector<int64_t>& b) const;
    
    // Sampling
    std::vector<int64_t> SampleUniform();
    std::vector<int64_t> SampleGaussian(double sigma);
    std::vector<int64_t> SampleBinary();
    std::vector<int64_t> SampleTernary();  // {-1, 0, 1}
    
    // Reduction
    std::vector<int64_t> ModReduce(const std::vector<int64_t>& poly) const;
    std::vector<int64_t> CenteredReduce(const std::vector<int64_t>& poly) const;
    
    // Serialization
    std::vector<uint8_t> Serialize(const std::vector<int64_t>& poly) const;
    std::vector<int64_t> Deserialize(const std::vector<uint8_t>& data) const;
    
private:
    LatticeParams params_;
    std::vector<int64_t> ntt_roots_;
    
    void ComputeNTTRoots();
    int64_t ModExp(int64_t base, int64_t exp, int64_t mod) const;
};

// ============================================================================
// LWE Encryption
// ============================================================================

class LWEEncryption {
public:
    struct Config {
        int n = 512;          // Secret dimension
        int q = 4096;         // Modulus
        double sigma = 3.2;   // Error standard deviation
        int m = 640;          // Number of samples
    };
    
    explicit LWEEncryption(const Config& config);
    ~LWEEncryption();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    LatticeKeyPair GenerateKeyPair();
    
    // Encryption
    LatticeCiphertext Encrypt(const std::vector<int64_t>& plaintext,
                              const std::vector<std::vector<int64_t>>& public_key);
    
    // Decryption
    std::vector<int64_t> Decrypt(const LatticeCiphertext& ciphertext,
                                  const std::vector<std::vector<int64_t>>& secret_key);
    
    // Homomorphic operations (limited)
    LatticeCiphertext AddCiphertexts(const LatticeCiphertext& ct1,
                                      const LatticeCiphertext& ct2);
    LatticeCiphertext AddPlaintext(const LatticeCiphertext& ct,
                                    const std::vector<int64_t>& pt);
    
    // Parameters
    int GetSecurityLevel() const;
    size_t GetPublicKeySize() const;
    size_t GetSecretKeySize() const;
    size_t GetCiphertextSize() const;
    
private:
    Config config_;
    std::unique_ptr<PolynomialRing> ring_;
    
    std::vector<int64_t> GenerateErrorVector();
    std::vector<std::vector<int64_t>> GenerateMatrixA();
};

// ============================================================================
// Ring-LWE Encryption
// ============================================================================

class RingLWEEncryption {
public:
    struct Config {
        int n = 1024;         // Polynomial degree (power of 2)
        int q = 12289;        // Prime modulus (q = 1 mod 2n)
        double sigma = 3.192; // Gaussian parameter
        bool use_ntt = true;  // Use NTT for fast operations
    };
    
    explicit RingLWEEncryption(const Config& config);
    ~RingLWEEncryption();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    LatticeKeyPair GenerateKeyPair();
    LatticeKeyPair GenerateKeyPairDeterministic(const std::vector<uint8_t>& seed);
    
    // Encryption
    LatticeCiphertext Encrypt(const std::vector<int64_t>& plaintext,
                              const std::vector<std::vector<int64_t>>& public_key);
    
    // Decryption
    std::vector<int64_t> Decrypt(const LatticeCiphertext& ciphertext,
                                  const std::vector<std::vector<int64_t>>& secret_key);
    
    // Optimized batch operations
    std::vector<LatticeCiphertext> EncryptBatch(
        const std::vector<std::vector<int64_t>>& plaintexts,
        const std::vector<std::vector<int64_t>>& public_key);
    
    std::vector<std::vector<int64_t>> DecryptBatch(
        const std::vector<LatticeCiphertext>& ciphertexts,
        const std::vector<std::vector<int64_t>>& secret_key);
    
private:
    Config config_;
    std::unique_ptr<PolynomialRing> ring_;
};

// ============================================================================
// FALCON Signatures
// ============================================================================

class FalconSignatures {
public:
    struct Config {
        int n = 512;          // Ring degree (512 or 1024)
        int q = 12289;        // Modulus
        double sigmin = 1.291956;  // Signature standard deviation
    };
    
    struct FalconKeyPair {
        std::vector<int64_t> f;       // Secret polynomial f
        std::vector<int64_t> g;       // Secret polynomial g
        std::vector<int64_t> F;       // Extended secret F
        std::vector<int64_t> G;       // Extended secret G
        std::vector<int64_t> h;       // Public key h = g/f mod q
    };
    
    explicit FalconSignatures(const Config& config);
    ~FalconSignatures();
    
    bool Initialize();
    void Shutdown();
    
    // Key generation
    FalconKeyPair GenerateKeyPair();
    
    // Signing (using fast Fourier sampling)
    LatticeSignature Sign(const std::vector<uint8_t>& message,
                          const FalconKeyPair& keypair);
    
    // Verification
    bool Verify(const std::vector<uint8_t>& message,
                const LatticeSignature& signature,
                const std::vector<int64_t>& public_key_h);
    
    // Sizes (Falcon has very compact signatures)
    size_t GetPublicKeySize() const;
    size_t GetSecretKeySize() const;
    size_t GetSignatureSize() const;  // ~666 bytes for n=512, ~1279 bytes for n=1024
    
private:
    Config config_;
    std::unique_ptr<PolynomialRing> ring_;
    
    // Fast Fourier sampling
    std::vector<double> FFT(const std::vector<int64_t>& poly);
    std::vector<int64_t> InverseFFT(const std::vector<double>& fft_poly);
    std::vector<int64_t> SampleGaussianFFT(const std::vector<double>& std_devs);
    
    // NTRU solving
    bool SolveNTRU(const std::vector<int64_t>& f, const std::vector<int64_t>& g,
                   std::vector<int64_t>& F, std::vector<int64_t>& G);
};

// ============================================================================
// Lattice-Based Key Derivation
// ============================================================================

class LatticeKDF {
public:
    struct Config {
        int iterations = 10000;
        int output_length = 32;
        std::string hash_algorithm = "SHA3-256";
    };
    
    explicit LatticeKDF(const Config& config);
    
    // Derive key from password using lattice-based hard problem
    std::vector<uint8_t> DeriveKey(const std::string& password,
                                    const std::vector<uint8_t>& salt);
    
    // Memory-hard derivation (resistant to ASIC/FPGA attacks)
    std::vector<uint8_t> DeriveKeyMemoryHard(const std::string& password,
                                              const std::vector<uint8_t>& salt,
                                              int memory_kb = 65536);
    
    // Lattice-based key stretching
    std::vector<uint8_t> StretchKey(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& salt,
                                     int iterations);
    
private:
    Config config_;
    
    std::vector<uint8_t> HashToLattice(const std::vector<uint8_t>& data);
    std::vector<uint8_t> LatticeWalk(const std::vector<int64_t>& start,
                                        int steps);
};

// ============================================================================
// Lattice Crypto Runtime
// ============================================================================

class LatticeCryptoRuntime {
public:
    struct Config {
        LWEEncryption::Config lwe;
        RingLWEEncryption::Config ring_lwe;
        FalconSignatures::Config falcon;
        LatticeKDF::Config kdf;
        LatticeScheme default_scheme = LatticeScheme::RING_LWE;
    };
    
    explicit LatticeCryptoRuntime(const Config& config);
    ~LatticeCryptoRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    LWEEncryption* GetLWE();
    RingLWEEncryption* GetRingLWE();
    FalconSignatures* GetFalcon();
    LatticeKDF* GetKDF();
    
    // High-level API
    LatticeKeyPair GenerateKeyPair(LatticeScheme scheme);
    LatticeCiphertext Encrypt(const std::vector<int64_t>& plaintext,
                             const std::vector<std::vector<int64_t>>& public_key,
                             LatticeScheme scheme);
    std::vector<int64_t> Decrypt(const LatticeCiphertext& ciphertext,
                                  const std::vector<std::vector<int64_t>>& secret_key,
                                  LatticeScheme scheme);
    
    LatticeSignature Sign(const std::vector<uint8_t>& message,
                          const LatticeKeyPair& keypair,
                          LatticeScheme scheme);
    bool Verify(const std::vector<uint8_t>& message,
                const LatticeSignature& signature,
                const std::vector<std::vector<int64_t>>& public_key,
                LatticeScheme scheme);
    
    // Parameter selection
    LatticeParams SelectParameters(int security_bits);
    int EstimateSecurityLevel(const LatticeParams& params);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<LWEEncryption> lwe_;
    std::unique_ptr<RingLWEEncryption> ring_lwe_;
    std::unique_ptr<FalconSignatures> falcon_;
    std::unique_ptr<LatticeKDF> kdf_;
};

} // namespace Crypto
} // namespace Sovereign
