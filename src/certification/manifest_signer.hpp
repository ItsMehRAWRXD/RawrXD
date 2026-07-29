// VAL-074: Certification Manifest Signing
// Cryptographic signatures for evidence integrity

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Signature Types
// ============================================================================

enum class SignatureAlgorithm {
    Ed25519,        // Recommended
    ECDSA_P256,
    RSA_PSS_SHA256,
    None
};

struct SignerIdentity {
    std::string name;              // "RawrXD Release Authority"
    std::string public_key_id;     // Key fingerprint
    std::string public_key_pem;    // PEM-encoded public key
    std::string organization;      // "RawrXD Project"
    std::string contact;           // security@rawrxd.ai
    
    std::string Serialize() const;
    std::string ComputeKeyFingerprint() const;
};

struct SignatureMetadata {
    std::string signed_at;         // ISO 8601 timestamp
    std::string timestamp_authority; // Optional TSA URL
    std::string timestamp_token;   // RFC 3161 timestamp token
    uint64_t unix_timestamp;       // Unix nanoseconds
    
    std::string Serialize() const;
};

struct ManifestSignature {
    std::string manifest_hash;     // Hash of evidence manifest
    std::string signature;         // Base64-encoded signature
    std::string algorithm;         // "Ed25519", "ECDSA_P256", etc.
    SignerIdentity signer;
    SignatureMetadata metadata;
    
    // Verification policy
    std::vector<std::string> required_verifiers;
    int minimum_signatures;
    
    bool Verify(const std::string& public_key) const;
    std::string Serialize() const;
};

// ============================================================================
// Signing Key Management
// ============================================================================

class SigningKeyManager {
public:
    SigningKeyManager();
    ~SigningKeyManager();
    
    // Key generation
    bool GenerateKeyPair(SignatureAlgorithm algorithm);
    
    // Key loading
    bool LoadPrivateKey(const std::string& path);
    bool LoadPublicKey(const std::string& path);
    
    // Key export
    bool ExportPublicKey(const std::string& path) const;
    std::string GetPublicKeyPEM() const;
    
    // Signing
    std::string Sign(const std::string& data) const;
    bool Verify(const std::string& data, const std::string& signature) const;
    
    // Key identity
    SignerIdentity GetIdentity() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Manifest Signer
// ============================================================================

class ManifestSigner {
public:
    ManifestSigner();
    ~ManifestSigner();
    
    // Initialize with signing key
    bool Initialize(SigningKeyManager* key_manager);
    
    // Sign evidence manifest
    ManifestSignature SignManifest(
        const std::string& manifest_path,
        const SignerIdentity& signer
    );
    
    // Sign with timestamp authority
    ManifestSignature SignManifestWithTimestamp(
        const std::string& manifest_path,
        const SignerIdentity& signer,
        const std::string& tsa_url
    );
    
    // Batch sign multiple manifests
    std::vector<ManifestSignature> SignManifests(
        const std::vector<std::string>& manifest_paths,
        const SignerIdentity& signer
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Signature Verifier
// ============================================================================

class SignatureVerifier {
public:
    SignatureVerifier();
    ~SignatureVerifier();
    
    // Verify manifest signature
    bool VerifyManifest(
        const std::string& manifest_path,
        const ManifestSignature& signature,
        const std::string& public_key_pem
    );
    
    // Verify with timestamp
    bool VerifyWithTimestamp(
        const ManifestSignature& signature,
        const std::string& tsa_cert_path
    );
    
    // Get verification report
    struct VerificationReport {
        bool signature_valid;
        bool manifest_hash_match;
        bool timestamp_valid;
        bool signer_trusted;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        
        bool IsValid() const {
            return signature_valid && manifest_hash_match &&
                   timestamp_valid && signer_trusted;
        }
    };
    VerificationReport GetReport() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Signed Evidence Manifest
// ============================================================================

struct SignedEvidenceManifest {
    // Original manifest
    std::string schema;
    std::string release;
    std::vector<std::string> artifacts;
    std::string root_hash;
    
    // Signature
    ManifestSignature signature;
    
    // Verification
    bool Verify(const std::string& public_key) const;
    std::string Serialize() const;
    static std::optional<SignedEvidenceManifest> Load(const std::string& path);
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Key management
typedef struct Val074KeyManager* Val074KeyHandle;

Val074KeyHandle val074_key_manager_create();
int val074_key_generate(Val074KeyHandle handle, int algorithm);
int val074_key_load_private(Val074KeyHandle handle, const char* path);
int val074_key_load_public(Val074KeyHandle handle, const char* path);
const char* val074_key_get_public_pem(Val074KeyHandle handle);
void val074_key_destroy(Val074KeyHandle handle);

// Signing
typedef struct Val074Signer* Val074SignerHandle;

Val074SignerHandle val074_signer_create(Val074KeyHandle key_handle);
const char* val074_sign_manifest(
    Val074SignerHandle handle,
    const char* manifest_path,
    const char* signer_name
);
void val074_signer_destroy(Val074SignerHandle handle);

// Verification
typedef struct Val074Verifier* Val074VerifierHandle;

Val074VerifierHandle val074_verifier_create();
int val074_verify_manifest(
    Val074VerifierHandle handle,
    const char* manifest_path,
    const char* signature_json,
    const char* public_key_pem
);
const char* val074_verifier_get_report(Val074VerifierHandle handle);
void val074_verifier_destroy(Val074VerifierHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
