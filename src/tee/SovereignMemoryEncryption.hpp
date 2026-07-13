// Phase D.16 Batch 4/5: Memory Encryption
// Secure memory management and encryption
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
namespace TEE {

// Forward declarations
struct EncryptedMemoryRegion;
struct MemoryKey;
struct SecureBuffer;

// ============================================================================
// Memory Encryption Types
// ============================================================================

enum class EncryptionAlgorithm {
    AES_256_GCM = 0,
    AES_256_XTS = 1,
    CHACHA20_POLY1305 = 2,
    AES_256_CBC_HMAC = 3,
    PLATFORM_TME = 4,      // Intel TME
    PLATFORM_SME = 5,      // AMD SME
    PLATFORM_MEE = 6       // Memory Encryption Engine
};

enum class KeyProtection {
    SOFTWARE = 0,
    HARDWARE_TPM = 1,
    HARDWARE_HSM = 2,
    ENCLAVE_SEALED = 3,
    PLATFORM_MKTME = 4     // Intel MKTME
};

enum class MemoryProtection {
    NONE = 0,
    READ_ONLY = 1,
    NO_EXECUTE = 2,
    GUARD_PAGE = 3,
    POISONED = 4
};

struct MemoryKey {
    std::string key_id;
    std::vector<uint8_t> key_data;
    EncryptionAlgorithm algorithm;
    KeyProtection protection;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point expires_at;
    int usage_count;
    int max_uses;
    std::map<std::string, std::any> metadata;
};

struct EncryptedMemoryRegion {
    std::string region_id;
    void* virtual_address;
    size_t size;
    EncryptionAlgorithm algorithm;
    std::string key_id;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    bool is_locked;
    MemoryProtection protection;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_accessed;
    int access_count;
};

struct SecureBuffer {
    std::string buffer_id;
    std::vector<uint8_t> data;
    size_t capacity;
    bool is_encrypted;
    std::string key_id;
    int lock_count;
    std::chrono::steady_clock::time_point created_at;
};

// ============================================================================
// Memory Encryption Engine
// ============================================================================

class MemoryEncryptionEngine {
public:
    struct Config {
        EncryptionAlgorithm default_algorithm = EncryptionAlgorithm::AES_256_GCM;
        KeyProtection key_protection = KeyProtection::ENCLAVE_SEALED;
        size_t page_size = 4096;
        bool use_platform_encryption = true;
        bool enable_integrity_check = true;
    };
    
    struct EncryptionResult {
        bool success;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> tag;
        std::vector<uint8_t> iv;
        std::string error_message;
    };
    
    struct DecryptionResult {
        bool success;
        std::vector<uint8_t> plaintext;
        std::string error_message;
    };
    
    explicit MemoryEncryptionEngine(const Config& config);
    ~MemoryEncryptionEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Key management
    MemoryKey GenerateKey(EncryptionAlgorithm algorithm, KeyProtection protection);
    bool DestroyKey(const std::string& key_id);
    bool RotateKey(const std::string& key_id);
    MemoryKey GetKey(const std::string& key_id) const;
    
    // Encryption/Decryption
    EncryptionResult Encrypt(const std::vector<uint8_t>& plaintext,
                             const MemoryKey& key);
    DecryptionResult Decrypt(const std::vector<uint8_t>& ciphertext,
                             const std::vector<uint8_t>& tag,
                             const std::vector<uint8_t>& iv,
                             const MemoryKey& key);
    
    // In-place encryption
    bool EncryptInPlace(void* buffer, size_t size, const MemoryKey& key);
    bool DecryptInPlace(void* buffer, size_t size, const MemoryKey& key);
    
    // Platform-specific
    bool InitializePlatformEncryption();
    bool EnableTME();
    bool EnableSME();
    bool ConfigureMKTME(const std::vector<MemoryKey>& keys);
    
private:
    Config config_;
    std::map<std::string, MemoryKey> keys_;
    mutable std::mutex keys_mutex_;
    void* platform_context_;
    
    std::vector<uint8_t> GenerateIV();
    std::vector<uint8_t> GenerateNonce();
    bool DeriveKey(const MemoryKey& master_key, const std::string& context,
                   std::vector<uint8_t>& derived_key);
};

// ============================================================================
// Secure Memory Allocator
// ============================================================================

class SecureMemoryAllocator {
public:
    struct Config {
        size_t min_allocation_size = 4096;
        size_t max_allocation_size = 1024 * 1024 * 1024;  // 1GB
        bool zero_on_free = true;
        bool guard_pages = true;
        bool randomize_addresses = true;
        int guard_page_count = 1;
    };
    
    struct AllocationStats {
        size_t total_allocated;
        size_t total_freed;
        size_t active_allocations;
        size_t peak_usage;
        size_t fragmentation;
    };
    
    explicit SecureMemoryAllocator(const Config& config);
    ~SecureMemoryAllocator();
    
    bool Initialize();
    void Shutdown();
    
    // Allocation
    void* Allocate(size_t size);
    void* AllocateAligned(size_t size, size_t alignment);
    void* AllocateZeroed(size_t size);
    void* Reallocate(void* ptr, size_t new_size);
    
    // Deallocation
    void Free(void* ptr);
    void SecureFree(void* ptr);  // Overwrite before free
    
    // Protection
    bool ProtectReadOnly(void* ptr);
    bool ProtectNoExecute(void* ptr);
    bool ProtectReadWrite(void* ptr);
    bool LockPages(void* ptr, size_t size);
    bool UnlockPages(void* ptr, size_t size);
    
    // Queries
    size_t GetAllocationSize(void* ptr) const;
    AllocationStats GetStats() const;
    bool IsSecureMemory(void* ptr) const;
    
private:
    Config config_;
    std::map<void*, size_t> allocations_;
    mutable std::mutex allocations_mutex_;
    AllocationStats stats_;
    
    void* AllocateInternal(size_t size, bool zero);
    void SecureZero(void* ptr, size_t size);
    bool SetMemoryProtection(void* ptr, size_t size, int protection);
};

// ============================================================================
// Encrypted Memory Pool
// ============================================================================

class EncryptedMemoryPool {
public:
    struct Config {
        size_t pool_size = 100 * 1024 * 1024;  // 100MB
        size_t block_size = 65536;             // 64KB
        EncryptionAlgorithm algorithm = EncryptionAlgorithm::AES_256_GCM;
        bool lazy_encryption = false;
        int max_pools = 10;
    };
    
    struct PoolStats {
        size_t total_size;
        size_t used_size;
        size_t free_size;
        int active_regions;
        int encrypted_regions;
        int locked_regions;
    };
    
    explicit EncryptedMemoryPool(const Config& config);
    ~EncryptedMemoryPool();
    
    bool Initialize();
    void Shutdown();
    
    // Region management
    EncryptedMemoryRegion* AllocateRegion(size_t size);
    bool FreeRegion(EncryptedMemoryRegion* region);
    bool ResizeRegion(EncryptedMemoryRegion* region, size_t new_size);
    
    // Encryption control
    bool EncryptRegion(EncryptedMemoryRegion* region);
    bool DecryptRegion(EncryptedMemoryRegion* region);
    bool LockRegion(EncryptedMemoryRegion* region);
    bool UnlockRegion(EncryptedMemoryRegion* region);
    
    // Access
    void* MapRegion(EncryptedMemoryRegion* region);
    bool UnmapRegion(EncryptedMemoryRegion* region);
    bool SyncRegion(EncryptedMemoryRegion* region);
    
    // Stats
    PoolStats GetStats() const;
    std::vector<EncryptedMemoryRegion> GetRegions() const;
    
private:
    Config config_;
    void* pool_base_;
    std::map<std::string, EncryptedMemoryRegion> regions_;
    mutable std::mutex regions_mutex_;
    std::unique_ptr<MemoryEncryptionEngine> encryption_engine_;
    
    std::string GenerateRegionId();
    bool EncryptPage(void* page, size_t size);
    bool DecryptPage(void* page, size_t size);
};

// ============================================================================
// Secure Buffer Manager
// ============================================================================

class SecureBufferManager {
public:
    struct Config {
        size_t default_buffer_size = 8192;
        size_t max_buffer_size = 1024 * 1024;  // 1MB
        int max_buffers = 1000;
        bool auto_encrypt = true;
        std::chrono::seconds idle_timeout{300};
    };
    
    explicit SecureBufferManager(const Config& config);
    ~SecureBufferManager();
    
    bool Initialize();
    void Shutdown();
    
    // Buffer operations
    SecureBuffer* CreateBuffer(size_t size);
    SecureBuffer* CreateBufferFromData(const std::vector<uint8_t>& data);
    bool DestroyBuffer(SecureBuffer* buffer);
    bool ResizeBuffer(SecureBuffer* buffer, size_t new_size);
    
    // Encryption
    bool EncryptBuffer(SecureBuffer* buffer);
    bool DecryptBuffer(SecureBuffer* buffer);
    bool LockBuffer(SecureBuffer* buffer);
    bool UnlockBuffer(SecureBuffer* buffer);
    
    // Access
    std::vector<uint8_t> ReadBuffer(const SecureBuffer* buffer);
    bool WriteBuffer(SecureBuffer* buffer, const std::vector<uint8_t>& data);
    bool AppendToBuffer(SecureBuffer* buffer, const std::vector<uint8_t>& data);
    
    // Zeroing
    bool ZeroBuffer(SecureBuffer* buffer);
    bool SecureClear(SecureBuffer* buffer);
    
    // Queries
    size_t GetBufferSize(const SecureBuffer* buffer) const;
    bool IsBufferEncrypted(const SecureBuffer* buffer) const;
    bool IsBufferLocked(const SecureBuffer* buffer) const;
    
private:
    Config config_;
    std::map<std::string, std::unique_ptr<SecureBuffer>> buffers_;
    mutable std::mutex buffers_mutex_;
    std::unique_ptr<MemoryEncryptionEngine> encryption_engine_;
    std::thread cleanup_thread_;
    std::atomic<bool> running_{false};
    
    void CleanupLoop();
    void CleanupIdleBuffers();
    std::string GenerateBufferId();
};

// ============================================================================
// Memory Sanitizer
// ============================================================================

class MemorySanitizer {
public:
    struct Config {
        bool detect_use_after_free = true;
        bool detect_buffer_overflow = true;
        bool detect_uninitialized_read = true;
        bool poison_freed_memory = true;
        uint8_t poison_value = 0xDE;
    };
    
    struct SanitizerReport {
        std::string error_type;
        void* address;
        size_t size;
        std::string allocation_stack;
        std::string access_stack;
        std::chrono::steady_clock::time_point detected_at;
    };
    
    explicit MemorySanitizer(const Config& config);
    ~MemorySanitizer();
    
    bool Initialize();
    void Shutdown();
    
    // Monitoring
    void TrackAllocation(void* ptr, size_t size);
    void TrackDeallocation(void* ptr);
    void TrackAccess(void* ptr, size_t size, bool is_write);
    
    // Poisoning
    void PoisonMemory(void* ptr, size_t size);
    void UnpoisonMemory(void* ptr, size_t size);
    bool IsPoisoned(void* ptr) const;
    
    // Checks
    bool CheckAccess(void* ptr, size_t size, bool is_write);
    bool CheckBufferOverflow(void* ptr, size_t access_size);
    bool CheckUseAfterFree(void* ptr);
    bool CheckUninitialized(void* ptr, size_t size);
    
    // Reports
    std::vector<SanitizerReport> GetReports() const;
    void ClearReports();
    
private:
    Config config_;
    std::map<void*, size_t> allocations_;
    std::set<void*> freed_regions_;
    std::map<void*, bool> initialized_regions_;
    std::vector<SanitizerReport> reports_;
    mutable std::mutex sanitizer_mutex_;
    
    void ReportError(const std::string& type, void* address, size_t size);
};

// ============================================================================
// Memory Encryption Runtime
// ============================================================================

class MemoryEncryptionRuntime {
public:
    struct Config {
        MemoryEncryptionEngine::Config engine;
        SecureMemoryAllocator::Config allocator;
        EncryptedMemoryPool::Config pool;
        SecureBufferManager::Config buffer;
        MemorySanitizer::Config sanitizer;
    };
    
    explicit MemoryEncryptionRuntime(const Config& config);
    ~MemoryEncryptionRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    MemoryEncryptionEngine* GetEngine();
    SecureMemoryAllocator* GetAllocator();
    EncryptedMemoryPool* GetPool();
    SecureBufferManager* GetBufferManager();
    MemorySanitizer* GetSanitizer();
    
    // High-level API
    void* SecureAllocate(size_t size);
    void SecureFree(void* ptr);
    
    SecureBuffer* CreateSecureBuffer(const std::vector<uint8_t>& data);
    bool DestroySecureBuffer(SecureBuffer* buffer);
    
    EncryptedMemoryRegion* CreateEncryptedRegion(size_t size);
    bool DestroyEncryptedRegion(EncryptedMemoryRegion* region);
    
    bool EncryptMemory(void* ptr, size_t size);
    bool DecryptMemory(void* ptr, size_t size);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<MemoryEncryptionEngine> engine_;
    std::unique_ptr<SecureMemoryAllocator> allocator_;
    std::unique_ptr<EncryptedMemoryPool> pool_;
    std::unique_ptr<SecureBufferManager> buffer_manager_;
    std::unique_ptr<MemorySanitizer> sanitizer_;
};

} // namespace TEE
} // namespace Sovereign
