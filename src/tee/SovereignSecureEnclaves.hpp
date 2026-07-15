// Phase D.16 Batch 2/5: Secure Enclaves
// Enclave development and management framework
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
struct EnclaveManifest;
struct EnclaveInterface;
struct SecureChannel;

// ============================================================================
// Secure Enclave Types
// ============================================================================

enum class EnclaveLanguage {
    C = 0,
    CPP = 1,
    RUST = 2,
    ASSEMBLY = 3
};

enum class EnclaveState {
    UNLOADED = 0,
    LOADING = 1,
    INITIALIZED = 2,
    RUNNING = 3,
    PAUSED = 4,
    TERMINATED = 5,
    CRASHED = 6
};

enum class EnclavePrivilege {
    UNTRUSTED = 0,
    STANDARD = 1,
    PRIVILEGED = 2,
    SYSTEM = 3
};

struct EnclaveManifest {
    std::string enclave_id;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    EnclaveLanguage language;
    size_t memory_size;
    size_t stack_size;
    size_t heap_size;
    int max_threads;
    EnclavePrivilege privilege_level;
    std::vector<std::string> required_capabilities;
    std::vector<std::string> exported_functions;
    std::vector<std::string> imported_functions;
    std::map<std::string, std::any> metadata;
    std::vector<uint8_t> signature;
    std::chrono::steady_clock::time_point created_at;
};

struct EnclaveInterface {
    std::string function_name;
    uint32_t function_id;
    std::vector<std::string> input_types;
    std::string output_type;
    size_t max_input_size;
    size_t max_output_size;
    bool is_async;
    std::chrono::milliseconds timeout;
};

struct SecureChannel {
    std::string channel_id;
    std::string enclave_id;
    std::vector<uint8_t> session_key;
    std::vector<uint8_t> iv;
    uint64_t sequence_number;
    std::chrono::steady_clock::time_point established_at;
    std::chrono::steady_clock::time_point expires_at;
    bool is_encrypted;
    bool is_authenticated;
};

// ============================================================================
// Enclave Builder
// ============================================================================

class EnclaveBuilder {
public:
    struct Config {
        EnclaveLanguage language = EnclaveLanguage::CPP;
        std::string sdk_path;
        std::string compiler_flags;
        bool optimize = true;
        bool debug_symbols = false;
        bool enable_lvi_mitigation = true;  // Load Value Injection
    };
    
    struct BuildResult {
        bool success;
        std::string output_path;
        std::string signed_enclave_path;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        EnclaveManifest manifest;
        size_t code_size;
        size_t data_size;
        std::chrono::steady_clock::time_point build_time;
    };
    
    explicit EnclaveBuilder(const Config& config);
    ~EnclaveBuilder();
    
    bool Initialize();
    void Shutdown();
    
    // Source management
    bool AddSourceFile(const std::string& path);
    bool AddHeaderFile(const std::string& path);
    bool AddLibrary(const std::string& path);
    bool SetEntryPoint(const std::string& function_name);
    
    // EDL (Enclave Definition Language)
    bool ParseEDL(const std::string& edl_path);
    bool GenerateEdgeFiles();
    
    // Build process
    BuildResult Build(const std::string& output_name);
    BuildResult BuildAndSign(const std::string& output_name,
                             const std::string& signing_key);
    
    // Signing
    bool SignEnclave(const std::string& unsigned_enclave,
                     const std::string& signing_key,
                     const std::string& output_path);
    bool GenerateSigningKey(const std::string& output_path);
    
    // Verification
    bool VerifySignature(const std::string& signed_enclave);
    EnclaveManifest ExtractManifest(const std::string& signed_enclave);
    
private:
    Config config_;
    std::vector<std::string> source_files_;
    std::vector<std::string> header_files_;
    std::vector<std::string> libraries_;
    std::string entry_point_;
    std::string edl_file_;
    
    bool CompileSources(const std::string& build_dir);
    bool LinkEnclave(const std::string& build_dir, const std::string& output);
    bool GenerateManifest(const std::string& enclave_path, EnclaveManifest& manifest);
};

// ============================================================================
// Enclave Loader
// ============================================================================

class EnclaveLoader {
public:
    struct Config {
        size_t max_loaded_enclaves = 10;
        size_t total_memory_limit = 1024 * 1024 * 1024;  // 1GB
        bool verify_signatures = true;
        std::vector<std::string> trusted_signers;
        bool allow_debug_enclaves = false;
    };
    
    struct LoadedEnclave {
        std::string enclave_id;
        std::string path;
        EnclaveManifest manifest;
        EnclaveState state;
        void* native_handle;
        size_t memory_base;
        size_t memory_size;
        std::chrono::steady_clock::time_point loaded_at;
        int ref_count;
    };
    
    explicit EnclaveLoader(const Config& config);
    ~EnclaveLoader();
    
    bool Initialize();
    void Shutdown();
    
    // Loading
    std::string LoadEnclave(const std::string& enclave_path);
    bool UnloadEnclave(const std::string& enclave_id);
    bool ReloadEnclave(const std::string& enclave_id);
    
    // Reference counting
    bool AddReference(const std::string& enclave_id);
    bool ReleaseReference(const std::string& enclave_id);
    int GetReferenceCount(const std::string& enclave_id) const;
    
    // Queries
    LoadedEnclave GetEnclaveInfo(const std::string& enclave_id) const;
    std::vector<LoadedEnclave> GetLoadedEnclaves() const;
    std::vector<LoadedEnclave> GetEnclavesByState(EnclaveState state) const;
    
    // State management
    bool SetEnclaveState(const std::string& enclave_id, EnclaveState state);
    bool PauseEnclave(const std::string& enclave_id);
    bool ResumeEnclave(const std::string& enclave_id);
    
    // Security
    bool VerifyEnclave(const std::string& enclave_path);
    bool IsTrustedSigner(const std::vector<uint8_t>& signature);
    
private:
    Config config_;
    std::map<std::string, LoadedEnclave> loaded_enclaves_;
    mutable std::mutex enclaves_mutex_;
    size_t total_loaded_memory_;
    
    bool CheckMemoryLimit(size_t requested);
    bool ValidateManifest(const EnclaveManifest& manifest);
};

// ============================================================================
// Enclave Runtime
// ============================================================================

class EnclaveRuntime {
public:
    struct Config {
        int max_concurrent_calls = 100;
        std::chrono::seconds call_timeout{30};
        bool enable_call_logging = false;
        bool enable_profiling = false;
    };
    
    struct CallContext {
        std::string call_id;
        std::string enclave_id;
        std::string function_name;
        std::vector<uint8_t> input_data;
        std::vector<uint8_t> output_data;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        bool success;
        std::string error_message;
    };
    
    struct PerformanceStats {
        int total_calls;
        int successful_calls;
        int failed_calls;
        double avg_latency_ms;
        double max_latency_ms;
        double min_latency_ms;
        std::map<std::string, double> function_latencies;
    };
    
    explicit EnclaveRuntime(const Config& config);
    ~EnclaveRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Function invocation
    std::vector<uint8_t> CallFunction(const std::string& enclave_id,
                                    const std::string& function_name,
                                    const std::vector<uint8_t>& input);
    std::string CallFunctionAsync(const std::string& enclave_id,
                                  const std::string& function_name,
                                  const std::vector<uint8_t>& input);
    CallContext GetCallResult(const std::string& call_id);
    bool WaitForCall(const std::string& call_id, std::chrono::milliseconds timeout);
    
    // Thread management
    bool CreateThread(const std::string& enclave_id);
    bool DestroyThread(const std::string& enclave_id, int thread_id);
    int GetThreadCount(const std::string& enclave_id) const;
    
    // Exception handling
    bool HandleException(const std::string& enclave_id, void* exception_info);
    bool RecoverEnclave(const std::string& enclave_id);
    
    // Performance
    PerformanceStats GetStats(const std::string& enclave_id) const;
    void ResetStats(const std::string& enclave_id);
    
private:
    Config config_;
    std::map<std::string, CallContext> active_calls_;
    std::map<std::string, PerformanceStats> stats_;
    mutable std::mutex calls_mutex_;
    mutable std::mutex stats_mutex_;
    std::thread monitor_thread_;
    std::atomic<bool> running_{false};
    
    void MonitorLoop();
    void CleanupStaleCalls();
};

// ============================================================================
// Secure Channel Manager
// ============================================================================

class SecureChannelManager {
public:
    struct Config {
        std::string cipher_suite = "AES-256-GCM";
        int key_rotation_interval_minutes = 60;
        bool perfect_forward_secrecy = true;
        int max_channels = 1000;
    };
    
    explicit SecureChannelManager(const Config& config);
    ~SecureChannelManager();
    
    bool Initialize();
    void Shutdown();
    
    // Channel establishment
    SecureChannel EstablishChannel(const std::string& enclave_id);
    SecureChannel EstablishChannelWithAuth(const std::string& enclave_id,
                                           const std::vector<uint8_t>& auth_data);
    
    // Channel operations
    bool CloseChannel(const std::string& channel_id);
    bool RotateKey(const std::string& channel_id);
    
    // Encryption
    std::vector<uint8_t> Encrypt(const std::string& channel_id,
                                 const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> Decrypt(const std::string& channel_id,
                                 const std::vector<uint8_t>& ciphertext);
    
    // Queries
    SecureChannel GetChannelInfo(const std::string& channel_id) const;
    std::vector<SecureChannel> GetChannelsForEnclave(const std::string& enclave_id) const;
    bool IsChannelValid(const std::string& channel_id) const;
    
private:
    Config config_;
    std::map<std::string, SecureChannel> channels_;
    mutable std::mutex channels_mutex_;
    std::thread rotation_thread_;
    std::atomic<bool> running_{false};
    
    void RotationLoop();
    std::vector<uint8_t> GenerateSessionKey();
    std::vector<uint8_t> DeriveKey(const std::vector<uint8_t>& master_secret,
                                  const std::string& context);
};

// ============================================================================
// Enclave Debugger
// ============================================================================

class EnclaveDebugger {
public:
    struct Config {
        bool enable_debugging = false;
        int debug_port = 2345;
        bool break_on_entry = false;
        bool break_on_exception = true;
    };
    
    struct Breakpoint {
        std::string enclave_id;
        uint64_t address;
        std::string condition;
        bool enabled;
    };
    
    struct StackFrame {
        uint64_t instruction_pointer;
        uint64_t stack_pointer;
        uint64_t base_pointer;
        std::string function_name;
        std::string source_file;
        int line_number;
    };
    
    explicit EnclaveDebugger(const Config& config);
    ~EnclaveDebugger();
    
    bool Initialize();
    void Shutdown();
    
    // Debugging control
    bool AttachToEnclave(const std::string& enclave_id);
    bool DetachFromEnclave(const std::string& enclave_id);
    bool StepInstruction(const std::string& enclave_id);
    bool ContinueExecution(const std::string& enclave_id);
    bool PauseExecution(const std::string& enclave_id);
    
    // Breakpoints
    bool SetBreakpoint(const std::string& enclave_id, uint64_t address);
    bool ClearBreakpoint(const std::string& enclave_id, uint64_t address);
    bool ClearAllBreakpoints(const std::string& enclave_id);
    std::vector<Breakpoint> GetBreakpoints(const std::string& enclave_id) const;
    
    // Inspection
    std::vector<StackFrame> GetStackTrace(const std::string& enclave_id) const;
    std::vector<uint8_t> ReadMemory(const std::string& enclave_id, uint64_t address, size_t size);
    bool WriteMemory(const std::string& enclave_id, uint64_t address, const std::vector<uint8_t>& data);
    std::map<std::string, std::any> GetRegisters(const std::string& enclave_id) const;
    
private:
    Config config_;
    std::set<std::string> attached_enclaves_;
    std::map<std::string, std::vector<Breakpoint>> breakpoints_;
    mutable std::mutex debugger_mutex_;
    std::thread debug_server_thread_;
    
    void DebugServerLoop();
};

// ============================================================================
// Secure Enclaves Runtime
// ============================================================================

class SecureEnclavesRuntime {
public:
    struct Config {
        EnclaveBuilder::Config builder;
        EnclaveLoader::Config loader;
        EnclaveRuntime::Config runtime;
        SecureChannelManager::Config channels;
        EnclaveDebugger::Config debugger;
    };
    
    explicit SecureEnclavesRuntime(const Config& config);
    ~SecureEnclavesRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    EnclaveBuilder* GetBuilder();
    EnclaveLoader* GetLoader();
    EnclaveRuntime* GetRuntime();
    SecureChannelManager* GetChannelManager();
    EnclaveDebugger* GetDebugger();
    
    // High-level API
    std::string BuildAndLoad(const std::string& source_dir,
                             const std::string& enclave_name);
    std::vector<uint8_t> Execute(const std::string& enclave_id,
                                  const std::string& function,
                                  const std::vector<uint8_t>& input);
    bool Unload(const std::string& enclave_id);
    
    // Lifecycle
    std::vector<std::string> GetLoadedEnclaves() const;
    bool IsEnclaveRunning(const std::string& enclave_id) const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<EnclaveBuilder> builder_;
    std::unique_ptr<EnclaveLoader> loader_;
    std::unique_ptr<EnclaveRuntime> runtime_;
    std::unique_ptr<SecureChannelManager> channel_manager_;
    std::unique_ptr<EnclaveDebugger> debugger_;
};

} // namespace TEE
} // namespace Sovereign
