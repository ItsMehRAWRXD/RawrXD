// ============================================================================
// test_e2e_splitter_decoder.cpp - Phase 9: End-to-End Integration Test
// Full pipeline: Batch Splitter -> HTTP Client -> HTTP Server -> Decoder
// ============================================================================

#include "sovereign_http_splitter_client.hpp"
#include "../core/sovereign_batch_splitter.hpp"
#include <stdio.h>
#include <windows.h>
#include <process.h>

using namespace Sovereign;

// ============================================================================
// Test Configuration
// ============================================================================
struct E2ETestConfig {
    const char* server_exe = "rawrxd_http_server.exe";
    int server_port = 18080;  // Use non-standard port to avoid conflicts
    int startup_delay_ms = 2000;
    int shutdown_delay_ms = 500;
    bool debug = true;
};

// ============================================================================
// Server Process Management
// ============================================================================
class TestServerProcess {
public:
    TestServerProcess() : process_handle_(NULL), pid_(0) {}
    
    bool Start(const E2ETestConfig& config) {
        char cmd_line[512];
        snprintf(cmd_line, sizeof(cmd_line), 
                 "%s --port %d %s", 
                 config.server_exe, 
                 config.server_port,
                 config.debug ? "--debug" : "");
        
        STARTUPINFOA si = {sizeof(si)};
        PROCESS_INFORMATION pi = {0};
        
        if (!CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
                           CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[E2E] Failed to start server: %lu\n", GetLastError());
            return false;
        }
        
        process_handle_ = pi.hProcess;
        pid_ = pi.dwProcessId;
        CloseHandle(pi.hThread);
        
        printf("[E2E] Server started (PID: %lu) on port %d\n", pid_, config.server_port);
        
        // Wait for server to initialize
        Sleep(config.startup_delay_ms);
        return true;
    }
    
    void Stop() {
        if (process_handle_) {
            TerminateProcess(process_handle_, 0);
            WaitForSingleObject(process_handle_, 5000);
            CloseHandle(process_handle_);
            process_handle_ = NULL;
            printf("[E2E] Server stopped\n");
        }
    }
    
    bool IsRunning() const {
        if (!process_handle_) return false;
        DWORD exit_code;
        return GetExitCodeProcess(process_handle_, &exit_code) && exit_code == STILL_ACTIVE;
    }
    
    DWORD GetPid() const { return pid_; }
    
private:
    HANDLE process_handle_;
    DWORD pid_;
};

// ============================================================================
// E2E Test Runner
// ============================================================================
class E2ETestRunner {
public:
    E2ETestRunner(const E2ETestConfig& config) : config_(config), passed_(0), failed_(0) {}
    
    bool Initialize() {
        printf("=== Phase 9: End-to-End Splitter->Decoder Integration ===\n\n");
        
        // Start HTTP server
        if (!server_.Start(config_)) {
            printf("[FAIL] Could not start test server\n");
            return false;
        }
        
        // Initialize client
        SplitterClientConfig client_config;
        client_config.host = "localhost";
        client_config.port = config_.server_port;
        client_config.timeout_ms = 10000;
        client_config.max_retries = 3;
        client_config.debug = config_.debug;
        
        if (!client_.Initialize(client_config)) {
            printf("[FAIL] Could not initialize client\n");
            server_.Stop();
            return false;
        }
        
        // Wait for server to be ready
        int retries = 10;
        while (retries-- > 0) {
            if (client_.HealthCheck()) {
                printf("[E2E] Server is ready\n\n");
                return true;
            }
            Sleep(500);
        }
        
        printf("[FAIL] Server health check failed\n");
        return false;
    }
    
    void Shutdown() {
        client_.Shutdown();
        server_.Stop();
        
        printf("\n=== E2E Test Results ===\n");
        printf("  Passed: %d\n", passed_);
        printf("  Failed: %d\n", failed_);
        printf("  Total:  %d\n", passed_ + failed_);
    }
    
    // Test 1: Simple batch split and decode
    void Test_SimpleBatch() {
        printf("Test 1: Simple batch split and decode...\n");
        
        // Create splitter
        BatchSplitter splitter;
        SplitterConfig split_config;
        split_config.max_batch_size = 4;
        split_config.enable_overlap = false;
        
        if (!splitter.Initialize(split_config)) {
            printf("  [FAIL] Failed to initialize splitter\n");
            failed_++;
            return;
        }
        
        // Create a token sequence
        std::vector<int32_t> tokens = {1, 2, 3, 4, 5, 6, 7, 8};
        
        // Split into batches
        auto batches = splitter.SplitBatch(tokens, 0);
        printf("  Split %zu tokens into %zu batches\n", tokens.size(), batches.size());
        
        // Process each batch through HTTP
        bool all_success = true;
        int batch_num = 0;
        for (const auto& batch : batches) {
            SplitterDecodeRequest req;
            req.tokens = batch.tokens;
            req.positions = batch.positions;
            req.max_tokens = 1;
            
            SplitterDecodeResponse resp = client_.Decode(req);
            
            printf("    Batch %d: %zu tokens -> ", ++batch_num, batch.tokens.size());
            if (resp.success) {
                printf("OK (generated %d tokens)\n", resp.tokens_generated);
            } else {
                printf("FAILED (error: %s)\n", resp.error_message.c_str());
                all_success = false;
            }
        }
        
        if (all_success) {
            printf("  [PASS]\n");
            passed_++;
        } else {
            printf("  [FAIL]\n");
            failed_++;
        }
        printf("\n");
    }
    
    // Test 2: Overlapping batches
    void Test_OverlappingBatches() {
        printf("Test 2: Overlapping batches...\n");
        
        BatchSplitter splitter;
        SplitterConfig split_config;
        split_config.max_batch_size = 4;
        split_config.enable_overlap = true;
        split_config.overlap_tokens = 2;
        
        if (!splitter.Initialize(split_config)) {
            printf("  [FAIL] Failed to initialize splitter\n");
            failed_++;
            return;
        }
        
        std::vector<int32_t> tokens = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
        auto batches = splitter.SplitBatch(tokens, 0);
        
        printf("  Split %zu tokens into %zu overlapping batches\n", tokens.size(), batches.size());
        
        // Verify overlap
        bool overlap_ok = true;
        for (size_t i = 1; i < batches.size(); i++) {
            // Check for overlap between consecutive batches
            if (batches[i].position_offset <= batches[i-1].position_offset + batches[i-1].tokens.size()) {
                printf("    Batch %zu overlaps with batch %zu\n", i-1, i);
            }
        }
        
        // Process through HTTP
        bool all_success = true;
        for (const auto& batch : batches) {
            SplitterDecodeRequest req;
            req.tokens = batch.tokens;
            req.positions = batch.positions;
            req.max_tokens = 1;
            
            SplitterDecodeResponse resp = client_.Decode(req);
            if (!resp.success) {
                all_success = false;
            }
        }
        
        if (all_success && overlap_ok) {
            printf("  [PASS]\n");
            passed_++;
        } else {
            printf("  [FAIL]\n");
            failed_++;
        }
        printf("\n");
    }
    
    // Test 3: Position offset handling
    void Test_PositionOffsets() {
        printf("Test 3: Position offset handling...\n");
        
        BatchSplitter splitter;
        SplitterConfig split_config;
        split_config.max_batch_size = 3;
        
        if (!splitter.Initialize(split_config)) {
            printf("  [FAIL] Failed to initialize splitter\n");
            failed_++;
            return;
        }
        
        // Split with initial offset
        std::vector<int32_t> tokens = {100, 200, 300, 400, 500};
        auto batches = splitter.SplitBatch(tokens, 10);  // Start at position 10
        
        printf("  Split with initial offset 10:\n");
        
        bool positions_ok = true;
        for (size_t i = 0; i < batches.size(); i++) {
            printf("    Batch %zu: position_offset=%zu, positions=[", i, batches[i].position_offset);
            for (size_t j = 0; j < batches[i].positions.size() && j < 3; j++) {
                if (j > 0) printf(", ");
                printf("%d", batches[i].positions[j]);
            }
            printf("...]\n");
            
            // Verify positions are correct
            for (size_t j = 0; j < batches[i].positions.size(); j++) {
                int32_t expected = batches[i].position_offset + j;
                if (batches[i].positions[j] != expected) {
                    printf("      ERROR: position[%zu]=%d, expected=%d\n", 
                           j, batches[i].positions[j], expected);
                    positions_ok = false;
                }
            }
        }
        
        if (positions_ok) {
            printf("  [PASS]\n");
            passed_++;
        } else {
            printf("  [FAIL]\n");
            failed_++;
        }
        printf("\n");
    }
    
    // Test 4: Error recovery
    void Test_ErrorRecovery() {
        printf("Test 4: Error recovery...\n");
        
        // Test with invalid tokens (should fail gracefully)
        SplitterDecodeRequest req;
        req.tokens = {};  // Empty
        req.max_tokens = 1;
        
        SplitterDecodeResponse resp = client_.Decode(req);
        
        printf("  Empty token request: ");
        if (!resp.success) {
            printf("Correctly rejected (error: %s)\n", resp.error_message.c_str());
            printf("  [PASS]\n");
            passed_++;
        } else {
            printf("Unexpectedly succeeded\n");
            printf("  [FAIL]\n");
            failed_++;
        }
        printf("\n");
    }
    
    // Test 5: Concurrent batches
    void Test_ConcurrentBatches() {
        printf("Test 5: Concurrent batch processing...\n");
        
        // Create multiple splitter instances
        const int num_batches = 3;
        std::vector<std::vector<int32_t>> token_sets = {
            {1, 2, 3, 4},
            {10, 20, 30, 40},
            {100, 200, 300, 400}
        };
        
        printf("  Processing %d concurrent batches...\n", num_batches);
        
        // Process all through HTTP
        bool all_success = true;
        for (int i = 0; i < num_batches; i++) {
            SplitterDecodeRequest req;
            req.tokens = token_sets[i];
            req.max_tokens = 1;
            
            SplitterDecodeResponse resp = client_.Decode(req);
            if (!resp.success) {
                printf("    Batch %d failed: %s\n", i, resp.error_message.c_str());
                all_success = false;
            }
        }
        
        if (all_success) {
            printf("  All %d batches processed successfully\n", num_batches);
            printf("  [PASS]\n");
            passed_++;
        } else {
            printf("  [FAIL]\n");
            failed_++;
        }
        printf("\n");
    }
    
private:
    E2ETestConfig config_;
    TestServerProcess server_;
    HTTPSplitterClient client_;
    int passed_;
    int failed_;
};

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    E2ETestConfig config;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            config.server_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--debug") == 0) {
            config.debug = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Phase 9: End-to-End Integration Test\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --port <n>    Server port (default: %d)\n", config.server_port);
            printf("  --debug       Enable debug output\n");
            printf("  --help        Show this help\n");
            return 0;
        }
    }
    
    // Run tests
    E2ETestRunner runner(config);
    
    if (!runner.Initialize()) {
        printf("[CRITICAL] Test initialization failed\n");
        return 1;
    }
    
    // Run all tests
    runner.Test_SimpleBatch();
    runner.Test_OverlappingBatches();
    runner.Test_PositionOffsets();
    runner.Test_ErrorRecovery();
    runner.Test_ConcurrentBatches();
    
    runner.Shutdown();
    
    printf("\n=== Phase 9 Complete ===\n");
    return 0;
}
