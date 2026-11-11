// ============================================================================
// test_http_splitter_client.cpp - Phase 8 Test
// Validates HTTP splitter client integration with decoder endpoint
// ============================================================================

#include "sovereign_http_splitter_client.hpp"
#include <stdio.h>
#include <windows.h>

using namespace Sovereign;

int main(int argc, char* argv[]) {
    printf("=== Phase 8: HTTP Splitter Client Test ===\n\n");
    
    // Configuration
    SplitterClientConfig config;
    config.host = (argc > 1) ? argv[1] : "localhost";
    config.port = (argc > 2) ? atoi(argv[2]) : 8080;
    config.timeout_ms = 10000;
    config.max_retries = 2;
    config.debug = true;
    
    printf("Configuration:\n");
    printf("  Host: %s\n", config.host.c_str());
    printf("  Port: %d\n", config.port);
    printf("  Endpoint: %s\n\n", config.endpoint.c_str());
    
    // Create client
    HTTPSplitterClient client;
    
    // Test 1: Initialize
    printf("Test 1: Initialize client...\n");
    if (!client.Initialize(config)) {
        printf("  [FAIL] Failed to initialize client\n");
        return 1;
    }
    printf("  [PASS] Client initialized\n\n");
    
    // Test 2: Health check
    printf("Test 2: Health check...\n");
    if (client.HealthCheck()) {
        printf("  [PASS] Server is healthy\n");
    } else {
        printf("  [WARN] Health check failed (server may not be running)\n");
        printf("  Skipping decode tests...\n");
        client.Shutdown();
        printf("\n=== Tests completed (server not running) ===\n");
        return 0;
    }
    printf("\n");
    
    // Test 3: Single token decode
    printf("Test 3: Single token decode...\n");
    {
        SplitterDecodeRequest req;
        req.tokens = {42, 43, 44};  // Sample tokens
        req.max_tokens = 1;
        req.temperature = 0.8f;
        req.top_p = 0.95f;
        req.top_k = 40;
        
        SplitterDecodeResponse resp = client.Decode(req);
        
        printf("  Request: tokens=[42,43,44], max_tokens=1\n");
        printf("  Response: success=%s, http_status=%d\n", 
               resp.success ? "true" : "false", resp.http_status);
        
        if (resp.success) {
            printf("  Tokens used: %d, generated: %d\n", 
                   resp.tokens_used, resp.tokens_generated);
            printf("  Output tokens: [");
            for (size_t i = 0; i < resp.output_tokens.size(); i++) {
                if (i > 0) printf(", ");
                printf("%d", resp.output_tokens[i]);
            }
            printf("]\n");
        } else {
            printf("  Error: %s (code: %d)\n", 
                   resp.error_message.c_str(), resp.error_code);
        }
        printf("  [%s]\n\n", resp.success ? "PASS" : "FAIL");
    }
    
    // Test 4: Batch decode with positions
    printf("Test 4: Decode with positions...\n");
    {
        SplitterDecodeRequest req;
        req.tokens = {10, 20, 30};
        req.positions = {0, 1, 2};  // Explicit positions
        req.max_tokens = 2;
        req.return_logits = false;
        
        SplitterDecodeResponse resp = client.Decode(req);
        
        printf("  Request: tokens=[10,20,30], positions=[0,1,2], max_tokens=2\n");
        printf("  Response: success=%s\n", resp.success ? "true" : "false");
        
        if (resp.success) {
            printf("  Generated %d tokens\n", resp.tokens_generated);
        }
        printf("  [%s]\n\n", resp.success ? "PASS" : "FAIL");
    }
    
    // Test 5: Error handling (empty tokens)
    printf("Test 5: Error handling (empty tokens)...\n");
    {
        SplitterDecodeRequest req;
        req.tokens = {};  // Empty
        
        SplitterDecodeResponse resp = client.Decode(req);
        
        printf("  Request: empty tokens array\n");
        printf("  Response: success=%s, error_code=%d\n", 
               resp.success ? "true" : "false", resp.error_code);
        printf("  [%s] (expected failure)\n\n", !resp.success ? "PASS" : "FAIL");
    }
    
    // Test 6: Convenience function
    printf("Test 6: Convenience function HttpDecode...\n");
    {
        // Set global client
        SetGlobalSplitterClient(&client);
        
        std::vector<int32_t> tokens = {100, 200, 300};
        SplitterDecodeResponse resp = HttpDecode(tokens, {}, 1);
        
        printf("  Request: tokens=[100,200,300]\n");
        printf("  Response: success=%s\n", resp.success ? "true" : "false");
        printf("  [%s]\n\n", resp.success ? "PASS" : "FAIL");
    }
    
    // Cleanup
    client.Shutdown();
    
    printf("=== All Phase 8 tests completed ===\n");
    return 0;
}
