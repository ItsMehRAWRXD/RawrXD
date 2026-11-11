// ============================================================================
// rawrxd_http_decoder_endpoint.h - Phase 7: HTTP Decoder Wiring
// REST API endpoint for llama_decode_internal with Epoch-RCU integration
// ============================================================================

#ifndef RAWRXD_HTTP_DECODER_ENDPOINT_H
#define RAWRXD_HTTP_DECODER_ENDPOINT_H

#include <winsock2.h>

// Forward declarations
namespace Sovereign {
    struct ModelWeights;
}

// ============================================================================
// HTTP Handler
// ============================================================================
// Handle POST /v1/decode requests
// Body: JSON with {tokens: [...], positions?: [...], temperature?: 0.8, ...}
void HandleDecodeEndpoint(SOCKET client, const char* body);

// Send JSON response helper
void SendJsonResponse(SOCKET client, int status, const char* json);

// ============================================================================
// Epoch-RCU Integration
// ============================================================================
// Set the current model for decode operations (called by hotpatch system)
void SetCurrentModel(Sovereign::ModelWeights* model);

// Get the current model
Sovereign::ModelWeights* GetCurrentModel();

#endif // RAWRXD_HTTP_DECODER_ENDPOINT_H
