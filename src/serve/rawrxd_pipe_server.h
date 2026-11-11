// ============================================================================
// RawrXD Pipe Server Integration Header
// Multi-instance named pipe server for hotpatch IPC
// ============================================================================

#ifndef RAWRXD_PIPE_SERVER_H
#define RAWRXD_PIPE_SERVER_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the multi-instance pipe server
// Returns TRUE on success, FALSE on failure
BOOL RawrXD_PipeServer_Init(void);

// Shutdown the pipe server and cleanup resources
void RawrXD_PipeServer_Shutdown(void);

// Check if pipe server is running
BOOL RawrXD_PipeServer_IsRunning(void);

// Process a hotpatch payload (called internally by server threads)
// Can also be called directly for testing
BOOL RawrXD_PipeServer_ProcessPayload(const uint8_t* data, DWORD len);

// Get statistics
void RawrXD_PipeServer_GetStats(uint64_t* totalReceived, uint64_t* totalProcessed);

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_PIPE_SERVER_H
