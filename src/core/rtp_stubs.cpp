// ============================================================================
// rtp_stubs.cpp - Stub implementations for Runtime Telemetry Protocol (RTP)
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>

extern "C" {

// RTP Descriptor Table functions
void* RTP_InitDescriptorTable() {
    OutputDebugStringA("[RTP] RTP_InitDescriptorTable stub called\n");
    return nullptr;
}

void* RTP_GetDescriptorTable() {
    OutputDebugStringA("[RTP] RTP_GetDescriptorTable stub called\n");
    return nullptr;
}

int RTP_GetDescriptorCount() {
    OutputDebugStringA("[RTP] RTP_GetDescriptorCount stub called\n");
    return 0;
}

// RTP Packet functions
bool RTP_ValidatePacket(const void* packet, size_t size) {
    (void)packet;
    (void)size;
    OutputDebugStringA("[RTP] RTP_ValidatePacket stub called\n");
    return true;
}

bool RTP_DispatchPacket(const void* packet, size_t size) {
    (void)packet;
    (void)size;
    OutputDebugStringA("[RTP] RTP_DispatchPacket stub called\n");
    return true;
}

// RTP Context Blob functions
void* RTP_BuildContextBlob(const void* data, size_t size) {
    (void)data;
    (void)size;
    OutputDebugStringA("[RTP] RTP_BuildContextBlob stub called\n");
    return nullptr;
}

void* RTP_GetContextBlobPtr(void* blob) {
    (void)blob;
    OutputDebugStringA("[RTP] RTP_GetContextBlobPtr stub called\n");
    return nullptr;
}

size_t RTP_GetContextBlobSize(void* blob) {
    (void)blob;
    OutputDebugStringA("[RTP] RTP_GetContextBlobSize stub called\n");
    return 0;
}

// RTP Telemetry functions
bool RTP_GetTelemetrySnapshot(void* buffer, size_t bufferSize) {
    (void)buffer;
    (void)bufferSize;
    OutputDebugStringA("[RTP] RTP_GetTelemetrySnapshot stub called\n");
    return true;
}

// RTP Agent Loop
int RTP_AgentLoop_Run(void* config) {
    (void)config;
    OutputDebugStringA("[RTP] RTP_AgentLoop_Run stub called\n");
    return 0;
}

} // extern "C"
