// rtp_protocol_fallback.cpp — Production RTP Protocol Implementation
// Provides real-time transport protocol for audio/video streaming
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ============================================================================
// RTP Header
// ============================================================================
#pragma pack(push, 1)
struct RtpHeader {
    uint8_t flags;          // Version (2), Padding, Extension, CSRC count
    uint8_t payloadType;    // Marker bit (1), Payload type (7)
    uint16_t sequenceNum;   // Sequence number
    uint32_t timestamp;     // Timestamp
    uint32_t ssrc;          // Synchronization source
};
#pragma pack(pop)

// ============================================================================
// RTP Packet
// ============================================================================
#define MAX_RTP_PACKETS     256
#define MAX_PAYLOAD_SIZE    1400

struct RtpPacket {
    volatile LONG active;
    RtpHeader header;
    uint8_t payload[MAX_PAYLOAD_SIZE];
    uint32_t payloadLen;
    uint64_t recvTime;
};

// ============================================================================
// Session State
// ============================================================================
static volatile LONG g_initialized = 0;
static RtpPacket g_packets[MAX_RTP_PACKETS];
static volatile LONG g_packetHead = 0;
static volatile LONG g_packetTail = 0;
static volatile LONG g_packetCount = 0;
static volatile LONG g_nextSequence = 1;
static uint32_t g_ssrc = 0;

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int RTPProtocol_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InterlockedExchange(&g_packetHead, 0);
    InterlockedExchange(&g_packetTail, 0);
    InterlockedExchange(&g_packetCount, 0);
    InterlockedExchange(&g_nextSequence, 1);
    memset(g_packets, 0, sizeof(g_packets));
    
    // Generate random SSRC
    g_ssrc = GetTickCount() ^ (GetCurrentProcessId() << 16);
    
    return 1;
}

extern "C" __declspec(dllexport) int RTPProtocol_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    
    for (int i = 0; i < MAX_RTP_PACKETS; ++i) {
        InterlockedExchange(&g_packets[i].active, 0);
    }
    InterlockedExchange(&g_packetCount, 0);
    
    return 0;
}

extern "C" __declspec(dllexport) int RTPProtocol_CreatePacket(uint8_t payloadType, const uint8_t* payload, uint32_t payloadLen, uint8_t* outBuffer, uint32_t* outLen) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!payload || !outBuffer || !outLen) return 0;
    if (payloadLen > MAX_PAYLOAD_SIZE) payloadLen = MAX_PAYLOAD_SIZE;
    
    RtpHeader header;
    header.flags = 0x80;  // Version 2
    header.payloadType = payloadType & 0x7F;
    header.sequenceNum = static_cast<uint16_t>(InterlockedIncrement(&g_nextSequence) - 1);
    header.timestamp = GetTickCount();
    header.ssrc = g_ssrc;
    
    // Store in queue
    LONG tail = InterlockedIncrement(&g_packetTail) - 1;
    tail %= MAX_RTP_PACKETS;
    
    RtpPacket* pkt = &g_packets[tail];
    pkt->header = header;
    memcpy(pkt->payload, payload, payloadLen);
    pkt->payloadLen = payloadLen;
    pkt->recvTime = GetTickCount64();
    InterlockedExchange(&pkt->active, 1);
    InterlockedIncrement(&g_packetCount);
    
    // Serialize to output buffer
    memcpy(outBuffer, &header, sizeof(RtpHeader));
    memcpy(outBuffer + sizeof(RtpHeader), payload, payloadLen);
    *outLen = sizeof(RtpHeader) + payloadLen;
    
    return 1;
}

extern "C" __declspec(dllexport) int RTPProtocol_ParsePacket(const uint8_t* buffer, uint32_t bufferLen, uint8_t* outPayload, uint32_t* outPayloadLen, uint16_t* outSeqNum) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!buffer || bufferLen < sizeof(RtpHeader) || !outPayload || !outPayloadLen) return 0;
    
    const RtpHeader* header = reinterpret_cast<const RtpHeader*>(buffer);
    
    // Verify version
    if ((header->flags & 0xC0) != 0x80) return 0;
    
    uint32_t payloadLen = bufferLen - sizeof(RtpHeader);
    if (payloadLen > MAX_PAYLOAD_SIZE) payloadLen = MAX_PAYLOAD_SIZE;
    
    memcpy(outPayload, buffer + sizeof(RtpHeader), payloadLen);
    *outPayloadLen = payloadLen;
    if (outSeqNum) *outSeqNum = header->sequenceNum;
    
    return 1;
}

extern "C" __declspec(dllexport) int RTPProtocol_GetQueueDepth() {
    return static_cast<int>(InterlockedCompareExchange(&g_packetCount, 0, 0));
}

extern "C" __declspec(dllexport) void RTPProtocolFallbackStub() {
    // Legacy symbol - now has real implementation above
}
