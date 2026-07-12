//==============================================================================
// SovereignNetworkProtocolAnalysis.h - Network Protocol Analysis Subsystem
// Encrypted protocol inference, packet structure recovery, state machine reconstruction
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#ifndef SOVEREIGN_NETWORK_PROTOCOL_ANALYSIS_H
#define SOVEREIGN_NETWORK_PROTOCOL_ANALYSIS_H

#include <windows.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

//==============================================================================
// Protocol Types
//==============================================================================

enum ProtocolLayer {
    LAYER_PHYSICAL,
    LAYER_DATA_LINK,
    LAYER_NETWORK,
    LAYER_TRANSPORT,
    LAYER_SESSION,
    LAYER_PRESENTATION,
    LAYER_APPLICATION
};

enum ProtocolType {
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS,
    PROTO_CUSTOM,
    PROTO_UNKNOWN
};

//==============================================================================
// Packet Structures
//==============================================================================

struct Packet {
    uint8_t* data;
    size_t length;
    uint64_t timestamp;
    ProtocolLayer layer;
    ProtocolType type;
    bool isEncrypted;
    bool isObfuscated;
};

struct PacketField {
    char name[64];
    uint32_t offset;
    uint32_t size;
    char type[32];      // "int", "string", "blob", "encrypted"
    bool isEncrypted;
    bool isVariable;
};

struct PacketStructure {
    char protocolName[64];
    uint32_t fieldCount;
    PacketField fields[64];
    uint32_t fixedHeaderSize;
    bool hasVariableLength;
};

//==============================================================================
// Protocol State Machine
//==============================================================================

enum StateType {
    STATE_IDLE,
    STATE_HANDSHAKE,
    STATE_AUTHENTICATED,
    STATE_DATA_TRANSFER,
    STATE_CLOSING,
    STATE_ERROR
};

struct ProtocolState {
    StateType type;
    char name[64];
    uint32_t id;
};

struct StateTransition {
    ProtocolState from;
    ProtocolState to;
    char trigger[128];      // Packet pattern or condition
    float probability;
};

struct StateMachine {
    char protocolName[64];
    ProtocolState states[32];
    uint32_t stateCount;
    StateTransition transitions[128];
    uint32_t transitionCount;
    ProtocolState initialState;
    ProtocolState currentState;
};

//==============================================================================
// Encryption Analysis
//==============================================================================

enum CipherType {
    CIPHER_XOR,
    CIPHER_AES,
    CIPHER_RC4,
    CIPHER_CHACHA20,
    CIPHER_RSA,
    CIPHER_CUSTOM,
    CIPHER_UNKNOWN
};

struct EncryptionScheme {
    CipherType cipher;
    char keyMaterial[256];
    uint32_t keySize;
    uint32_t ivSize;
    uint32_t blockSize;
    bool hasIV;
    bool hasMAC;
};

struct ProtocolCrypto {
    bool isEncrypted;
    EncryptionScheme scheme;
    char keyExchange[64];   // "static", "DH", "ECDH", "RSA"
    bool hasPerfectForwardSecrecy;
};

//==============================================================================
// Traffic Analysis
//==============================================================================

struct TrafficPattern {
    char name[64];
    uint32_t packetCount;
    uint64_t totalBytes;
    uint64_t durationMs;
    float avgPacketSize;
    float packetRate;
    bool isPeriodic;
    bool isBurst;
};

struct Flow {
    uint32_t srcIP;
    uint32_t dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    ProtocolType protocol;
    Packet* packets;
    uint32_t packetCount;
    TrafficPattern pattern;
    StateMachine* stateMachine;
};

//==============================================================================
// Fuzzing Integration
//==============================================================================

struct FuzzTarget {
    char fieldName[64];
    uint32_t offset;
    uint32_t size;
    char strategy[32];    // "random", "boundary", "format"
    bool isActive;
};

struct FuzzResult {
    bool crashed;
    bool hung;
    char crashType[64];
    uint8_t* crashInput;
    size_t crashInputSize;
};

//==============================================================================
// Exploit Surface
//==============================================================================

struct ProtocolVulnerability {
    char type[64];          // "buffer_overflow", "format_string", "integer_overflow"
    char location[128];
    uint32_t severity;      // 1-10
    bool isExploitable;
    char description[512];
};

//==============================================================================
// Core Interface
//==============================================================================

bool NetProto_Init();
void NetProto_Shutdown();

// Packet capture and analysis
bool NetProto_CapturePacket(Packet* packet);
bool NetProto_AnalyzePacket(const Packet* packet, PacketStructure* outStructure);
bool NetProto_InferStructure(const Packet* packets, uint32_t count, PacketStructure* outStructure);

// Protocol detection
bool NetProto_DetectProtocol(const Packet* packet, ProtocolType* outType);
bool NetProto_DetectEncryption(const Packet* packets, uint32_t count, ProtocolCrypto* outCrypto);
bool NetProto_InferCipher(const Packet* packets, uint32_t count, CipherType* outCipher);

// State machine reconstruction
bool NetProto_BuildStateMachine(const Flow* flows, uint32_t flowCount, StateMachine* outMachine);
bool NetProto_TrackState(StateMachine* machine, const Packet* packet);
bool NetProto_InferTransitions(const Flow* flow, StateTransition* outTransitions, uint32_t* outCount);

// Encryption analysis
bool NetProto_RecoverKey(const Packet* packets, uint32_t count, const ProtocolCrypto* crypto, uint8_t* outKey, uint32_t* outKeySize);
bool NetProto_DecryptPacket(const Packet* encrypted, const ProtocolCrypto* crypto, Packet* outDecrypted);
bool NetProto_AnalyzeKeyExchange(const Flow* flow, char* outExchange, uint32_t* outExchangeLen);

// Traffic analysis
bool NetProto_AnalyzeTraffic(const Flow* flows, uint32_t count, TrafficPattern* outPatterns, uint32_t* outPatternCount);
bool NetProto_DetectC2(const Flow* flows, uint32_t count, bool* isC2, char* outC2Info, uint32_t* outInfoLen);
bool NetProto_DetectExfiltration(const Flow* flows, uint32_t count, bool* isExfil, char* outExfilInfo, uint32_t* outInfoLen);

// Fuzzing
bool NetProto_FuzzField(const Packet* templatePacket, const FuzzTarget* target, Packet* outMutated);
bool NetProto_FuzzSequence(const Packet* packets, uint32_t count, FuzzResult* outResults, uint32_t* outResultCount);

// Exploit surface mapping
bool NetProto_MapExploitSurface(const PacketStructure* structure, ProtocolVulnerability* outVulns, uint32_t* outVulnCount);
bool NetProto_AssessVulnerability(const ProtocolVulnerability* vuln, bool* isExploitable, char* outExploitInfo, uint32_t* outInfoLen);

//==============================================================================
// SEG Integration
//==============================================================================

bool SEGNode_CaptureTraffic(void* input, void* output);
bool SEGNode_AnalyzeProtocol(void* input, void* output);
bool SEGNode_ReconstructStateMachine(void* input, void* output);
bool SEGNode_DecryptTraffic(void* input, void* output);
bool SEGNode_FuzzProtocol(void* input, void* output);
bool SEGNode_MapProtocolExploitSurface(void* input, void* output);

//==============================================================================
// MoE Experts
//==============================================================================

bool Expert_ProtocolInference(const Packet* packets, uint32_t count, ProtocolType* outType);
bool Expert_EncryptionDetection(const Packet* packets, uint32_t count, ProtocolCrypto* outCrypto);
bool Expert_StateMachineInference(const Flow* flows, uint32_t count, StateMachine* outMachine);
bool Expert_KeyRecovery(const Packet* packets, uint32_t count, uint8_t* outKey, uint32_t* outKeySize);
bool Expert_C2Detection(const Flow* flows, uint32_t count, bool* isC2);
bool Expert_ProtocolFuzzing(const Packet* templatePacket, FuzzResult* outResults, uint32_t* outCount);

//==============================================================================
// IDE Panels
//==============================================================================

void NetProtoPanel_Render();
void NetProtoPanel_UpdatePacketList(const Packet* packets, uint32_t count);
void NetProtoPanel_UpdateStructure(const PacketStructure* structure);
void NetProtoPanel_UpdateStateMachine(const StateMachine* machine);
void NetProtoPanel_UpdateCryptoAnalysis(const ProtocolCrypto* crypto);
void NetProtoPanel_UpdateTrafficAnalysis(const TrafficPattern* patterns, uint32_t count);
void NetProtoPanel_UpdateFuzzResults(const FuzzResult* results, uint32_t count);
void NetProtoPanel_UpdateExploitSurface(const ProtocolVulnerability* vulns, uint32_t count);

//==============================================================================
// Export/Import
//==============================================================================

bool NetProto_ExportProtocolDefinition(const PacketStructure* structure, const char* path);
bool NetProto_ImportProtocolDefinition(const char* path, PacketStructure* outStructure);
bool NetProto_ExportStateMachine(const StateMachine* machine, const char* path);
bool NetProto_ImportStateMachine(const char* path, StateMachine* outMachine);

#endif // SOVEREIGN_NETWORK_PROTOCOL_ANALYSIS_H
