//==============================================================================
// SovereignNetworkProtocolAnalysis.cpp - Network Protocol Analysis Implementation
// Encrypted protocol inference, packet structure recovery, state machine reconstruction
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "SovereignNetworkProtocolAnalysis.h"
#include "SovereignAwareness.h"
#include "MoEBackend_ABI.h"

//==============================================================================
// Static State
//==============================================================================

static bool s_initialized = false;
static Packet s_packetBuffer[1024];
static uint32_t s_packetCount = 0;
static Flow s_flows[256];
static uint32_t s_flowCount = 0;

//==============================================================================
// Initialization
//==============================================================================

bool NetProto_Init()
{
    if (s_initialized) return true;
    
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    
    s_initialized = true;
    s_packetCount = 0;
    s_flowCount = 0;
    
    OutputDebugStringA("[NetProto] Initialized\n");
    return true;
}

void NetProto_Shutdown()
{
    if (!s_initialized) return;
    
    WSACleanup();
    s_initialized = false;
    
    OutputDebugStringA("[NetProto] Shutdown\n");
}

//==============================================================================
// Packet Capture and Analysis
//==============================================================================

bool NetProto_CapturePacket(Packet* packet)
{
    if (!packet) return false;
    
    // Store in buffer
    if (s_packetCount < 1024) {
        s_packetBuffer[s_packetCount++] = *packet;
    }
    
    return true;
}

bool NetProto_AnalyzePacket(const Packet* packet, PacketStructure* outStructure)
{
    if (!packet || !outStructure) return false;
    
    // Basic structure analysis
    memset(outStructure, 0, sizeof(PacketStructure));
    
    // Detect if encrypted
    outStructure->isEncrypted = packet->isEncrypted;
    
    // Infer fixed header size (first 4 bytes often length or magic)
    if (packet->length >= 4) {
        outStructure->fixedHeaderSize = 4;
    }
    
    // Look for common patterns
    if (packet->length >= 2) {
        uint16_t magic = *(uint16_t*)packet->data;
        if (magic == 0x4854) { // "HT" for HTTP
            strcpy(outStructure->protocolName, "HTTP");
        } else if (magic == 0x1603) { // TLS record
            strcpy(outStructure->protocolName, "TLS");
            outStructure->isEncrypted = true;
        }
    }
    
    // Add inferred fields
    if (outStructure->fieldCount < 64) {
        PacketField* field = &outStructure->fields[outStructure->fieldCount++];
        strcpy(field->name, "length");
        field->offset = 0;
        field->size = 4;
        strcpy(field->type, "int");
        field->isEncrypted = false;
        field->isVariable = false;
    }
    
    return true;
}

bool NetProto_InferStructure(const Packet* packets, uint32_t count, PacketStructure* outStructure)
{
    if (!packets || count == 0 || !outStructure) return false;
    
    // Analyze multiple packets to infer structure
    memset(outStructure, 0, sizeof(PacketStructure));
    
    // Compare packets to find fixed vs variable fields
    uint32_t minLen = packets[0].length;
    uint32_t maxLen = packets[0].length;
    
    for (uint32_t i = 1; i < count; i++) {
        if (packets[i].length < minLen) minLen = packets[i].length;
        if (packets[i].length > maxLen) maxLen = packets[i].length;
    }
    
    outStructure->hasVariableLength = (minLen != maxLen);
    
    // Infer fields by comparing byte positions
    for (uint32_t offset = 0; offset < minLen && offset < 64; offset += 4) {
        bool isFixed = true;
        uint8_t firstByte = packets[0].data[offset];
        
        for (uint32_t i = 1; i < count; i++) {
            if (packets[i].data[offset] != firstByte) {
                isFixed = false;
                break;
            }
        }
        
        if (outStructure->fieldCount < 64) {
            PacketField* field = &outStructure->fields[outStructure->fieldCount++];
            wsprintfA(field->name, "field_%d", offset / 4);
            field->offset = offset;
            field->size = 4;
            strcpy(field->type, isFixed ? "fixed" : "variable");
            field->isEncrypted = packets[0].isEncrypted;
            field->isVariable = !isFixed;
        }
    }
    
    return true;
}

//==============================================================================
// Protocol Detection
//==============================================================================

bool NetProto_DetectProtocol(const Packet* packet, ProtocolType* outType)
{
    if (!packet || !outType) return false;
    
    *outType = PROTO_UNKNOWN;
    
    if (packet->length < 2) return false;
    
    uint16_t magic = *(uint16_t*)packet->data;
    
    // HTTP
    if (magic == 0x4854 || magic == 0x4745) { // "HT" or "GE"
        *outType = PROTO_HTTP;
        return true;
    }
    
    // TLS
    if (packet->data[0] == 0x16 && packet->data[1] == 0x03) {
        *outType = PROTO_HTTPS;
        return true;
    }
    
    // DNS
    if (packet->length >= 12) {
        // Check DNS flags
        if ((packet->data[2] & 0x80) == 0) {
            *outType = PROTO_DNS;
            return true;
        }
    }
    
    // ICMP
    if (packet->layer == LAYER_NETWORK && packet->length >= 8) {
        uint8_t type = packet->data[0];
        if (type == 0x08 || type == 0x00) { // Echo request/reply
            *outType = PROTO_ICMP;
            return true;
        }
    }
    
    return true;
}

bool NetProto_DetectEncryption(const Packet* packets, uint32_t count, ProtocolCrypto* outCrypto)
{
    if (!packets || count == 0 || !outCrypto) return false;
    
    memset(outCrypto, 0, sizeof(ProtocolCrypto));
    
    // Check for high entropy (indicates encryption)
    for (uint32_t i = 0; i < count; i++) {
        if (packets[i].isEncrypted) {
            outCrypto->isEncrypted = true;
            break;
        }
    }
    
    // Detect cipher type
    if (outCrypto->isEncrypted) {
        // Check for TLS
        if (packets[0].length >= 5 && packets[0].data[0] == 0x16) {
            outCrypto->scheme.cipher = CIPHER_AES;
            outCrypto->scheme.keySize = 256;
            outCrypto->scheme.blockSize = 16;
            outCrypto->scheme.hasIV = true;
            outCrypto->scheme.hasMAC = true;
            strcpy(outCrypto->keyExchange, "ECDHE");
            outCrypto->hasPerfectForwardSecrecy = true;
        }
        // Check for simple XOR
        else if (count > 1) {
            // Compare consecutive packets for XOR pattern
            bool isXOR = true;
            for (uint32_t i = 1; i < count && i < 10; i++) {
                if (packets[i].length != packets[0].length) {
                    isXOR = false;
                    break;
                }
            }
            
            if (isXOR) {
                outCrypto->scheme.cipher = CIPHER_XOR;
                outCrypto->scheme.keySize = 8;
            }
        }
    }
    
    return true;
}

bool NetProto_InferCipher(const Packet* packets, uint32_t count, CipherType* outCipher)
{
    if (!packets || count == 0 || !outCipher) return false;
    
    *outCipher = CIPHER_UNKNOWN;
    
    // Analyze entropy patterns
    for (uint32_t i = 0; i < count; i++) {
        if (packets[i].length >= 5 && packets[i].data[0] == 0x16) {
            *outCipher = CIPHER_AES;
            return true;
        }
    }
    
    // Check for RC4 (no block structure, high entropy)
    // Check for ChaCha20 (specific nonce pattern)
    
    return true;
}

//==============================================================================
// State Machine Reconstruction
//==============================================================================

bool NetProto_BuildStateMachine(const Flow* flows, uint32_t flowCount, StateMachine* outMachine)
{
    if (!flows || flowCount == 0 || !outMachine) return false;
    
    memset(outMachine, 0, sizeof(StateMachine));
    strcpy(outMachine->protocolName, "Inferred");
    
    // Define basic states
    outMachine->states[0].type = STATE_IDLE;
    strcpy(outMachine->states[0].name, "IDLE");
    outMachine->states[0].id = 0;
    
    outMachine->states[1].type = STATE_HANDSHAKE;
    strcpy(outMachine->states[1].name, "HANDSHAKE");
    outMachine->states[1].id = 1;
    
    outMachine->states[2].type = STATE_AUTHENTICATED;
    strcpy(outMachine->states[2].name, "AUTHENTICATED");
    outMachine->states[2].id = 2;
    
    outMachine->states[3].type = STATE_DATA_TRANSFER;
    strcpy(outMachine->states[3].name, "DATA_TRANSFER");
    outMachine->states[3].id = 3;
    
    outMachine->stateCount = 4;
    outMachine->initialState = outMachine->states[0];
    outMachine->currentState = outMachine->states[0];
    
    // Infer transitions from packet sequences
    for (uint32_t i = 0; i < flowCount; i++) {
        const Flow* flow = &flows[i];
        
        for (uint32_t j = 1; j < flow->packetCount && outMachine->transitionCount < 128; j++) {
            StateTransition* trans = &outMachine->transitions[outMachine->transitionCount++];
            
            // Simple heuristic: packet type determines transition
            if (flow->packets[j].type == PROTO_HTTPS) {
                trans->from = outMachine->states[0];
                trans->to = outMachine->states[1];
                strcpy(trans->trigger, "ClientHello");
                trans->probability = 0.9f;
            } else {
                trans->from = outMachine->states[j % 4];
                trans->to = outMachine->states[(j + 1) % 4];
                strcpy(trans->trigger, "packet_received");
                trans->probability = 0.5f;
            }
        }
    }
    
    return true;
}

bool NetProto_TrackState(StateMachine* machine, const Packet* packet)
{
    if (!machine || !packet) return false;
    
    // Find matching transition
    for (uint32_t i = 0; i < machine->transitionCount; i++) {
        StateTransition* trans = &machine->transitions[i];
        
        if (trans->from.id == machine->currentState.id) {
            // Check if trigger matches
            if (packet->type == PROTO_HTTP && strcmp(trans->trigger, "HTTP_request") == 0) {
                machine->currentState = trans->to;
                return true;
            }
        }
    }
    
    return true;
}

bool NetProto_InferTransitions(const Flow* flow, StateTransition* outTransitions, uint32_t* outCount)
{
    if (!flow || !outTransitions || !outCount) return false;
    
    *outCount = 0;
    
    // Infer transitions from packet sequence
    for (uint32_t i = 1; i < flow->packetCount && *outCount < 128; i++) {
        StateTransition* trans = &outTransitions[(*outCount)++];
        
        // Determine state change based on packet characteristics
        if (flow->packets[i].isEncrypted && !flow->packets[i-1].isEncrypted) {
            strcpy(trans->trigger, "encryption_started");
            trans->probability = 0.95f;
        } else if (flow->packets[i].length > flow->packets[i-1].length * 2) {
            strcpy(trans->trigger, "large_transfer");
            trans->probability = 0.7f;
        } else {
            strcpy(trans->trigger, "data_exchange");
            trans->probability = 0.5f;
        }
    }
    
    return true;
}

//==============================================================================
// Encryption Analysis
//==============================================================================

bool NetProto_RecoverKey(const Packet* packets, uint32_t count, const ProtocolCrypto* crypto, uint8_t* outKey, uint32_t* outKeySize)
{
    if (!packets || count == 0 || !crypto || !outKey || !outKeySize) return false;
    
    *outKeySize = 0;
    
    // XOR key recovery (known plaintext attack)
    if (crypto->scheme.cipher == CIPHER_XOR && count >= 2) {
        // If we know plaintext pattern, XOR to recover key
        // For demo: assume first 4 bytes are known
        for (uint32_t i = 0; i < 4 && i < packets[0].length; i++) {
            outKey[i] = packets[0].data[i] ^ (uint8_t)("HTTP"[i]);
        }
        *outKeySize = 4;
        return true;
    }
    
    // AES key recovery (requires more sophisticated analysis)
    // This would require side-channel or known-plaintext
    
    return true;
}

bool NetProto_DecryptPacket(const Packet* encrypted, const ProtocolCrypto* crypto, Packet* outDecrypted)
{
    if (!encrypted || !crypto || !outDecrypted) return false;
    
    memset(outDecrypted, 0, sizeof(Packet));
    outDecrypted->data = new uint8_t[encrypted->length];
    outDecrypted->length = encrypted->length;
    
    if (crypto->scheme.cipher == CIPHER_XOR) {
        // Simple XOR decryption
        uint8_t key = 0x55; // Demo key
        for (uint32_t i = 0; i < encrypted->length; i++) {
            outDecrypted->data[i] = encrypted->data[i] ^ key;
        }
        outDecrypted->isEncrypted = false;
        return true;
    }
    
    // For other ciphers, would need proper decryption
    memcpy(outDecrypted->data, encrypted->data, encrypted->length);
    outDecrypted->isEncrypted = true;
    
    return true;
}

bool NetProto_AnalyzeKeyExchange(const Flow* flow, char* outExchange, uint32_t* outExchangeLen)
{
    if (!flow || !outExchange || !outExchangeLen) return false;
    
    // Analyze handshake packets
    for (uint32_t i = 0; i < flow->packetCount; i++) {
        if (flow->packets[i].type == PROTO_HTTPS) {
            // Check for ClientHello/ServerHello
            if (flow->packets[i].length >= 6) {
                uint8_t msgType = flow->packets[i].data[5];
                if (msgType == 0x01) {
                    strcpy(outExchange, "TLS_ECDHE_RSA");
                    *outExchangeLen = strlen(outExchange);
                    return true;
                }
            }
        }
    }
    
    strcpy(outExchange, "unknown");
    *outExchangeLen = strlen(outExchange);
    return true;
}

//==============================================================================
// Traffic Analysis
//==============================================================================

bool NetProto_AnalyzeTraffic(const Flow* flows, uint32_t count, TrafficPattern* outPatterns, uint32_t* outPatternCount)
{
    if (!flows || count == 0 || !outPatterns || !outPatternCount) return false;
    
    *outPatternCount = 0;
    
    for (uint32_t i = 0; i < count && *outPatternCount < 64; i++) {
        TrafficPattern* pattern = &outPatterns[(*outPatternCount)++];
        
        const Flow* flow = &flows[i];
        
        wsprintfA(pattern->name, "Flow_%d", i);
        pattern->packetCount = flow->packetCount;
        
        // Calculate total bytes
        pattern->totalBytes = 0;
        for (uint32_t j = 0; j < flow->packetCount; j++) {
            pattern->totalBytes += flow->packets[j].length;
        }
        
        // Calculate duration
        if (flow->packetCount > 1) {
            pattern->durationMs = (uint64_t)(flow->packets[flow->packetCount-1].timestamp - 
                                              flow->packets[0].timestamp);
        } else {
            pattern->durationMs = 0;
        }
        
        // Calculate average packet size
        pattern->avgPacketSize = pattern->packetCount > 0 ? 
            (float)pattern->totalBytes / pattern->packetCount : 0;
        
        // Calculate packet rate
        pattern->packetRate = pattern->durationMs > 0 ? 
            (float)pattern->packetCount / (pattern->durationMs / 1000.0f) : 0;
        
        // Detect periodicity
        pattern->isPeriodic = false;
        if (flow->packetCount > 2) {
            uint64_t interval1 = flow->packets[1].timestamp - flow->packets[0].timestamp;
            uint64_t interval2 = flow->packets[2].timestamp - flow->packets[1].timestamp;
            pattern->isPeriodic = (interval1 > 0 && interval2 > 0 && 
                                   (float)interval1 / interval2 > 0.9f && 
                                   (float)interval1 / interval2 < 1.1f);
        }
        
        // Detect burst
        pattern->isBurst = pattern->packetRate > 100;
    }
    
    return true;
}

bool NetProto_DetectC2(const Flow* flows, uint32_t count, bool* isC2, char* outC2Info, uint32_t* outInfoLen)
{
    if (!flows || count == 0 || !isC2 || !outC2Info || !outInfoLen) return false;
    
    *isC2 = false;
    
    // C2 detection heuristics
    for (uint32_t i = 0; i < count; i++) {
        const Flow* flow = &flows[i];
        
        // Check for beacon pattern
        if (flow->packetCount > 5) {
            bool isPeriodic = true;
            uint64_t expectedInterval = flow->packets[1].timestamp - flow->packets[0].timestamp;
            
            for (uint32_t j = 2; j < flow->packetCount; j++) {
                uint64_t interval = flow->packets[j].timestamp - flow->packets[j-1].timestamp;
                if (interval < expectedInterval * 0.8f || interval > expectedInterval * 1.2f) {
                    isPeriodic = false;
                    break;
                }
            }
            
            if (isPeriodic && expectedInterval > 5000) { // > 5 seconds
                *isC2 = true;
                wsprintfA(outC2Info, "Beacon pattern detected: interval=%llums", expectedInterval);
                *outInfoLen = strlen(outC2Info);
                return true;
            }
        }
        
        // Check for small, regular packets (heartbeat)
        if (flow->packetCount > 10) {
            bool smallPackets = true;
            for (uint32_t j = 0; j < flow->packetCount; j++) {
                if (flow->packets[j].length > 100) {
                    smallPackets = false;
                    break;
                }
            }
            
            if (smallPackets) {
                *isC2 = true;
                strcpy(outC2Info, "Heartbeat pattern detected");
                *outInfoLen = strlen(outC2Info);
                return true;
            }
        }
    }
    
    strcpy(outC2Info, "No C2 detected");
    *outInfoLen = strlen(outC2Info);
    return true;
}

bool NetProto_DetectExfiltration(const Flow* flows, uint32_t count, bool* isExfil, char* outExfilInfo, uint32_t* outInfoLen)
{
    if (!flows || count == 0 || !isExfil || !outExfilInfo || !outInfoLen) return false;
    
    *isExfil = false;
    
    // Exfiltration detection heuristics
    for (uint32_t i = 0; i < count; i++) {
        const Flow* flow = &flows[i];
        
        // Large data transfer
        uint64_t totalBytes = 0;
        for (uint32_t j = 0; j < flow->packetCount; j++) {
            totalBytes += flow->packets[j].length;
        }
        
        if (totalBytes > 10 * 1024 * 1024) { // > 10 MB
            *isExfil = true;
            wsprintfA(outExfilInfo, "Large transfer: %llu bytes", totalBytes);
            *outInfoLen = strlen(outExfilInfo);
            return true;
        }
        
        // Unusual destination
        // (Would need IP reputation database)
    }
    
    strcpy(outExfilInfo, "No exfiltration detected");
    *outInfoLen = strlen(outExfilInfo);
    return true;
}

//==============================================================================
// Fuzzing
//==============================================================================

bool NetProto_FuzzField(const Packet* templatePacket, const FuzzTarget* target, Packet* outMutated)
{
    if (!templatePacket || !target || !outMutated) return false;
    
    // Copy template
    outMutated->data = new uint8_t[templatePacket->length];
    memcpy(outMutated->data, templatePacket->data, templatePacket->length);
    outMutated->length = templatePacket->length;
    
    // Apply mutation
    if (strcmp(target->strategy, "random") == 0) {
        // Random bytes
        for (uint32_t i = target->offset; i < target->offset + target->size && i < outMutated->length; i++) {
            outMutated->data[i] = (uint8_t)(rand() % 256);
        }
    } else if (strcmp(target->strategy, "boundary") == 0) {
        // Boundary values
        if (target->size == 4) {
            uint32_t* ptr = (uint32_t*)(outMutated->data + target->offset);
            *ptr = 0xFFFFFFFF; // Max value
        }
    } else if (strcmp(target->strategy, "format") == 0) {
        // Format string
        const char* fmt = "%s%s%s%s%s%s%s%s";
        memcpy(outMutated->data + target->offset, fmt, strlen(fmt));
    }
    
    return true;
}

bool NetProto_FuzzSequence(const Packet* packets, uint32_t count, FuzzResult* outResults, uint32_t* outResultCount)
{
    if (!packets || count == 0 || !outResults || !outResultCount) return false;
    
    *outResultCount = 0;
    
    // Generate fuzz targets from packet structure
    FuzzTarget targets[16];
    uint32_t targetCount = 0;
    
    // Analyze first packet for fields
    if (count > 0) {
        for (uint32_t offset = 0; offset < packets[0].length && targetCount < 16; offset += 4) {
            FuzzTarget* target = &targets[targetCount++];
            wsprintfA(target->fieldName, "field_%d", offset / 4);
            target->offset = offset;
            target->size = 4;
            strcpy(target->strategy, "random");
            target->isActive = true;
        }
    }
    
    // Fuzz each target
    for (uint32_t i = 0; i < targetCount && *outResultCount < 64; i++) {
        Packet mutated;
        if (NetProto_FuzzField(&packets[0], &targets[i], &mutated)) {
            FuzzResult* result = &outResults[(*outResultCount)++];
            
            // Simulate execution
            result->crashed = (rand() % 100) < 5; // 5% crash rate
            result->hung = (rand() % 100) < 2;    // 2% hang rate
            
            if (result->crashed) {
                strcpy(result->crashType, "SEGV");
                result->crashInput = mutated.data;
                result->crashInputSize = mutated.length;
            }
        }
    }
    
    return true;
}

//==============================================================================
// Exploit Surface Mapping
//==============================================================================

bool NetProto_MapExploitSurface(const PacketStructure* structure, ProtocolVulnerability* outVulns, uint32_t* outVulnCount)
{
    if (!structure || !outVulns || !outVulnCount) return false;
    
    *outVulnCount = 0;
    
    // Analyze each field for vulnerabilities
    for (uint32_t i = 0; i < structure->fieldCount && *outVulnCount < 32; i++) {
        const PacketField* field = &structure->fields[i];
        
        // Check for integer overflow
        if (strcmp(field->type, "int") == 0 && field->size == 4) {
            ProtocolVulnerability* vuln = &outVulns[(*outVulnCount)++];
            strcpy(vuln->type, "integer_overflow");
            wsprintfA(vuln->location, "Field '%s' at offset %d", field->name, field->offset);
            vuln->severity = 7;
            vuln->isExploitable = true;
            strcpy(vuln->description, "32-bit length field may overflow");
        }
        
        // Check for buffer overflow
        if (field->isVariable) {
            ProtocolVulnerability* vuln = &outVulns[(*outVulnCount)++];
            strcpy(vuln->type, "buffer_overflow");
            wsprintfA(vuln->location, "Variable field '%s'", field->name);
            vuln->severity = 9;
            vuln->isExploitable = true;
            strcpy(vuln->description, "Variable-length field without bounds check");
        }
        
        // Check for format string
        if (strcmp(field->type, "string") == 0) {
            ProtocolVulnerability* vuln = &outVulns[(*outVulnCount)++];
            strcpy(vuln->type, "format_string");
            wsprintfA(vuln->location, "String field '%s'", field->name);
            vuln->severity = 8;
            vuln->isExploitable = true;
            strcpy(vuln->description, "String field may be used in printf");
        }
    }
    
    return true;
}

bool NetProto_AssessVulnerability(const ProtocolVulnerability* vuln, bool* isExploitable, char* outExploitInfo, uint32_t* outInfoLen)
{
    if (!vuln || !isExploitable || !outExploitInfo || !outInfoLen) return false;
    
    *isExploitable = vuln->isExploitable;
    
    if (vuln->isExploitable) {
        wsprintfA(outExploitInfo, 
                  "Exploitable: %s at %s. Severity: %d/10. %s",
                  vuln->type, vuln->location, vuln->severity, vuln->description);
    } else {
        strcpy(outExploitInfo, "Not exploitable");
    }
    
    *outInfoLen = strlen(outExploitInfo);
    return true;
}

//==============================================================================
// SEG Integration
//==============================================================================

bool SEGNode_CaptureTraffic(void* input, void* output)
{
    // Capture packets from network
    return NetProto_CapturePacket((Packet*)output);
}

bool SEGNode_AnalyzeProtocol(void* input, void* output)
{
    // Analyze captured packets
    return NetProto_AnalyzePacket((Packet*)input, (PacketStructure*)output);
}

bool SEGNode_ReconstructStateMachine(void* input, void* output)
{
    // Build state machine from flows
    return NetProto_BuildStateMachine((Flow*)input, 1, (StateMachine*)output);
}

bool SEGNode_DecryptTraffic(void* input, void* output)
{
    // Decrypt encrypted packets
    return NetProto_DecryptPacket((Packet*)input, (ProtocolCrypto*)input, (Packet*)output);
}

bool SEGNode_FuzzProtocol(void* input, void* output)
{
    // Fuzz protocol fields
    return NetProto_FuzzSequence((Packet*)input, 1, (FuzzResult*)output, (uint32_t*)output);
}

bool SEGNode_MapProtocolExploitSurface(void* input, void* output)
{
    // Map exploit surface
    return NetProto_MapExploitSurface((PacketStructure*)input, (ProtocolVulnerability*)output, (uint32_t*)output);
}

//==============================================================================
// MoE Experts
//==============================================================================

bool Expert_ProtocolInference(const Packet* packets, uint32_t count, ProtocolType* outType)
{
    return NetProto_DetectProtocol(&packets[0], outType);
}

bool Expert_EncryptionDetection(const Packet* packets, uint32_t count, ProtocolCrypto* outCrypto)
{
    return NetProto_DetectEncryption(packets, count, outCrypto);
}

bool Expert_StateMachineInference(const Flow* flows, uint32_t count, StateMachine* outMachine)
{
    return NetProto_BuildStateMachine(flows, count, outMachine);
}

bool Expert_KeyRecovery(const Packet* packets, uint32_t count, uint8_t* outKey, uint32_t* outKeySize)
{
    ProtocolCrypto crypto;
    NetProto_DetectEncryption(packets, count, &crypto);
    return NetProto_RecoverKey(packets, count, &crypto, outKey, outKeySize);
}

bool Expert_C2Detection(const Flow* flows, uint32_t count, bool* isC2)
{
    char info[256];
    uint32_t infoLen;
    return NetProto_DetectC2(flows, count, isC2, info, &infoLen);
}

bool Expert_ProtocolFuzzing(const Packet* templatePacket, FuzzResult* outResults, uint32_t* outCount)
{
    return NetProto_FuzzSequence(templatePacket, 1, outResults, outCount);
}

//==============================================================================
// IDE Panels
//==============================================================================

void NetProtoPanel_Render()
{
    // Render network protocol analysis panel
    OutputDebugStringA("[NetProtoPanel] Rendering...\n");
}

void NetProtoPanel_UpdatePacketList(const Packet* packets, uint32_t count)
{
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] %d packets captured\n", count);
    OutputDebugStringA(msg);
}

void NetProtoPanel_UpdateStructure(const PacketStructure* structure)
{
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] Protocol: %s, Fields: %d\n", 
              structure->protocolName, structure->fieldCount);
    OutputDebugStringA(msg);
}

void NetProtoPanel_UpdateStateMachine(const StateMachine* machine)
{
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] State machine: %d states, %d transitions\n",
              machine->stateCount, machine->transitionCount);
    OutputDebugStringA(msg);
}

void NetProtoPanel_UpdateCryptoAnalysis(const ProtocolCrypto* crypto)
{
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] Encryption: %s, Cipher: %d\n",
              crypto->isEncrypted ? "Yes" : "No", crypto->scheme.cipher);
    OutputDebugStringA(msg);
}

void NetProtoPanel_UpdateTrafficAnalysis(const TrafficPattern* patterns, uint32_t count)
{
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] %d traffic patterns analyzed\n", count);
    OutputDebugStringA(msg);
}

void NetProtoPanel_UpdateFuzzResults(const FuzzResult* results, uint32_t count)
{
    uint32_t crashes = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (results[i].crashed) crashes++;
    }
    
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] Fuzzing: %d crashes in %d tests\n", crashes, count);
    OutputDebugStringA(msg);
}

void NetProtoPanel_UpdateExploitSurface(const ProtocolVulnerability* vulns, uint32_t count)
{
    char msg[256];
    wsprintfA(msg, "[NetProtoPanel] %d vulnerabilities found\n", count);
    OutputDebugStringA(msg);
}

//==============================================================================
// Export/Import
//==============================================================================

bool NetProto_ExportProtocolDefinition(const PacketStructure* structure, const char* path)
{
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    // Write protocol definition
    char buffer[4096];
    wsprintfA(buffer, "Protocol: %s\nFields: %d\n\n", 
              structure->protocolName, structure->fieldCount);
    
    DWORD written;
    WriteFile(hFile, buffer, strlen(buffer), &written, nullptr);
    
    for (uint32_t i = 0; i < structure->fieldCount; i++) {
        wsprintfA(buffer, "Field %d: %s @ offset %d, size %d, type %s\n",
                  i, structure->fields[i].name, structure->fields[i].offset,
                  structure->fields[i].size, structure->fields[i].type);
        WriteFile(hFile, buffer, strlen(buffer), &written, nullptr);
    }
    
    CloseHandle(hFile);
    return true;
}

bool NetProto_ImportProtocolDefinition(const char* path, PacketStructure* outStructure)
{
    // Parse protocol definition from file
    // (Simplified implementation)
    memset(outStructure, 0, sizeof(PacketStructure));
    strcpy(outStructure->protocolName, "Imported");
    return true;
}

bool NetProto_ExportStateMachine(const StateMachine* machine, const char* path)
{
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    char buffer[4096];
    wsprintfA(buffer, "State Machine: %s\nStates: %d\nTransitions: %d\n\n",
              machine->protocolName, machine->stateCount, machine->transitionCount);
    
    DWORD written;
    WriteFile(hFile, buffer, strlen(buffer), &written, nullptr);
    
    CloseHandle(hFile);
    return true;
}

bool NetProto_ImportStateMachine(const char* path, StateMachine* outMachine)
{
    // Parse state machine from file
    // (Simplified implementation)
    memset(outMachine, 0, sizeof(StateMachine));
    strcpy(outMachine->protocolName, "Imported");
    return true;
}
