//==============================================================================
// SRIPProtocol.cpp - Phase LMM-5: SRIP Protocol Implementation
//==============================================================================

#include "SRIPProtocol.h"
#include <cstring>
#include <cstdio>

//==============================================================================
// Protocol Functions
//==============================================================================

void SRIP_InitHeader(SRIP_Header* hdr, SRIPMessageType type, uint32_t payload_len) {
    if (!hdr) return;
    
    hdr->magic = SRIP_MAGIC;
    hdr->version_major = SRIP_VERSION_MAJOR;
    hdr->version_minor = SRIP_VERSION_MINOR;
    hdr->msg_type = (uint16_t)type;
    hdr->payload_length = payload_len;
    hdr->request_id = SRIP_GenerateRequestId();
    hdr->flags = 0;
}

int SRIP_ValidateHeader(const SRIP_Header* hdr) {
    if (!hdr) return -1;
    
    if (hdr->magic != SRIP_MAGIC) {
        return -1;
    }
    
    if (hdr->version_major != SRIP_VERSION_MAJOR) {
        return -1;
    }
    
    if (hdr->payload_length > SRIP_MAX_PAYLOAD) {
        return -1;
    }
    
    return 0;
}

int SRIP_SerializeHeader(const SRIP_Header* hdr, uint8_t* buf, size_t buf_size) {
    if (!hdr || !buf || buf_size < SRIP_HEADER_SIZE) {
        return -1;
    }
    
    // Write fields in little-endian
    buf[0] = (hdr->magic >> 0) & 0xFF;
    buf[1] = (hdr->magic >> 8) & 0xFF;
    buf[2] = (hdr->magic >> 16) & 0xFF;
    buf[3] = (hdr->magic >> 24) & 0xFF;
    
    buf[4] = (hdr->version_major >> 0) & 0xFF;
    buf[5] = (hdr->version_major >> 8) & 0xFF;
    
    buf[6] = (hdr->version_minor >> 0) & 0xFF;
    buf[7] = (hdr->version_minor >> 8) & 0xFF;
    
    buf[8] = (hdr->msg_type >> 0) & 0xFF;
    buf[9] = (hdr->msg_type >> 8) & 0xFF;
    
    buf[10] = (hdr->payload_length >> 0) & 0xFF;
    buf[11] = (hdr->payload_length >> 8) & 0xFF;
    buf[12] = (hdr->payload_length >> 16) & 0xFF;
    buf[13] = (hdr->payload_length >> 24) & 0xFF;
    
    buf[14] = (hdr->request_id >> 0) & 0xFF;
    buf[15] = (hdr->request_id >> 8) & 0xFF;
    buf[16] = (hdr->request_id >> 16) & 0xFF;
    buf[17] = (hdr->request_id >> 24) & 0xFF;
    
    buf[18] = (hdr->flags >> 0) & 0xFF;
    buf[19] = (hdr->flags >> 8) & 0xFF;
    buf[20] = (hdr->flags >> 16) & 0xFF;
    buf[21] = (hdr->flags >> 24) & 0xFF;
    
    return 0;
}

int SRIP_DeserializeHeader(const uint8_t* buf, size_t buf_size, SRIP_Header* hdr) {
    if (!buf || !hdr || buf_size < SRIP_HEADER_SIZE) {
        return -1;
    }
    
    hdr->magic = 
        ((uint32_t)buf[0] << 0) |
        ((uint32_t)buf[1] << 8) |
        ((uint32_t)buf[2] << 16) |
        ((uint32_t)buf[3] << 24);
    
    hdr->version_major = 
        ((uint16_t)buf[4] << 0) |
        ((uint16_t)buf[5] << 8);
    
    hdr->version_minor = 
        ((uint16_t)buf[6] << 0) |
        ((uint16_t)buf[7] << 8);
    
    hdr->msg_type = 
        ((uint16_t)buf[8] << 0) |
        ((uint16_t)buf[9] << 8);
    
    hdr->payload_length = 
        ((uint32_t)buf[10] << 0) |
        ((uint32_t)buf[11] << 8) |
        ((uint32_t)buf[12] << 16) |
        ((uint32_t)buf[13] << 24);
    
    hdr->request_id = 
        ((uint32_t)buf[14] << 0) |
        ((uint32_t)buf[15] << 8) |
        ((uint32_t)buf[16] << 16) |
        ((uint32_t)buf[17] << 24);
    
    hdr->flags = 
        ((uint32_t)buf[18] << 0) |
        ((uint32_t)buf[19] << 8) |
        ((uint32_t)buf[20] << 16) |
        ((uint32_t)buf[21] << 24);
    
    return 0;
}

const char* SRIP_MessageTypeName(SRIPMessageType type) {
    switch (type) {
        case SRIP_MSG_HELLO: return "HELLO";
        case SRIP_MSG_WELCOME: return "WELCOME";
        case SRIP_MSG_GOODBYE: return "GOODBYE";
        case SRIP_MSG_CAPABILITIES: return "CAPABILITIES";
        case SRIP_MSG_SELECT_MODEL: return "SELECT_MODEL";
        case SRIP_MSG_PROMPT: return "PROMPT";
        case SRIP_MSG_TOKEN: return "TOKEN";
        case SRIP_MSG_COMPLETE: return "COMPLETE";
        case SRIP_MSG_ABORT: return "ABORT";
        case SRIP_MSG_METRICS: return "METRICS";
        case SRIP_MSG_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

const char* SRIP_ErrorCodeName(SRIPErrorCode code) {
    switch (code) {
        case SRIP_ERR_NONE: return "NONE";
        case SRIP_ERR_UNKNOWN_MSG: return "UNKNOWN_MSG";
        case SRIP_ERR_INVALID_VERSION: return "INVALID_VERSION";
        case SRIP_ERR_MODEL_NOT_FOUND: return "MODEL_NOT_FOUND";
        case SRIP_ERR_MODEL_BUSY: return "MODEL_BUSY";
        case SRIP_ERR_OUT_OF_MEMORY: return "OUT_OF_MEMORY";
        case SRIP_ERR_TIMEOUT: return "TIMEOUT";
        case SRIP_ERR_INVALID_PROMPT: return "INVALID_PROMPT";
        case SRIP_ERR_SERVER_ERROR: return "SERVER_ERROR";
        default: return "UNKNOWN";
    }
}

//==============================================================================
// Utility
//==============================================================================

static uint32_t g_request_id_counter = 1;

uint32_t SRIP_GenerateRequestId(void) {
    return g_request_id_counter++;
}

void SRIP_FormatHeader(const SRIP_Header* hdr, char* out, size_t out_size) {
    if (!hdr || !out || out_size == 0) return;
    
    snprintf(out, out_size,
             "SRIP v%d.%d | %s | req=%u | len=%u | flags=%u",
             hdr->version_major,
             hdr->version_minor,
             SRIP_MessageTypeName((SRIPMessageType)hdr->msg_type),
             hdr->request_id,
             hdr->payload_length,
             hdr->flags);
}
