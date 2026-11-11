/*=============================================================================
 * AwsSigV4Signer.h — Native Win32 AWS Signature V4 Implementation
 *
 * Pure Win32 HMAC-SHA256 signing for AWS API requests.
 * No external dependencies — uses Windows CryptoAPI (advapi32).
 *
 * This implements the AWS Signature V4 process:
 *   1. Create a canonical request
 *   2. Create a string-to-sign
 *   3. Compute the signature using HMAC-SHA256
 *   4. Build the Authorization header
 *
 * Pattern:  Structured results, no exceptions
 * Threading: Fully reentrant — all state is caller-provided buffers
 *===========================================================================*/

#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <cstdint>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * CONSTANTS
 *===========================================================================*/

#define AWS_SIGV4_MAX_HEADER_SIZE    4096
#define AWS_SIGV4_SHA256_HEX_SIZE    65    // 64 hex chars + null
#define AWS_SIGV4_MAX_REGION         64
#define AWS_SIGV4_MAX_SERVICE        64
#define AWS_SIGV4_MAX_KEY_ID         256
#define AWS_SIGV4_MAX_SECRET_KEY     256
#define AWS_SIGV4_ISO8601_SIZE       20    // YYYYMMDDTHHmmssZ + null
#define AWS_SIGV4_DATE_SIZE          9     // YYYYMMDD + null

/*=============================================================================
 * STRUCTURES
 *============================================================================*/

typedef struct {
    char    accessKeyId[AWS_SIGV4_MAX_KEY_ID];
    char    secretAccessKey[AWS_SIGV4_MAX_SECRET_KEY];
    char    region[AWS_SIGV4_MAX_REGION];
    char    service[AWS_SIGV4_MAX_SERVICE];
} AwsCredentials;

typedef struct {
    char    method[16];             // GET, POST, etc.
    char    canonicalUri[1024];     // /path/to/resource
    char    canonicalQueryString[1024]; // ?param=value
    char    host[256];              // service.region.amazonaws.com
    char    bodyHash[AWS_SIGV4_SHA256_HEX_SIZE]; // SHA256 of payload
    char    signedHeaders[512];     // Semi-colon separated header names
    char    authorization[AWS_SIGV4_MAX_HEADER_SIZE]; // Output: full Authorization header
    char    xAmzDate[AWS_SIGV4_ISO8601_SIZE];   // X-Amz-Date value
    char    xAmzTarget[256];        // X-Amz-Target value (for JSON 1.0)
    char    contentType[64];        // Content-Type value
} AwsSigV4Request;

/*=============================================================================
 * API FUNCTIONS
 *============================================================================*/

/**
 * @brief Compute SHA-256 hex digest of a buffer
 * @param data      Input data
 * @param dataLen   Length of input data
 * @param outHex    Output buffer (must be AWS_SIGV4_SHA256_HEX_SIZE bytes)
 * @return TRUE on success
 */
BOOL AwsSigV4_Sha256Hex(const BYTE* data, size_t dataLen, char* outHex);

/**
 * @brief Compute SHA-256 of a string and return hex
 * @param str       Null-terminated input string
 * @param outHex    Output buffer (must be AWS_SIGV4_SHA256_HEX_SIZE bytes)
 * @return TRUE on success
 */
BOOL AwsSigV4_Sha256HexString(const char* str, char* outHex);

/**
 * @brief Get current UTC time in ISO 8601 format
 * @param outIso    Output buffer (must be AWS_SIGV4_ISO8601_SIZE bytes)
 * @param outDate   Output buffer for YYYYMMDD (must be AWS_SIGV4_DATE_SIZE bytes)
 */
void AwsSigV4_GetTimestamp(char* outIso, char* outDate);

/**
 * @brief Sign an AWS request using Signature V4
 *
 * This is the main entry point. It computes the full Authorization header
 * and populates request->authorization.
 *
 * @param creds     AWS credentials (access key, secret key, region, service)
 * @param request   Request parameters (method, uri, host, body, etc.)
 *                  On success, request->authorization is populated
 * @return TRUE on success
 */
BOOL AwsSigV4_Sign(const AwsCredentials* creds, AwsSigV4Request* request);

/**
 * @brief Convenience: Build a complete POST request for Bedrock JSON 1.0
 *
 * Populates all fields of request for a typical Bedrock API call.
 *
 * @param creds     AWS credentials
 * @param request   Request structure to populate
 * @param target    X-Amz-Target value (e.g., "BedrockAgentRuntime.InvokeAgent")
 * @param bodyJson  The JSON payload body
 * @return TRUE on success
 */
BOOL AwsSigV4_BuildBedrockPost(
    const AwsCredentials* creds,
    AwsSigV4Request* request,
    const char* target,
    const char* bodyJson
);

#ifdef __cplusplus
}
#endif
