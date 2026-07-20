/*=============================================================================
 * AwsSigV4Signer.cpp — Native Win32 AWS Signature V4 Implementation
 *
 * Pure Win32 implementation using Windows CryptoAPI (advapi32.lib).
 * No external dependencies — no OpenSSL, no libcurl, no boto3.
 *
 * Implements: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
 *===========================================================================*/

#include "AwsSigV4Signer.h"
#include <stdio.h>
#include <string.h>

/*=============================================================================
 * INTERNAL: Hex encoding helpers
 *===========================================================================*/

static const char HEX_CHARS[] = "0123456789abcdef";

static void BytesToHex(const BYTE* bytes, size_t len, char* out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_CHARS[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX_CHARS[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

/*=============================================================================
 * SHA-256 HASHING
 *===========================================================================*/

BOOL AwsSigV4_Sha256Hex(const BYTE* data, size_t dataLen, char* outHex) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[32];
    DWORD hashLen = sizeof(hash);
    BOOL result = FALSE;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        goto cleanup;
    }

    if (!CryptHashData(hHash, data, (DWORD)dataLen, 0)) {
        goto cleanup;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        goto cleanup;
    }

    BytesToHex(hash, hashLen, outHex);
    result = TRUE;

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
}

BOOL AwsSigV4_Sha256HexString(const char* str, char* outHex) {
    return AwsSigV4_Sha256Hex((const BYTE*)str, strlen(str), outHex);
}

/*=============================================================================
 * TIMESTAMP
 *===========================================================================*/

void AwsSigV4_GetTimestamp(char* outIso, char* outDate) {
    SYSTEMTIME st;
    GetSystemTime(&st);  // UTC

    if (outIso) {
        snprintf(outIso, AWS_SIGV4_ISO8601_SIZE,
                 "%04d%02d%02dT%02d%02d%02dZ",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond);
    }

    if (outDate) {
        snprintf(outDate, AWS_SIGV4_DATE_SIZE,
                 "%04d%02d%02d",
                 st.wYear, st.wMonth, st.wDay);
    }
}

/*=============================================================================
 * INTERNAL: HMAC-SHA256
 *===========================================================================*/

static BOOL HmacSha256(const BYTE* key, DWORD keyLen,
                       const BYTE* data, DWORD dataLen,
                       BYTE* outMac, DWORD* outMacLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    HMAC_INFO hmacInfo = {0};
    BOOL result = FALSE;

    hmacInfo.HashAlgid = CALG_SHA_256;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        goto cleanup;
    }

    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
        goto cleanup;
    }

    if (!CryptHashData(hHash, data, dataLen, 0)) {
        goto cleanup;
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, outMac, outMacLen, 0)) {
        goto cleanup;
    }

    result = TRUE;

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
}

/*=============================================================================
 * INTERNAL: HMAC-SHA256 with key derivation
 *===========================================================================*/

static BOOL HmacSha256WithKey(const BYTE* key, DWORD keyLen,
                              const char* data,
                              BYTE* outMac, DWORD* outMacLen) {
    return HmacSha256(key, keyLen, (const BYTE*)data, (DWORD)strlen(data), outMac, outMacLen);
}

/*=============================================================================
 * INTERNAL: GetSignatureKey
 *
 * Derives the signing key from the secret key, date, region, and service.
 *===========================================================================*/

static BOOL GetSignatureKey(const char* secretKey, const char* date,
                            const char* region, const char* service,
                            BYTE* outSigningKey, DWORD* outKeyLen) {
    BYTE kSecret[256];
    DWORD kSecretLen;
    BYTE kDate[32], kRegion[32], kService[32], kSigning[32];
    DWORD macLen = 32;
    char dateRegionService[256];

    // kSecret = "AWS4" + secretKey
    char aws4Secret[512];
    snprintf(aws4Secret, sizeof(aws4Secret), "AWS4%s", secretKey);
    kSecretLen = (DWORD)strlen(aws4Secret);

    // kDate = HMAC-SHA256("AWS4" + secretKey, date)
    if (!HmacSha256WithKey((const BYTE*)aws4Secret, kSecretLen, date, kDate, &macLen))
        return FALSE;

    // kRegion = HMAC-SHA256(kDate, region)
    if (!HmacSha256WithKey(kDate, macLen, region, kRegion, &macLen))
        return FALSE;

    // kService = HMAC-SHA256(kRegion, service)
    if (!HmacSha256WithKey(kRegion, macLen, service, kService, &macLen))
        return FALSE;

    // kSigning = HMAC-SHA256(kService, "aws4_request")
    if (!HmacSha256WithKey(kService, macLen, "aws4_request", kSigning, &macLen))
        return FALSE;

    memcpy(outSigningKey, kSigning, macLen);
    *outKeyLen = macLen;
    return TRUE;
}

/*=============================================================================
 * MAIN: AwsSigV4_Sign
 *
 * Full SigV4 signing process:
 *   1. Canonical Request
 *   2. String to Sign
 *   3. Signature
 *   4. Authorization Header
 *===========================================================================*/

BOOL AwsSigV4_Sign(const AwsCredentials* creds, AwsSigV4Request* request) {
    char isoTime[AWS_SIGV4_ISO8601_SIZE];
    char date[AWS_SIGV4_DATE_SIZE];
    char canonicalRequest[4096];
    char stringToSign[4096];
    char signatureHex[AWS_SIGV4_SHA256_HEX_SIZE];
    BYTE signingKey[32];
    DWORD signingKeyLen = 0;
    BYTE signature[32];
    DWORD sigLen = 32;

    // Get timestamps
    AwsSigV4_GetTimestamp(isoTime, date);
    strcpy_s(request->xAmzDate, sizeof(request->xAmzDate), isoTime);

    // Build canonical request
    // CanonicalRequest = HTTPMethod + '\n' + CanonicalURI + '\n' + CanonicalQueryString + '\n' + CanonicalHeaders + '\n' + SignedHeaders + '\n' + PayloadHash
    int crLen = snprintf(canonicalRequest, sizeof(canonicalRequest),
        "%s\n"           // HTTP method
        "%s\n"           // Canonical URI
        "%s\n"           // Canonical query string
        "content-type:%s\n"  // Content-Type header
        "host:%s\n"      // Host header
        "x-amz-date:%s\n"    // X-Amz-Date header
        "x-amz-target:%s\n"  // X-Amz-Target header
        "\n"             // End of headers
        "%s\n"           // Signed headers
        "%s",            // Payload hash
        request->method,
        request->canonicalUri,
        request->canonicalQueryString,
        request->contentType,
        request->host,
        request->xAmzDate,
        request->xAmzTarget,
        request->signedHeaders,
        request->bodyHash);

    if (crLen <= 0) return FALSE;

    // Hash the canonical request
    char canonicalHash[AWS_SIGV4_SHA256_HEX_SIZE];
    if (!AwsSigV4_Sha256HexString(canonicalRequest, canonicalHash))
        return FALSE;

    // Build string-to-sign
    // StringToSign = Algorithm + '\n' + RequestDate + '\n' + CredentialScope + '\n' + HashedCanonicalRequest
    char credentialScope[256];
    snprintf(credentialScope, sizeof(credentialScope), "%s/%s/%s/aws4_request",
             date, creds->region, creds->service);

    int stsLen = snprintf(stringToSign, sizeof(stringToSign),
        "AWS4-HMAC-SHA256\n"
        "%s\n"
        "%s\n"
        "%s",
        request->xAmzDate,
        credentialScope,
        canonicalHash);

    if (stsLen <= 0) return FALSE;

    // Derive signing key
    if (!GetSignatureKey(creds->secretAccessKey, date, creds->region, creds->service,
                         signingKey, &signingKeyLen))
        return FALSE;

    // Compute signature
    if (!HmacSha256(signingKey, signingKeyLen,
                    (const BYTE*)stringToSign, (DWORD)strlen(stringToSign),
                    signature, &sigLen))
        return FALSE;

    BytesToHex(signature, sigLen, signatureHex);

    // Build Authorization header
    snprintf(request->authorization, sizeof(request->authorization),
        "AWS4-HMAC-SHA256 "
        "Credential=%s/%s, "
        "SignedHeaders=%s, "
        "Signature=%s",
        creds->accessKeyId, credentialScope,
        request->signedHeaders,
        signatureHex);

    return TRUE;
}

/*=============================================================================
 * CONVENIENCE: BuildBedrockPost
 *===========================================================================*/

BOOL AwsSigV4_BuildBedrockPost(
    const AwsCredentials* creds,
    AwsSigV4Request* request,
    const char* target,
    const char* bodyJson)
{
    // Set method
    strcpy_s(request->method, sizeof(request->method), "POST");

    // Set URI (root for JSON 1.0)
    strcpy_s(request->canonicalUri, sizeof(request->canonicalUri), "/");

    // No query string
    request->canonicalQueryString[0] = '\0';

    // Build host
    snprintf(request->host, sizeof(request->host), "%s.%s.amazonaws.com",
             creds->service, creds->region);

    // Set content type
    strcpy_s(request->contentType, sizeof(request->contentType),
             "application/x-amz-json-1.0");

    // Set target
    strcpy_s(request->xAmzTarget, sizeof(request->xAmzTarget), target);

    // Set signed headers
    strcpy_s(request->signedHeaders, sizeof(request->signedHeaders),
             "content-type;host;x-amz-date;x-amz-target");

    // Compute body hash
    if (!AwsSigV4_Sha256HexString(bodyJson, request->bodyHash))
        return FALSE;

    // Sign
    return AwsSigV4_Sign(creds, request);
}
