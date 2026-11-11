/*=============================================================================
 * AwsBedrockClient.cpp — Native Win32 AWS Bedrock Client Implementation
 *
 * Full TLS 1.2 connection to AWS Bedrock Runtime using WinSock + Schannel.
 * No external dependencies — pure Win32.
 *
 * Flow:
 *   1. WinSock TCP connect to host:443
 *   2. Schannel TLS handshake (client-side)
 *   3. Send HTTP/1.1 POST with SigV4 Authorization header
 *   4. Read streaming response chunks
 *   5. Invoke callbacks for each chunk
 *===========================================================================*/

#include "AwsBedrockClient.h"
#include <stdio.h>
#include <string.h>

/*=============================================================================
 * INTERNAL: Schannel TLS helpers
 *===========================================================================*/

static BOOL InitSchannelCredentials(AwsBedrockClient* client) {
    SCHANNEL_CRED schannelCred = {0};
    SECURITY_STATUS secStatus;

    schannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    schannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    schannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS |
                           SCH_CRED_MANUAL_CRED_VALIDATION |
                           SCH_CRED_USE_DEFAULT_CREDS;

    secStatus = AcquireCredentialsHandleA(
        nullptr,
        (LPSTR)"UNISP",
        SECPKG_CRED_OUTBOUND,
        nullptr,
        &schannelCred,
        nullptr,
        nullptr,
        &client->schannelCred,
        nullptr);

    if (secStatus != SEC_E_OK) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "AcquireCredentialsHandle failed: 0x%08X", secStatus);
        return FALSE;
    }

    return TRUE;
}

static BOOL PerformTlsHandshake(AwsBedrockClient* client) {
    SECURITY_STATUS secStatus;
    SecBufferDesc inBufferDesc;
    SecBuffer inSecBuffer;
    SecBufferDesc outBufferDesc;
    SecBuffer outSecBuffer;
    DWORD flags;
    DWORD shFlags;
    BOOL doRead = TRUE;
    int attempts = 0;
    const int maxAttempts = 20;

    // Initialize security context attributes
    SecPkgContext_StreamSizes streamSizes;
    ULONG contextAttr = 0;

    // Initial handshake: send ClientHello
    outSecBuffer.BufferType = SECBUFFER_TOKEN;
    outSecBuffer.cbBuffer = 0;
    outSecBuffer.pvBuffer = nullptr;

    outBufferDesc.ulVersion = SECBUFFER_VERSION;
    outBufferDesc.cBuffers = 1;
    outBufferDesc.pBuffers = &outSecBuffer;

    flags = ISC_REQ_SEQUENCE_DETECT |
            ISC_REP_SEQUENCE_DETECT |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY |
            ISC_RET_EXTENDED_ERROR |
            ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM;

    secStatus = InitializeSecurityContextA(
        &client->schannelCred,
        nullptr,
        client->host,
        flags,
        0,
        0,
        nullptr,
        0,
        &client->schannelCtx,
        &outBufferDesc,
        &contextAttr,
        nullptr);

    if (secStatus != SEC_I_CONTINUE_NEEDED) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "InitializeSecurityContext (initial) failed: 0x%08X", secStatus);
        return FALSE;
    }

    // Send ClientHello
    if (outSecBuffer.cbBuffer > 0 && outSecBuffer.pvBuffer) {
        int sent = send(client->socket, (const char*)outSecBuffer.pvBuffer,
                        outSecBuffer.cbBuffer, 0);
        FreeContextBuffer(outSecBuffer.pvBuffer);
        if (sent <= 0) {
            snprintf(client->lastError, sizeof(client->lastError),
                     "send(ClientHello) failed: %d", WSAGetLastError());
            return FALSE;
        }
    }

    // Handshake loop
    while (secStatus != SEC_E_OK && attempts < maxAttempts) {
        attempts++;

        // Read server response
        char handshakeBuf[4096];
        int bytesRead = recv(client->socket, handshakeBuf, sizeof(handshakeBuf), 0);
        if (bytesRead <= 0) {
            snprintf(client->lastError, sizeof(client->lastError),
                     "recv(handshake) failed: %d", WSAGetLastError());
            return FALSE;
        }

        // Process server response
        inSecBuffer.BufferType = SECBUFFER_TOKEN;
        inSecBuffer.cbBuffer = bytesRead;
        inSecBuffer.pvBuffer = handshakeBuf;

        inBufferDesc.ulVersion = SECBUFFER_VERSION;
        inBufferDesc.cBuffers = 1;
        inBufferDesc.pBuffers = &inSecBuffer;

        outSecBuffer.BufferType = SECBUFFER_TOKEN;
        outSecBuffer.cbBuffer = 0;
        outSecBuffer.pvBuffer = nullptr;

        outBufferDesc.ulVersion = SECBUFFER_VERSION;
        outBufferDesc.cBuffers = 1;
        outBufferDesc.pBuffers = &outSecBuffer;

        secStatus = InitializeSecurityContextA(
            &client->schannelCred,
            &client->schannelCtx,
            client->host,
            flags,
            0,
            0,
            &inBufferDesc,
            0,
            nullptr,
            &outBufferDesc,
            &contextAttr,
            nullptr);

        if (secStatus == SEC_E_OK || secStatus == SEC_I_CONTINUE_NEEDED) {
            // Send response to server
            if (outSecBuffer.cbBuffer > 0 && outSecBuffer.pvBuffer) {
                sent = send(client->socket, (const char*)outSecBuffer.pvBuffer,
                            outSecBuffer.cbBuffer, 0);
                FreeContextBuffer(outSecBuffer.pvBuffer);
                if (sent <= 0) {
                    snprintf(client->lastError, sizeof(client->lastError),
                             "send(handshake) failed: %d", WSAGetLastError());
                    return FALSE;
                }
            }
        }

        if (secStatus == SEC_E_INCOMPLETE_MESSAGE) {
            continue;
        }

        if (FAILED(secStatus)) {
            snprintf(client->lastError, sizeof(client->lastError),
                     "InitializeSecurityContext failed: 0x%08X", secStatus);
            return FALSE;
        }
    }

    if (secStatus != SEC_E_OK) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "TLS handshake did not complete: 0x%08X", secStatus);
        return FALSE;
    }

    client->tlsEstablished = TRUE;
    return TRUE;
}

static BOOL SchannelEncrypt(AwsBedrockClient* client, const char* data, DWORD dataLen,
                            char* outBuf, DWORD* outLen) {
    SecPkgContext_StreamSizes streamSizes;
    SECURITY_STATUS secStatus;
    SecBufferDesc bufferDesc;
    SecBuffer buffers[4];
    DWORD remaining = dataLen;
    const BYTE* ptr = (const BYTE*)data;
    DWORD totalOut = 0;

    secStatus = QueryContextAttributesA(
        &client->schannelCtx,
        SECPKG_ATTR_STREAM_SIZES,
        &streamSizes);

    if (secStatus != SEC_E_OK) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "QueryContextAttributes(STREAM_SIZES) failed: 0x%08X", secStatus);
        return FALSE;
    }

    while (remaining > 0) {
        DWORD toSend = (remaining > streamSizes.cbMaximumMessage) ?
                        streamSizes.cbMaximumMessage : remaining;

        BYTE* msgBuf = (BYTE*)malloc(streamSizes.cbHeader + toSend + streamSizes.cbTrailer);
        if (!msgBuf) return FALSE;

        // Copy data into message buffer
        memcpy(msgBuf + streamSizes.cbHeader, ptr, toSend);

        // Set up buffers
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].cbBuffer = streamSizes.cbHeader;
        buffers[0].pvBuffer = msgBuf;

        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].cbBuffer = toSend;
        buffers[1].pvBuffer = msgBuf + streamSizes.cbHeader;

        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].cbBuffer = streamSizes.cbTrailer;
        buffers[2].pvBuffer = msgBuf + streamSizes.cbHeader + toSend;

        buffers[3].BufferType = SECBUFFER_EMPTY;
        buffers[3].cbBuffer = 0;
        buffers[3].pvBuffer = nullptr;

        bufferDesc.ulVersion = SECBUFFER_VERSION;
        bufferDesc.cBuffers = 4;
        bufferDesc.pBuffers = buffers;

        secStatus = EncryptMessage(&client->schannelCtx, 0, &bufferDesc, 0);
        if (secStatus != SEC_E_OK) {
            free(msgBuf);
            snprintf(client->lastError, sizeof(client->lastError),
                     "EncryptMessage failed: 0x%08X", secStatus);
            return FALSE;
        }

        // Total encrypted size
        DWORD encryptedSize = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;

        // Copy to output
        memcpy(outBuf + totalOut, msgBuf, encryptedSize);
        totalOut += encryptedSize;

        ptr += toSend;
        remaining -= toSend;
        free(msgBuf);
    }

    *outLen = totalOut;
    return TRUE;
}

static BOOL SchannelDecrypt(AwsBedrockClient* client, const char* data, DWORD dataLen,
                            char* outBuf, DWORD* outLen) {
    SECURITY_STATUS secStatus;
    SecBufferDesc bufferDesc;
    SecBuffer buffers[4];
    DWORD totalOut = 0;
    DWORD remaining = dataLen;
    const BYTE* ptr = (const BYTE*)data;

    while (remaining > 0) {
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[0].cbBuffer = remaining;
        buffers[0].pvBuffer = (void*)ptr;

        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        bufferDesc.ulVersion = SECBUFFER_VERSION;
        bufferDesc.cBuffers = 4;
        bufferDesc.pBuffers = buffers;

        secStatus = DecryptMessage(&client->schannelCtx, &bufferDesc, 0, nullptr);
        if (secStatus == SEC_E_INCOMPLETE_MESSAGE) {
            break;
        }

        if (secStatus != SEC_E_OK) {
            break;
        }

        // Find the data buffer
        for (int i = 0; i < 4; i++) {
            if (buffers[i].BufferType == SECBUFFER_DATA) {
                memcpy(outBuf + totalOut, buffers[i].pvBuffer, buffers[i].cbBuffer);
                totalOut += buffers[i].cbBuffer;
            }
        }

        // Move to next record
        DWORD consumed = 0;
        for (int i = 0; i < 4; i++) {
            if (buffers[i].BufferType == SECBUFFER_EXTRA) {
                consumed = remaining - buffers[i].cbBuffer;
                break;
            }
        }
        if (consumed == 0) consumed = remaining;

        ptr += consumed;
        remaining -= consumed;
    }

    *outLen = totalOut;
    return TRUE;
}

/*=============================================================================
 * PUBLIC API
 *===========================================================================*/

BOOL AwsBedrockClient_Init(AwsBedrockClient* client) {
    if (!client) return FALSE;

    memset(client, 0, sizeof(AwsBedrockClient));
    client->socket = INVALID_SOCKET;
    client->port = AWS_BEDROCK_DEFAULT_PORT;

    // Initialize WinSock
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "WSAStartup failed: %d", wsaResult);
        return FALSE;
    }

    // Allocate response buffer
    client->responseBuffer = (char*)malloc(AWS_BEDROCK_MAX_RESPONSE);
    if (!client->responseBuffer) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "Failed to allocate response buffer");
        WSACleanup();
        return FALSE;
    }
    client->responseCapacity = AWS_BEDROCK_MAX_RESPONSE;

    client->initialized = TRUE;
    return TRUE;
}

void AwsBedrockClient_SetCallbacks(
    AwsBedrockClient* client,
    AwsBedrockStreamCallback streamCb,
    AwsBedrockToolCallback toolCb,
    void* context)
{
    if (!client) return;
    client->streamCallback = streamCb;
    client->toolCallback = toolCb;
    client->callbackContext = context;
}

BOOL AwsBedrockClient_Connect(AwsBedrockClient* client, const char* host, int port) {
    if (!client || !host) return FALSE;

    strcpy_s(client->host, sizeof(client->host), host);
    client->port = (port > 0) ? port : AWS_BEDROCK_DEFAULT_PORT;

    // Resolve hostname
    struct addrinfo hints = {0}, *addrInfo = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", client->port);

    int result = getaddrinfo(host, portStr, &hints, &addrInfo);
    if (result != 0) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "getaddrinfo failed: %d", result);
        return FALSE;
    }

    // Create socket
    client->socket = socket(addrInfo->ai_family, addrInfo->ai_socktype, addrInfo->ai_protocol);
    if (client->socket == INVALID_SOCKET) {
        client->lastWinSockError = WSAGetLastError();
        snprintf(client->lastError, sizeof(client->lastError),
                 "socket() failed: %d", client->lastWinSockError);
        freeaddrinfo(addrInfo);
        return FALSE;
    }

    // Set timeout
    DWORD timeout = AWS_BEDROCK_TIMEOUT_MS;
    setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    // Connect
    result = connect(client->socket, addrInfo->ai_addr, (int)addrInfo->ai_addrlen);
    freeaddrinfo(addrInfo);

    if (result == SOCKET_ERROR) {
        client->lastWinSockError = WSAGetLastError();
        snprintf(client->lastError, sizeof(client->lastError),
                 "connect() failed: %d", client->lastWinSockError);
        closesocket(client->socket);
        client->socket = INVALID_SOCKET;
        return FALSE;
    }

    client->connected = TRUE;

    // Initialize Schannel and perform TLS handshake
    if (!InitSchannelCredentials(client)) {
        closesocket(client->socket);
        client->socket = INVALID_SOCKET;
        client->connected = FALSE;
        return FALSE;
    }

    if (!PerformTlsHandshake(client)) {
        FreeCredentialsHandle(&client->schannelCred);
        closesocket(client->socket);
        client->socket = INVALID_SOCKET;
        client->connected = FALSE;
        return FALSE;
    }

    return TRUE;
}

BOOL AwsBedrockClient_SendRequest(
    AwsBedrockClient* client,
    const char* authorization,
    const char* xAmzDate,
    const char* xAmzTarget,
    const char* contentType,
    const char* body,
    size_t bodyLen)
{
    if (!client || !client->connected || !client->tlsEstablished) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "Not connected");
        return FALSE;
    }

    // Build HTTP request
    char httpRequest[16384];
    int reqLen = snprintf(httpRequest, sizeof(httpRequest),
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: %s\r\n"
        "X-Amz-Date: %s\r\n"
        "X-Amz-Target: %s\r\n"
        "Authorization: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "%s",
        client->host,
        contentType,
        xAmzDate,
        xAmzTarget,
        authorization,
        bodyLen,
        body);

    if (reqLen <= 0 || reqLen >= (int)sizeof(httpRequest)) {
        snprintf(client->lastError, sizeof(client->lastError),
                 "HTTP request too large");
        return FALSE;
    }

    // Encrypt via Schannel
    char encryptedBuf[65536];
    DWORD encryptedLen = 0;

    if (!SchannelEncrypt(client, httpRequest, (DWORD)reqLen, encryptedBuf, &encryptedLen)) {
        return FALSE;
    }

    // Send encrypted data
    int totalSent = 0;
    while (totalSent < (int)encryptedLen) {
        int sent = send(client->socket, encryptedBuf + totalSent,
                        encryptedLen - totalSent, 0);
        if (sent <= 0) {
            client->lastWinSockError = WSAGetLastError();
            snprintf(client->lastError, sizeof(client->lastError),
                     "send() failed: %d", client->lastWinSockError);
            return FALSE;
        }
        totalSent += sent;
    }

    // Read response
    client->responseLength = 0;
    char recvBuf[65536];
    char decryptedBuf[65536];
    BOOL headersComplete = FALSE;
    size_t contentLength = 0;
    size_t bodyRead = 0;
    BOOL chunked = FALSE;

    while (TRUE) {
        int bytesRead = recv(client->socket, recvBuf, sizeof(recvBuf), 0);
        if (bytesRead <= 0) {
            break;
        }

        // Decrypt
        DWORD decryptedLen = 0;
        if (!SchannelDecrypt(client, recvBuf, (DWORD)bytesRead, decryptedBuf, &decryptedLen)) {
            break;
        }

        if (decryptedLen == 0) continue;

        // Parse HTTP response
        if (!headersComplete) {
            // Look for end of headers
            char* headerEnd = strstr(decryptedBuf, "\r\n\r\n");
            if (headerEnd) {
                headersComplete = TRUE;
                size_t headerLen = (headerEnd + 4) - decryptedBuf;

                // Parse Content-Length
                char* cl = strstr(decryptedBuf, "Content-Length:");
                if (cl) {
                    contentLength = atoi(cl + 15);
                }

                // Check for chunked transfer
                if (strstr(decryptedBuf, "Transfer-Encoding: chunked")) {
                    chunked = TRUE;
                }

                // Copy body data
                size_t bodyData = decryptedLen - headerLen;
                if (bodyData > 0) {
                    size_t toCopy = (client->responseLength + bodyData < client->responseCapacity)
                                    ? bodyData : (client->responseCapacity - client->responseLength);
                    memcpy(client->responseBuffer + client->responseLength,
                           decryptedBuf + headerLen, toCopy);
                    client->responseLength += toCopy;
                    bodyRead += toCopy;

                    // Stream callback
                    if (client->streamCallback) {
                        client->streamCallback(client->callbackContext,
                                               client->responseBuffer + client->responseLength - toCopy,
                                               toCopy, FALSE);
                    }
                }
            } else {
                // Buffer partial headers
                size_t toCopy = (client->responseLength + decryptedLen < client->responseCapacity)
                                ? decryptedLen : (client->responseCapacity - client->responseLength);
                memcpy(client->responseBuffer + client->responseLength, decryptedBuf, toCopy);
                client->responseLength += toCopy;
            }
        } else {
            // Body data
            size_t toCopy = (client->responseLength + decryptedLen < client->responseCapacity)
                            ? decryptedLen : (client->responseCapacity - client->responseLength);
            memcpy(client->responseBuffer + client->responseLength, decryptedBuf, toCopy);
            client->responseLength += toCopy;
            bodyRead += toCopy;

            // Stream callback
            if (client->streamCallback) {
                client->streamCallback(client->callbackContext, decryptedBuf, toCopy, FALSE);
            }
        }

        // Check if we have all the data
        if (!chunked && contentLength > 0 && bodyRead >= contentLength) {
            break;
        }
    }

    // Null-terminate
    if (client->responseLength < client->responseCapacity) {
        client->responseBuffer[client->responseLength] = '\0';
    }

    // Final stream callback
    if (client->streamCallback) {
        client->streamCallback(client->callbackContext, nullptr, 0, TRUE);
    }

    return client->responseLength > 0;
}

const char* AwsBedrockClient_GetResponse(AwsBedrockClient* client) {
    if (!client || !client->responseBuffer) return nullptr;
    return client->responseBuffer;
}

void AwsBedrockClient_Disconnect(AwsBedrockClient* client) {
    if (!client) return;

    if (client->tlsEstablished) {
        // Send TLS close_notify
        SecBufferDesc bufferDesc;
        SecBuffer buffers[1];
        DWORD shFlags = SCHANNEL_SHUTDOWN;

        buffers[0].BufferType = SECBUFFER_TOKEN;
        buffers[0].cbBuffer = 0;
        buffers[0].pvBuffer = nullptr;

        bufferDesc.ulVersion = SECBUFFER_VERSION;
        bufferDesc.cBuffers = 1;
        bufferDesc.pBuffers = buffers;

        ApplyControlToken(&client->schannelCtx, &bufferDesc);

        // Encrypt and send shutdown
        buffers[0].BufferType = SECBUFFER_TOKEN;
        buffers[0].cbBuffer = 0;
        buffers[0].pvBuffer = nullptr;

        ULONG contextAttr = 0;
        InitializeSecurityContextA(
            &client->schannelCred,
            &client->schannelCtx,
            nullptr,
            ISC_REQ_ALLOCATE_MEMORY,
            0,
            0,
            nullptr,
            0,
            &client->schannelCtx,
            &bufferDesc,
            &contextAttr,
            nullptr);

        if (buffers[0].cbBuffer > 0 && buffers[0].pvBuffer) {
            send(client->socket, (const char*)buffers[0].pvBuffer,
                 buffers[0].cbBuffer, 0);
            FreeContextBuffer(buffers[0].pvBuffer);
        }

        DeleteSecurityContext(&client->schannelCtx);
        FreeCredentialsHandle(&client->schannelCred);
        client->tlsEstablished = FALSE;
    }

    if (client->socket != INVALID_SOCKET) {
        closesocket(client->socket);
        client->socket = INVALID_SOCKET;
    }

    client->connected = FALSE;
}

const char* AwsBedrockClient_GetLastError(AwsBedrockClient* client) {
    if (!client) return "Null client";
    return client->lastError;
}
