#include "rawrxd_pipe_server.hpp"
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <windows.h>
#include <atomic>

// ============================================================================
// RawrXD Named Pipe Server — Implementation
// B017.1: Synchronous baseline, connection lifecycle, zero injection
// ============================================================================

static constexpr char DEFAULT_PIPE_NAME[] = "\\\\.\\pipe\\RawrXD";
static constexpr DWORD PIPE_BUFFER_SIZE = 65536;
static std::atomic<bool> g_shutdown_requested{false};

// ============================================================================
// Helper: Read exact number of bytes from pipe
// ============================================================================
static bool PipeReadExact(HANDLE hPipe, void* buf, DWORD len)
{
    DWORD totalRead = 0;
    while (totalRead < len) {
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hPipe, static_cast<uint8_t*>(buf) + totalRead,
                           len - totalRead, &bytesRead, nullptr);
        if (!ok || bytesRead == 0) {
            return false;
        }
        totalRead += bytesRead;
    }
    return true;
}

// ============================================================================
// Helper: Write exact number of bytes to pipe
// ============================================================================
static bool PipeWriteExact(HANDLE hPipe, const void* buf, DWORD len)
{
    DWORD totalWritten = 0;
    while (totalWritten < len) {
        DWORD bytesWritten = 0;
        BOOL ok = WriteFile(hPipe, static_cast<const uint8_t*>(buf) + totalWritten,
                            len - totalWritten, &bytesWritten, nullptr);
        if (!ok || bytesWritten == 0) {
            return false;
        }
        totalWritten += bytesWritten;
    }
    return true;
}

// ============================================================================
// Send response packet
// ============================================================================
static bool SendResponse(HANDLE hPipe, uint32_t type, uint64_t request_id,
                         const void* payload, uint32_t payload_size)
{
    RawrXDPacketHeader header{};
    header.magic = RAWRXD_PACKET_MAGIC;
    header.version = RAWRXD_PACKET_VERSION;
    header.type = type;
    header.flags = 0;
    header.payload_size = payload_size;
    header.request_id = request_id;

    if (!PipeWriteExact(hPipe, &header, sizeof(header))) {
        return false;
    }
    if (payload_size > 0 && payload) {
        if (!PipeWriteExact(hPipe, payload, payload_size)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Send error response
// ============================================================================
static bool SendError(HANDLE hPipe, uint64_t request_id, int error_code,
                      const char* message)
{
    RawrXDRespError err{};
    err.error_code = error_code;
    std::strncpy(err.message, message ? message : "", sizeof(err.message) - 1);
    err.message[sizeof(err.message) - 1] = '\0';
    return SendResponse(hPipe, RAWRXD_RESP_ERROR, request_id, &err, sizeof(err));
}

// ============================================================================
// Handle a single client connection
// ============================================================================
static void HandleClient(HANDLE hPipe)
{
    // Create host instance for this connection
    rawrxd_host_config_t cfg{};
    cfg.version = 0x00010000;
    cfg.weight_residency_max_bytes = 512ULL * 1024 * 1024;
    cfg.gpu_device_index = 0;
    cfg.pipe_name = nullptr;

    rawrxd_host_t host = rawrxd_host_create(&cfg);
    if (!host) {
        std::fprintf(stderr, "[PipeServer] Failed to create host instance\n");
        return;
    }

    std::printf("[PipeServer] Client connected\n");

    while (!g_shutdown_requested.load()) {
        // Read header
        RawrXDPacketHeader header{};
        if (!PipeReadExact(hPipe, &header, sizeof(header))) {
            break; // Client disconnected or error
        }

        // Validate header
        if (header.magic != RAWRXD_PACKET_MAGIC) {
            std::fprintf(stderr, "[PipeServer] Invalid magic: 0x%08X\n", header.magic);
            break;
        }
        if (header.version != RAWRXD_PACKET_VERSION) {
            SendError(hPipe, header.request_id, RAWRXD_ERR_PROTOCOL,
                      "Unsupported protocol version");
            continue;
        }

        // Read payload if present
        std::vector<uint8_t> payload;
        if (header.payload_size > 0) {
            payload.resize(header.payload_size);
            if (!PipeReadExact(hPipe, payload.data(), header.payload_size)) {
                break;
            }
        }

        // Dispatch request
        switch (header.type) {
            case RAWRXD_REQ_LOAD_MODEL: {
                if (header.payload_size < sizeof(RawrXDReqLoadModel)) {
                    SendError(hPipe, header.request_id, RAWRXD_ERR_PROTOCOL,
                              "LOAD_MODEL payload too small");
                    continue;
                }
                auto* req = reinterpret_cast<RawrXDReqLoadModel*>(payload.data());
                uint32_t model_id = 0;
                int rc = rawrxd_host_load_model(host, req->path, &model_id);
                if (rc != RAWRXD_OK) {
                    SendError(hPipe, header.request_id, rc,
                              rawrxd_host_strerror(rc));
                } else {
                    // Echo model_id as payload (simple OK with data)
                    SendResponse(hPipe, RAWRXD_RESP_OK, header.request_id,
                                 &model_id, sizeof(model_id));
                }
                break;
            }

            case RAWRXD_REQ_GENERATE:
            case RAWRXD_REQ_GENERATE_BATCH: {
                if (header.payload_size < sizeof(RawrXDReqGenerate)) {
                    SendError(hPipe, header.request_id, RAWRXD_ERR_PROTOCOL,
                              "GENERATE payload too small");
                    continue;
                }
                auto* req = reinterpret_cast<RawrXDReqGenerate*>(payload.data());
                if (header.payload_size < sizeof(RawrXDReqGenerate) +
                    req->token_count * sizeof(uint32_t)) {
                    SendError(hPipe, header.request_id, RAWRXD_ERR_PROTOCOL,
                              "GENERATE token data missing");
                    continue;
                }

                const uint32_t* tokens = reinterpret_cast<const uint32_t*>(
                    payload.data() + sizeof(RawrXDReqGenerate));

                // Allocate output buffer (vocab_size max)
                constexpr size_t MAX_LOGITS = 128256;
                std::vector<float> logits(MAX_LOGITS);
                size_t logits_count = MAX_LOGITS;

                int rc;
                if (header.type == RAWRXD_REQ_GENERATE) {
                    rc = rawrxd_host_generate(host, req->model_id, tokens,
                                               req->token_count, req->max_new_tokens,
                                               logits.data(), &logits_count);
                } else {
                    rc = rawrxd_host_generate_batch(host, req->model_id, tokens,
                                                     req->token_count, req->max_new_tokens,
                                                     logits.data(), &logits_count);
                }

                if (rc != RAWRXD_OK) {
                    SendError(hPipe, header.request_id, rc,
                              rawrxd_host_strerror(rc));
                } else {
                    // Stream back: first chunk is the logits count, then logits data
                    // For simplicity, send as single response
                    struct GenerateResponse {
                        uint32_t logits_count;
                        uint32_t reserved;
                    } resp{};
                    resp.logits_count = static_cast<uint32_t>(logits_count);

                    // Send header + count
                    if (!SendResponse(hPipe, RAWRXD_RESP_OK, header.request_id,
                                     &resp, sizeof(resp))) {
                        break;
                    }
                    // Send logits data
                    if (!PipeWriteExact(hPipe, logits.data(),
                                        static_cast<DWORD>(logits_count * sizeof(float)))) {
                        break;
                    }
                }
                break;
            }

            case RAWRXD_REQ_RESET: {
                if (header.payload_size < sizeof(RawrXDReqReset)) {
                    SendError(hPipe, header.request_id, RAWRXD_ERR_PROTOCOL,
                              "RESET payload too small");
                    continue;
                }
                auto* req = reinterpret_cast<RawrXDReqReset*>(payload.data());
                int rc = rawrxd_host_reset(host, req->model_id);
                if (rc != RAWRXD_OK) {
                    SendError(hPipe, header.request_id, rc,
                              rawrxd_host_strerror(rc));
                } else {
                    SendResponse(hPipe, RAWRXD_RESP_OK, header.request_id, nullptr, 0);
                }
                break;
            }

            case RAWRXD_REQ_STATS: {
                if (header.payload_size < sizeof(RawrXDReqStats)) {
                    SendError(hPipe, header.request_id, RAWRXD_ERR_PROTOCOL,
                              "STATS payload too small");
                    continue;
                }
                rawrxd_host_stats_t stats{};
                int rc = rawrxd_host_get_stats(host, 0, &stats); // model_id ignored for now
                if (rc != RAWRXD_OK) {
                    SendError(hPipe, header.request_id, rc,
                              rawrxd_host_strerror(rc));
                } else {
                    RawrXDRespStats resp{};
                    resp.stats = stats;
                    SendResponse(hPipe, RAWRXD_RESP_STATS, header.request_id,
                                 &resp, sizeof(resp));
                }
                break;
            }

            case RAWRXD_REQ_SHUTDOWN: {
                SendResponse(hPipe, RAWRXD_RESP_OK, header.request_id, nullptr, 0);
                g_shutdown_requested.store(true);
                break;
            }

            default: {
                SendError(hPipe, header.request_id, RAWRXD_ERR_NOT_IMPLEMENTED,
                          "Unknown request type");
                break;
            }
        }
    }

    rawrxd_host_destroy(host);
    std::printf("[PipeServer] Client disconnected\n");
}

// ============================================================================
// Public API
// ============================================================================

int rawrxd_pipe_server_run(const char* pipe_name)
{
    const char* name = pipe_name ? pipe_name : DEFAULT_PIPE_NAME;
    g_shutdown_requested.store(false);

    std::printf("[PipeServer] Starting on '%s'\n", name);

    while (!g_shutdown_requested.load()) {
        HANDLE hPipe = CreateNamedPipeA(
            name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::fprintf(stderr, "[PipeServer] CreateNamedPipe failed: %lu\n",
                         GetLastError());
            return RAWRXD_ERR_PIPE_IO;
        }

        std::printf("[PipeServer] Waiting for connection...\n");
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::fprintf(stderr, "[PipeServer] ConnectNamedPipe failed: %lu\n",
                         GetLastError());
            CloseHandle(hPipe);
            continue;
        }

        // Handle one client synchronously (B017 baseline)
        // Future: spawn thread or use overlapped I/O for concurrency
        HandleClient(hPipe);

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    std::printf("[PipeServer] Shut down cleanly\n");
    return RAWRXD_OK;
}

void rawrxd_pipe_server_shutdown(void)
{
    g_shutdown_requested.store(true);
}
