// ============================================================================
// RawrXDHost.exe — Named Pipe Control Plane Server
// B017: Minimal IPC host, zero inference duplication
// ============================================================================
// Build: cl /O2 /MT /W4 /EHsc RawrXDHost.cpp rawrxd_host.cpp ...
// ============================================================================
#include "rawrxd_host.hpp"
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

// ============================================================================
// Protocol constants
// ============================================================================
constexpr char DEFAULT_PIPE_NAME[] = "\\\\.\\pipe\\RawrXD";
constexpr DWORD PIPE_BUFFER_SIZE = 65536;
constexpr DWORD PIPE_TIMEOUT_MS = 5000;

// ============================================================================
// Packet I/O helpers
// ============================================================================
static bool ReadPacketHeader(HANDLE hPipe, rawrxd_packet_header_t& header)
{
    DWORD bytesRead = 0;
    if (!ReadFile(hPipe, &header, sizeof(header), &bytesRead, nullptr)) {
        return false;
    }
    if (bytesRead != sizeof(header)) {
        return false;
    }
    if (header.magic != RAWRXD_PACKET_MAGIC) {
        return false;
    }
    if (header.version != RAWRXD_PACKET_VERSION) {
        return false;
    }
    return true;
}

static bool ReadPacketPayload(HANDLE hPipe, std::vector<uint8_t>& payload, uint32_t payload_size)
{
    payload.resize(payload_size);
    if (payload_size == 0) {
        return true;
    }
    DWORD bytesRead = 0;
    if (!ReadFile(hPipe, payload.data(), payload_size, &bytesRead, nullptr)) {
        return false;
    }
    return bytesRead == payload_size;
}

static bool WritePacket(HANDLE hPipe, uint32_t type, uint32_t flags, uint64_t request_id,
                        const void* payload, uint32_t payload_size)
{
    rawrxd_packet_header_t header{};
    header.magic = RAWRXD_PACKET_MAGIC;
    header.version = RAWRXD_PACKET_VERSION;
    header.type = type;
    header.flags = flags;
    header.payload_size = payload_size;
    header.request_id = request_id;

    DWORD written = 0;
    if (!WriteFile(hPipe, &header, sizeof(header), &written, nullptr)) {
        return false;
    }
    if (written != sizeof(header)) {
        return false;
    }

    if (payload_size > 0 && payload) {
        written = 0;
        if (!WriteFile(hPipe, payload, payload_size, &written, nullptr)) {
            return false;
        }
        if (written != payload_size) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// Request dispatch
// ============================================================================
static void DispatchRequest(rawrxd_host_t host, HANDLE hPipe,
                            const rawrxd_packet_header_t& req_header,
                            const std::vector<uint8_t>& req_payload)
{
    switch (req_header.type) {
        case RAWRXD_REQ_LOAD_MODEL: {
            // Payload: null-terminated path string
            if (req_payload.empty() || req_payload.back() != '\0') {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            nullptr, 0);
                return;
            }
            const char* path = reinterpret_cast<const char*>(req_payload.data());
            uint32_t model_id = 0;
            int rc = rawrxd_host_load_model(host, path, &model_id);
            if (rc == RAWRXD_OK) {
                WritePacket(hPipe, RAWRXD_RESP_OK, 0, req_header.request_id,
                            &model_id, sizeof(model_id));
            } else {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            &rc, sizeof(rc));
            }
            break;
        }

        case RAWRXD_REQ_GENERATE: {
            // Payload: model_id (4 bytes) + token_count (4 bytes) + tokens[]
            if (req_payload.size() < 8) {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            nullptr, 0);
                return;
            }
            uint32_t model_id = *reinterpret_cast<const uint32_t*>(req_payload.data());
            uint32_t token_count = *reinterpret_cast<const uint32_t*>(req_payload.data() + 4);
            const uint32_t* tokens = reinterpret_cast<const uint32_t*>(req_payload.data() + 8);

            // Allocate logits buffer (vocab size heuristic)
            constexpr size_t MAX_VOCAB = 256000;
            std::vector<float> logits(MAX_VOCAB);
            size_t logits_count = MAX_VOCAB;

            int rc = rawrxd_host_generate(host, model_id, tokens, token_count, 1,
                                          logits.data(), &logits_count);
            if (rc == RAWRXD_OK) {
                WritePacket(hPipe, RAWRXD_RESP_OK, 0, req_header.request_id,
                            logits.data(), static_cast<uint32_t>(logits_count * sizeof(float)));
            } else {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            &rc, sizeof(rc));
            }
            break;
        }

        case RAWRXD_REQ_GENERATE_BATCH: {
            // Payload: model_id (4) + token_count (4) + tokens[]
            if (req_payload.size() < 8) {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            nullptr, 0);
                return;
            }
            uint32_t model_id = *reinterpret_cast<const uint32_t*>(req_payload.data());
            uint32_t token_count = *reinterpret_cast<const uint32_t*>(req_payload.data() + 4);
            const uint32_t* tokens = reinterpret_cast<const uint32_t*>(req_payload.data() + 8);

            constexpr size_t MAX_VOCAB = 256000;
            std::vector<float> logits(MAX_VOCAB);
            size_t logits_count = MAX_VOCAB;

            int rc = rawrxd_host_generate_batch(host, model_id, tokens, token_count, 1,
                                                  logits.data(), &logits_count);
            if (rc == RAWRXD_OK) {
                WritePacket(hPipe, RAWRXD_RESP_OK, RAWRXD_FLAG_BATCHED, req_header.request_id,
                            logits.data(), static_cast<uint32_t>(logits_count * sizeof(float)));
            } else {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            &rc, sizeof(rc));
            }
            break;
        }

        case RAWRXD_REQ_RESET: {
            if (req_payload.size() < 4) {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            nullptr, 0);
                return;
            }
            uint32_t model_id = *reinterpret_cast<const uint32_t*>(req_payload.data());
            int rc = rawrxd_host_reset(host, model_id);
            WritePacket(hPipe, rc == RAWRXD_OK ? RAWRXD_RESP_OK : RAWRXD_RESP_ERROR,
                        0, req_header.request_id, &rc, sizeof(rc));
            break;
        }

        case RAWRXD_REQ_STATS: {
            if (req_payload.size() < 4) {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            nullptr, 0);
                return;
            }
            uint32_t model_id = *reinterpret_cast<const uint32_t*>(req_payload.data());
            rawrxd_host_stats_t stats{};
            int rc = rawrxd_host_get_stats(host, model_id, &stats);
            if (rc == RAWRXD_OK) {
                WritePacket(hPipe, RAWRXD_RESP_STATS, 0, req_header.request_id,
                            &stats, sizeof(stats));
            } else {
                WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                            &rc, sizeof(rc));
            }
            break;
        }

        case RAWRXD_REQ_SHUTDOWN: {
            WritePacket(hPipe, RAWRXD_RESP_OK, 0, req_header.request_id, nullptr, 0);
            break;
        }

        default: {
            int rc = RAWRXD_ERR_NOT_IMPLEMENTED;
            WritePacket(hPipe, RAWRXD_RESP_ERROR, 0, req_header.request_id,
                        &rc, sizeof(rc));
            break;
        }
    }
}

// ============================================================================
// Server loop
// ============================================================================
static void RunServer(rawrxd_host_t host, const char* pipe_name)
{
    std::printf("[RawrXDHost] Starting named pipe server: %s\n", pipe_name);
    std::printf("[RawrXDHost] Certified engine: B009 ForwardBatch + B015 Residency\n");
    std::printf("[RawrXDHost] No inference duplication. No GEMM in host. No tokenizer in host.\n\n");

    while (true) {
        HANDLE hPipe = CreateNamedPipeA(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            PIPE_TIMEOUT_MS,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::fprintf(stderr, "[RawrXDHost] Failed to create named pipe: %lu\n", GetLastError());
            return;
        }

        std::printf("[RawrXDHost] Waiting for client connection...\n");
        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            std::fprintf(stderr, "[RawrXDHost] ConnectNamedPipe failed: %lu\n", GetLastError());
            CloseHandle(hPipe);
            continue;
        }

        std::printf("[RawrXDHost] Client connected.\n");

        // Process requests from this client
        while (true) {
            rawrxd_packet_header_t req_header{};
            if (!ReadPacketHeader(hPipe, req_header)) {
                break; // Client disconnected or error
            }

            std::vector<uint8_t> req_payload;
            if (!ReadPacketPayload(hPipe, req_payload, req_header.payload_size)) {
                break;
            }

            DispatchRequest(host, hPipe, req_header, req_payload);

            if (req_header.type == RAWRXD_REQ_SHUTDOWN) {
                std::printf("[RawrXDHost] Shutdown requested.\n");
                FlushFileBuffers(hPipe);
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
                return;
            }
        }

        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        std::printf("[RawrXDHost] Client disconnected.\n");
    }
}

// ============================================================================
// Entry point
// ============================================================================
int main(int argc, char** argv)
{
    std::printf("╔══════════════════════════════════════════════════════════════╗\n");
    std::printf("║  RawrXD Native Host Control Plane                            ║\n");
    std::printf("║  B017: IPC + C ABI + lifecycle + isolation                   ║\n");
    std::printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Parse command line
    const char* pipe_name = DEFAULT_PIPE_NAME;
    const char* model_path = nullptr;
    uint64_t residency_bytes = 512ULL * 1024 * 1024; // 512 MB default

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--pipe") == 0 && i + 1 < argc) {
            pipe_name = argv[++i];
        } else if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            model_path = argv[++i];
        } else if (std::strcmp(argv[i], "--residency") == 0 && i + 1 < argc) {
            residency_bytes = std::strtoull(argv[++i], nullptr, 10);
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            std::printf("Usage: RawrXDHost.exe [options]\n");
            std::printf("  --pipe NAME       Named pipe name (default: \\\\.\\pipe\\RawrXD)\n");
            std::printf("  --model PATH      Pre-load model at startup\n");
            std::printf("  --residency BYTES Weight residency pool size (default: 536870912)\n");
            std::printf("  --help            Show this help\n");
            return 0;
        }
    }

    // Create host
    rawrxd_host_config_t cfg{};
    cfg.version = 0x00010000;
    cfg.flags = 0;
    cfg.weight_residency_max_bytes = residency_bytes;
    cfg.gpu_device_index = 0;
    cfg.pipe_name = pipe_name;

    rawrxd_host_t host = rawrxd_host_create(&cfg);
    if (!host) {
        std::fprintf(stderr, "[RawrXDHost] Failed to create host instance\n");
        return 1;
    }

    // Pre-load model if specified
    if (model_path) {
        std::printf("[RawrXDHost] Pre-loading model: %s\n", model_path);
        uint32_t model_id = 0;
        int rc = rawrxd_host_load_model(host, model_path, &model_id);
        if (rc != RAWRXD_OK) {
            std::fprintf(stderr, "[RawrXDHost] Failed to load model: %s (%d)\n",
                         rawrxd_host_strerror(rc), rc);
            rawrxd_host_destroy(host);
            return 1;
        }
        std::printf("[RawrXDHost] Model loaded with ID: %u\n", model_id);
    }

    // Run server
    RunServer(host, pipe_name);

    // Cleanup
    rawrxd_host_destroy(host);
    std::printf("[RawrXDHost] Shutdown complete.\n");
    return 0;
}
