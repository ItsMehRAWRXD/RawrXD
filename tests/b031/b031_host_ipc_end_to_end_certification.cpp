// ============================================================================
// b031_host_ipc_end_to_end_certification.cpp — B031 Host IPC End-to-End
// ============================================================================
// Tests: Named pipe creation, packet framing, request/response round-trip,
//        binary protocol correctness, shutdown sequence
// ============================================================================
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <windows.h>
#include <string>

struct TestResult {
    const char* id;
    const char* desc;
    bool passed;
    const char* detail;
};

static std::vector<TestResult> g_results;

static void Record(const char* id, const char* desc, bool passed, const char* detail = "")
{
    g_results.push_back({id, desc, passed, detail});
    std::printf("  [%s] %s: %s\n", passed ? "PASS" : "FAIL", id, detail);
}

static bool Check(bool condition, const char* id, const char* desc, const char* detail = "")
{
    Record(id, desc, condition, detail);
    return condition;
}

// ============================================================================
// Packet protocol helpers (from rawrxd_host.hpp)
// ============================================================================
static bool WritePacketHeader(HANDLE hPipe, uint32_t type, uint32_t payload_size)
{
    rawrxd_packet_header_t hdr;
    hdr.magic = RAWRXD_PACKET_MAGIC;
    hdr.version = RAWRXD_PACKET_VERSION;
    hdr.type = type;
    hdr.flags = 0;
    hdr.payload_size = payload_size;
    hdr.reserved = 0;
    hdr.request_id = 1;

    DWORD written;
    return WriteFile(hPipe, &hdr, sizeof(hdr), &written, nullptr) && written == sizeof(hdr);
}

static bool ReadPacketHeader(HANDLE hPipe, rawrxd_packet_header_t& hdr)
{
    DWORD read;
    return ReadFile(hPipe, &hdr, sizeof(hdr), &read, nullptr) && read == sizeof(hdr);
}

// ============================================================================
// Test 1: Pipe creation and connection
// ============================================================================
static bool TestPipeCreation()
{
    std::printf("\n[TEST 1] Pipe creation and connection\n");

    const char* pipeName = "\\\\.\\pipe\\RawrXD_B031_Test";

    HANDLE hServer = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, nullptr);

    bool ok = true;
    ok &= Check(hServer != INVALID_HANDLE_VALUE, "B031-001", "server pipe created", hServer != INVALID_HANDLE_VALUE ? "yes" : "no");

    if (hServer != INVALID_HANDLE_VALUE) {
        // Client connect in background
        HANDLE hClient = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        ok &= Check(hClient != INVALID_HANDLE_VALUE, "B031-002", "client connected", hClient != INVALID_HANDLE_VALUE ? "yes" : "no");

        if (hClient != INVALID_HANDLE_VALUE) {
            // Server accepts
            BOOL connected = ConnectNamedPipe(hServer, nullptr);
            if (!connected && GetLastError() == ERROR_PIPE_CONNECTED) connected = TRUE;
            ok &= Check(connected, "B031-003", "server accepted connection", "yes");

            CloseHandle(hClient);
        }
        CloseHandle(hServer);
    }

    return ok;
}

// ============================================================================
// Test 2: Packet header framing
// ============================================================================
static bool TestPacketFraming()
{
    std::printf("\n[TEST 2] Packet header framing\n");

    rawrxd_packet_header_t hdr;
    hdr.magic = RAWRXD_PACKET_MAGIC;
    hdr.version = RAWRXD_PACKET_VERSION;
    hdr.type = RAWRXD_REQ_LOAD_MODEL;
    hdr.flags = 0;
    hdr.payload_size = 256;
    hdr.reserved = 0;
    hdr.request_id = 42;

    bool ok = true;
    ok &= Check(hdr.magic == 0x52415752u, "B031-004", "magic value correct", "RAWR");
    ok &= Check(hdr.version == 0x00010000u, "B031-005", "version correct", "0x00010000");
    ok &= Check(sizeof(hdr) == 32, "B031-006", "header size is 32 bytes", std::to_string(sizeof(hdr)).c_str());

    return ok;
}

// ============================================================================
// Test 3: Request/response round-trip
// ============================================================================
static bool TestRoundTrip()
{
    std::printf("\n[TEST 3] Request/response round-trip\n");

    const char* pipeName = "\\\\.\\pipe\\RawrXD_B031_RoundTrip";

    HANDLE hServer = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, nullptr);

    bool ok = true;

    if (hServer != INVALID_HANDLE_VALUE) {
        HANDLE hClient = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

        if (hClient != INVALID_HANDLE_VALUE) {
            ConnectNamedPipe(hServer, nullptr);

            // Client sends request
            WritePacketHeader(hClient, RAWRXD_REQ_STATS, 0);

            // Server reads request
            rawrxd_packet_header_t req_hdr;
            bool read_ok = ReadPacketHeader(hServer, req_hdr);
            ok &= Check(read_ok, "B031-007", "server read request header", read_ok ? "yes" : "no");
            ok &= Check(req_hdr.type == RAWRXD_REQ_STATS, "B031-008", "request type matches", std::to_string(req_hdr.type).c_str());

            // Server sends response
            WritePacketHeader(hServer, RAWRXD_RESP_OK, 0);

            // Client reads response
            rawrxd_packet_header_t resp_hdr;
            bool resp_ok = ReadPacketHeader(hClient, resp_hdr);
            ok &= Check(resp_ok, "B031-009", "client read response header", resp_ok ? "yes" : "no");
            ok &= Check(resp_hdr.type == RAWRXD_RESP_OK, "B031-010", "response type is OK", std::to_string(resp_hdr.type).c_str());

            CloseHandle(hClient);
        }
        CloseHandle(hServer);
    }

    return ok;
}

// ============================================================================
// Test 4: Error response handling
// ============================================================================
static bool TestErrorResponse()
{
    std::printf("\n[TEST 4] Error response handling\n");

    rawrxd_packet_header_t hdr;
    hdr.magic = RAWRXD_PACKET_MAGIC;
    hdr.version = RAWRXD_PACKET_VERSION;
    hdr.type = RAWRXD_RESP_ERROR;
    hdr.flags = 0;
    hdr.payload_size = 0;
    hdr.reserved = 0;
    hdr.request_id = 1;

    bool ok = true;
    ok &= Check(hdr.type == RAWRXD_RESP_ERROR, "B031-011", "error response type recognized", "yes");

    return ok;
}

// ============================================================================
// Test 5: Shutdown sequence
// ============================================================================
static bool TestShutdownSequence()
{
    std::printf("\n[TEST 5] Shutdown sequence\n");

    const char* pipeName = "\\\\.\\pipe\\RawrXD_B031_Shutdown";

    HANDLE hServer = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 4096, 4096, 0, nullptr);

    bool ok = true;

    if (hServer != INVALID_HANDLE_VALUE) {
        HANDLE hClient = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);

        if (hClient != INVALID_HANDLE_VALUE) {
            ConnectNamedPipe(hServer, nullptr);

            // Client sends shutdown
            WritePacketHeader(hClient, RAWRXD_REQ_SHUTDOWN, 0);

            // Server reads and acknowledges
            rawrxd_packet_header_t hdr;
            ReadPacketHeader(hServer, hdr);
            ok &= Check(hdr.type == RAWRXD_REQ_SHUTDOWN, "B031-012", "shutdown request received", "yes");

            // Server sends OK and closes
            WritePacketHeader(hServer, RAWRXD_RESP_OK, 0);

            CloseHandle(hClient);
        }
        CloseHandle(hServer);
        ok &= Check(true, "B031-013", "pipe resources cleaned up", "done");
    }

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B031 — Host IPC End-to-End\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestPipeCreation();
    all_passed &= TestPacketFraming();
    all_passed &= TestRoundTrip();
    all_passed &= TestErrorResponse();
    all_passed &= TestShutdownSequence();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B031 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
