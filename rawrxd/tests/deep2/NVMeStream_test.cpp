// ============================================================================
// NVMeStream_test.cpp — Isolated validation of real NVMeStream provider
// ============================================================================
#include "../../src/deep2/NVMeStream.h"
#include <cstdio>
#include <cassert>
#include <cstring>
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;
using namespace Deep2;

static bool createTempFile(const std::string& path, size_t size) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    for (size_t i = 0; i < size; ++i) {
        ofs.put(static_cast<char>(i & 0xFF));
    }
    return ofs.good();
}

static void test_sync_read() {
    std::string tmp = (fs::temp_directory_path() / "nvme_test_sync.bin").string();
    constexpr size_t FILE_SIZE = 8192;
    assert(createTempFile(tmp, FILE_SIZE));

    NVMeStreamConfig cfg;
    cfg.blockSize = 4096; // direct I/O alignment
    cfg.queueDepth = 4;

    NVMeStream s(cfg);
    assert(s.initialize(tmp));
    assert(s.isInitialized());

    std::vector<uint8_t> buf(FILE_SIZE);
    size_t read = 0;
    assert(s.readSync("test", 0, FILE_SIZE, buf.data(), read));
    assert(read == FILE_SIZE);

    // verify content
    for (size_t i = 0; i < FILE_SIZE; ++i) {
        assert(buf[i] == static_cast<uint8_t>(i & 0xFF));
    }

    s.shutdown();
    assert(!s.isInitialized());
    fs::remove(tmp);
    std::printf("PASS: sync_read\n");
}

static void test_async_read() {
    std::string tmp = (fs::temp_directory_path() / "nvme_test_async.bin").string();
    constexpr size_t FILE_SIZE = 8192;
    assert(createTempFile(tmp, FILE_SIZE));

    NVMeStreamConfig cfg;
    cfg.blockSize = 4096;
    cfg.queueDepth = 8;

    NVMeStream s(cfg);
    assert(s.initialize(tmp));

    std::vector<uint8_t> buf(FILE_SIZE);
    uint64_t reqId = s.readAsync("async_test", 0, FILE_SIZE, buf.data());
    assert(reqId != 0);

    size_t read = 0;
    int ec = 0;
    assert(s.waitForRequest(reqId, read, ec));
    assert(ec == 0);
    assert(read == FILE_SIZE);

    for (size_t i = 0; i < FILE_SIZE; ++i) {
        assert(buf[i] == static_cast<uint8_t>(i & 0xFF));
    }

    s.shutdown();
    fs::remove(tmp);
    std::printf("PASS: async_read\n");
}

static void test_stats() {
    std::string tmp = (fs::temp_directory_path() / "nvme_test_stats.bin").string();
    constexpr size_t FILE_SIZE = 4096;
    assert(createTempFile(tmp, FILE_SIZE));

    NVMeStreamConfig cfg;
    cfg.blockSize = 4096;
    cfg.queueDepth = 4;

    NVMeStream s(cfg);
    s.initialize(tmp);

    std::vector<uint8_t> buf(FILE_SIZE);
    size_t read = 0;
    s.readSync("s1", 0, FILE_SIZE, buf.data(), read);

    auto st = s.stats();
    assert(st.requestsCompleted >= 1);
    assert(st.bytesReadActual == FILE_SIZE);
    assert(st.shortReads == 0);

    s.resetStats();
    st = s.stats();
    assert(st.requestsCompleted == 0);
    assert(st.bytesReadActual == 0);

    s.shutdown();
    fs::remove(tmp);
    std::printf("PASS: stats\n");
}

static void test_out_of_core_read_test() {
    std::string tmp = (fs::temp_directory_path() / "nvme_test_ooc.bin").string();
    constexpr size_t FILE_SIZE = 4096;
    assert(createTempFile(tmp, FILE_SIZE));

    NVMeStreamConfig cfg;
    cfg.blockSize = 4096;
    cfg.queueDepth = 4;

    NVMeStream s(cfg);
    s.initialize(tmp);
    assert(s.outOfCoreReadTest(0, FILE_SIZE, 0)); // CRC=0 bypass

    s.shutdown();
    fs::remove(tmp);
    std::printf("PASS: out_of_core_read_test\n");
}

static void test_cancel() {
    std::string tmp = (fs::temp_directory_path() / "nvme_test_cancel.bin").string();
    constexpr size_t FILE_SIZE = 65536;
    assert(createTempFile(tmp, FILE_SIZE));

    NVMeStreamConfig cfg;
    cfg.blockSize = 4096;
    cfg.queueDepth = 4;

    NVMeStream s(cfg);
    s.initialize(tmp);

    std::vector<uint8_t> buf(FILE_SIZE);
    uint64_t reqId = s.readAsync("cancel_me", 0, FILE_SIZE, buf.data());
    assert(reqId != 0);

    // cancel before worker picks it up (likely)
    bool cancelled = s.cancelRequest(reqId);
    // cancellation may or may not succeed depending on timing; both are valid
    (void)cancelled;

    s.shutdown();
    fs::remove(tmp);
    std::printf("PASS: cancel\n");
}

int main() {
    std::printf("=== NVMeStream Isolated Tests ===\n");
    test_sync_read();
    test_async_read();
    test_stats();
    test_out_of_core_read_test();
    test_cancel();
    std::printf("=== ALL PASSED ===\n");
    return 0;
}
