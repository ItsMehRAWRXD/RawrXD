// bench_deflate_masm.cpp — Compare custom gzip (stored block) vs zlib deflate
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

#ifdef DEFLATE_NASM
extern "C" void* deflate_nasm(const void* src, size_t len, size_t* out_len, void* hash_buf);
#define HASH_SIZE (1u << 15)
#define deflate_custom deflate_nasm
#elif defined(DEFLATE_GODMODE)
extern "C" void* deflate_godmode(const void* src, size_t len, size_t* out_len, void* hash_buf);
#define HASH_SIZE 8192
#define deflate_custom deflate_godmode
#else
extern "C" void* deflate_masm(const void* src, size_t len, size_t* out_len);
#define deflate_custom deflate_masm
#endif

// zlib reference (optional)
#if !defined(NO_ZLIB_REF)
extern "C" {
    int compress2(unsigned char* dest, unsigned long* destLen, const unsigned char* source, unsigned long sourceLen, int level);
}
#endif

using clk = std::chrono::high_resolution_clock;

static std::string make_json_payload(size_t words, size_t avg_len) {
    std::string s;
    s.reserve(words * (avg_len + 8));
    s += "{\n  \"data\": [\n";
    for (size_t i = 0; i < words; ++i) {
        s += "    {\"id\": ";
        s += std::to_string(i);
        s += ", \"text\": \"";
        for (size_t j = 0; j < avg_len; ++j) {
            char c = static_cast<char>('a' + (j + i) % 26);
            s += c;
        }
        s += "\"}";
        if (i + 1 != words) s += ",";
        s += "\n";
    }
    s += "  ]\n}";
    return s;
}

static void run_case(const char* label, size_t words, size_t avg_len) {
    std::string json = make_json_payload(words, avg_len);
    const unsigned char* src = reinterpret_cast<const unsigned char*>(json.data());
    size_t src_len = json.size();

#ifdef DEFLATE_NASM
    // Allocate hash buffer for NASM version
    void* hash_buf = std::malloc(HASH_SIZE * 4);
    if (!hash_buf) {
        std::printf("Failed to allocate hash buffer\n");
        return;
    }
#endif

    // Our gzip (LZ77 + static Huffman via deflate_nasm/masm)
    size_t out_len = 0;
    auto t0 = clk::now();
#ifdef DEFLATE_NASM
    void* gz = deflate_custom(src, src_len, &out_len, hash_buf);
#else
    void* gz = deflate_custom(src, src_len, &out_len);
#endif
    auto t1 = clk::now();
    double our_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    double our_ratio = (double)src_len / (double)out_len;

#if !defined(NO_ZLIB_REF)
    // zlib reference (level 6)
    std::vector<unsigned char> zbuf(src_len * 2 + 64);
    unsigned long zlen = (unsigned long)zbuf.size();
    t0 = clk::now();
    int zret = compress2(zbuf.data(), &zlen, src, (unsigned long)src_len, 6);
    t1 = clk::now();
    double z_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double z_ratio = (double)src_len / (double)zlen;
    std::printf("[%-10s] src=%zuB  gzip(stored)=%zuB (%.2fx, %.2f ms)  zlib=%luB (%.2fx, %.2f ms)%s\n",
        label, src_len, out_len, our_ratio, our_ms, zlen, z_ratio, z_ms, (zret==0?"":" [zlib err]"));
#else
    std::printf("[%-10s] src=%zuB  gzip(stored)=%zuB (%.2fx, %.2f ms)\n",
        label, src_len, out_len, our_ratio, our_ms);
#endif

#ifdef DEFLATE_NASM
    std::free(hash_buf);
#endif
    std::free(gz);
}

int main() {
    std::puts("== bench_deflate (LZ77 + static Huffman) ==");
    std::puts("Starting test cases...\n");
    std::fflush(stdout);
    
    std::puts("Test 1: 10k/20");
    std::fflush(stdout);
    run_case("10k/20", 10000, 20);
    
    std::puts("Test 2: 40k/40");
    std::fflush(stdout);
    run_case("40k/40", 40000, 40);
    
    std::puts("Test 3: 160k/80");
    std::fflush(stdout);
    run_case("160k/80", 160000, 80);
    
    std::puts("\nAll tests complete!");
    return 0;
}
