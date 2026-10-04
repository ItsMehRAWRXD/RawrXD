// gguf_header_raw.cpp — dump the raw GGUF header fields.
//
// Used when the production loader REJECTS a file that nevertheless begins with
// the GGUF magic. At that point the question is not "what model is this" but
// "what is actually in these bytes", and the only honest way to answer is to
// read the header fields directly and print them, including the failure point.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static uint64_t fileSizeOf(const char* p) {
    WIN32_FILE_ATTRIBUTE_DATA fa{};
    if (!GetFileExInfoStandard && !GetFileAttributesExA(p, GetFileExInfoStandard, &fa))
        return 0;
    return (static_cast<uint64_t>(fa.nFileSizeHigh) << 32) | fa.nFileSizeLow;
}

struct R {
    std::vector<uint8_t> buf;
    size_t pos = 0;
    bool ok = true;
    std::string why;
    bool need(size_t n) {
        if (pos + n > buf.size()) {
            ok = false;
            char t[128];
            std::snprintf(t, sizeof(t), "read past end: want %zu at %zu, have %zu",
                          n, pos, buf.size());
            why = t;
            return false;
        }
        return true;
    }
    template <class T> bool pod(T& out) {
        if (!need(sizeof(T))) return false;
        std::memcpy(&out, buf.data() + pos, sizeof(T));
        pos += sizeof(T);
        return true;
    }
    bool str(uint64_t& len) {
        if (!pod(len)) return false;
        if (len > (1ull << 30)) { ok = false; why = "implausible string length"; return false; }
        if (!need((size_t)len)) return false;
        pos += (size_t)len;
        return true;
    }
};

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: gguf_header_raw <file>\n"); return 2; }
    const char* path = argv[1];

    std::printf("FILE=%s\n", path);
    std::printf("FILE_BYTES=%llu\n", (unsigned long long)fileSizeOf(path));

    // Read a bounded prefix. A real GGUF header is well under 64 KB even with
    // hundreds of metadata entries; if the interesting fields are not in the
    // first 64 KB, that itself is a finding.
    const size_t kRead = 1u << 20;
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::printf("CANNOT_OPEN\n"); return 1; }
    std::vector<uint8_t> head(kRead, 0);
    f.read(reinterpret_cast<char*>(head.data()), (std::streamsize)kRead);
    const size_t got = (size_t)f.gcount();
    std::printf("PREFIX_BYTES_READ=%zu\n", got);
    head.resize(got);

    R r{head, 0, true, ""};

    uint32_t magic = 0, version = 0;
    uint64_t tensorCount = 0, kvCount = 0;

    if (!r.pod(magic)) { std::printf("STOP=%s\n", r.why.c_str()); return 1; }
    std::printf("MAGIC=0x%08x (%s)\n", magic,
                (magic == 0x46554747u) ? "'GGUF'" : "NOT_GGUF");

    if (!r.pod(version)) { std::printf("STOP=%s\n", r.why.c_str()); return 1; }
    std::printf("VERSION=%u\n", version);
    if (version < 2 || version > 3)
        std::printf("VERSION_IMPLAUSIBLE=1  (loader accepts 2 or 3)\n");

    if (!r.pod(tensorCount)) { std::printf("STOP=%s\n", r.why.c_str()); return 1; }
    std::printf("TENSOR_COUNT=%llu\n", (unsigned long long)tensorCount);

    if (!r.pod(kvCount)) { std::printf("STOP=%s\n", r.why.c_str()); return 1; }
    std::printf("METADATA_KV_COUNT=%llu\n", (unsigned long long)kvCount);

    if (tensorCount > (16ull << 20)) std::printf("TENSOR_COUNT_IMPLAUSIBLE=1\n");
    if (kvCount  > ( 4ull << 20)) std::printf("KV_COUNT_IMPLAUSIBLE=1\n");

    // Walk the first few metadata entries so we can SEE the key names rather
    // than infer them.
    std::printf("---- first metadata entries ----\n");
    for (uint64_t i = 0; i < kvCount && i < 6; ++i) {
        uint32_t ktype = 0;
        uint64_t klen = 0;
        if (!r.pod(ktype) || !r.str(klen)) {
            std::printf("KV[%llu] UNREADABLE_AT_OFFSET=%zu : %s\n",
                        (unsigned long long)i, r.pos, r.why.c_str());
            break;
        }
        std::string key((const char*)r.buf.data() + r.pos - (size_t)klen, (size_t)klen);
        // value type follows the key
        uint32_t vtype = 0;
        if (!r.pod(vtype)) {
            std::printf("KV[%llu] key='%s' VALUE_TYPE_UNREADABLE : %s\n",
                        (unsigned long long)i, key.c_str(), r.why.c_str());
            break;
        }
        std::printf("KV[%llu] key='%s' keytype=%u valtype=%u\n",
                    (unsigned long long)i, key.c_str(), ktype, vtype);
        // We cannot generically skip the value without a full type table, so we
        // stop here: the key names alone identify the file.
        break;
    }

    std::printf("HEADER_PARSED_TO_OFFSET=%zu\n", r.pos);
    std::printf("VERDICT=RAW_HEADER_DUMPED\n");
    return 0;
}
