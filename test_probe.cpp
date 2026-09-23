#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "F:\\~dev\\rawrxd\\src\\core\\test_tiny_with_vocab.gguf";
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("open failed\n"); return 1; }

    auto readU32 = [&](DWORD& bytesRead) -> uint32_t {
        unsigned char b[4]; DWORD rb = 0;
        if (!ReadFile(h, b, 4, &rb, NULL) || rb < 4) return 0;
        bytesRead += 4;
        return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
    };
    auto readU64 = [&](DWORD& bytesRead) -> uint64_t {
        unsigned char b[8]; DWORD rb = 0;
        if (!ReadFile(h, b, 8, &rb, NULL) || rb < 8) return 0;
        bytesRead += 8;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)b[i] << (i * 8);
        return v;
    };
    auto readString = [&](DWORD& bytesRead) -> std::string {
        uint64_t len = readU64(bytesRead);
        if (len == 0 || len > 65535) return "";
        std::string s(static_cast<size_t>(len), '\0');
        DWORD rb = 0;
        if (!ReadFile(h, &s[0], static_cast<DWORD>(len), &rb, NULL) || rb < len) return "";
        bytesRead += rb;
        return s;
    };
    auto skipString = [&](DWORD& bytesRead) -> bool {
        uint64_t len = readU64(bytesRead);
        if (len > 65535) return false;
        if (len == 0) return true;
        std::vector<char> buf(static_cast<size_t>(len));
        DWORD rb = 0;
        if (!ReadFile(h, buf.data(), static_cast<DWORD>(len), &rb, NULL) || rb < len) return false;
        bytesRead += rb;
        return true;
    };

    DWORD totalRead = 0;

    uint32_t magic = readU32(totalRead);
    if (magic != 0x46554747) { printf("bad magic %08x\n", magic); CloseHandle(h); return 1; }
    uint32_t version = readU32(totalRead);
    uint64_t tensorCount = readU64(totalRead);
    uint64_t metaCount   = readU64(totalRead);

    printf("version=%u tensorCount=%llu metaCount=%llu\n", version, tensorCount, metaCount);

    uint32_t alignment = 32;
    for (uint64_t i = 0; i < metaCount; ++i) {
        std::string key = readString(totalRead);
        if (key.empty()) break;
        uint32_t vtype = readU32(totalRead);
        switch (vtype) {
            case 4: {
                uint32_t v = readU32(totalRead);
                if (key == "general.alignment") alignment = v;
                break;
            }
            case 5: case 6: case 7: {
                unsigned char tmp[4]; DWORD rb = 0;
                ReadFile(h, tmp, 4, &rb, NULL); totalRead += rb;
                break;
            }
            case 8: {
                std::string val = readString(totalRead);
                if (key == "general.architecture") printf("arch=%s\n", val.c_str());
                break;
            }
            case 10: case 11: case 12: {
                unsigned char tmp[8]; DWORD rb = 0;
                ReadFile(h, tmp, 8, &rb, NULL); totalRead += rb;
                break;
            }
            case 9: {
                uint32_t arrType = readU32(totalRead);
                uint64_t arrLen = readU64(totalRead);
                for (uint64_t a = 0; a < arrLen; ++a) {
                    if (arrType == 8) {
                        if (!skipString(totalRead)) { a = arrLen; break; }
                    } else if (arrType == 4 || arrType == 5 || arrType == 6 || arrType == 7) {
                        unsigned char tmp[4]; DWORD rb = 0;
                        ReadFile(h, tmp, 4, &rb, NULL); totalRead += rb;
                    } else if (arrType == 10 || arrType == 11 || arrType == 12) {
                        unsigned char tmp[8]; DWORD rb = 0;
                        ReadFile(h, tmp, 8, &rb, NULL); totalRead += rb;
                    } else {
                        a = arrLen; break;
                    }
                }
                break;
            }
            default: {
                unsigned char tmp[4]; DWORD rb = 0;
                ReadFile(h, tmp, 4, &rb, NULL); totalRead += rb;
                break;
            }
        }
    }

    printf("metadata end totalRead=%u alignment=%u\n", totalRead, alignment);

    // tensor scan
    for (uint64_t i = 0; i < tensorCount; ++i) {
        std::string tname = readString(totalRead);
        if (tname.empty()) { printf("tensor %llu empty name, abort\n", i); break; }
        printf("tensor %llu: name='%s'\n", i, tname.c_str());
        uint32_t nDims = readU32(totalRead);
        for (uint32_t d = 0; d < nDims; ++d) {
            unsigned char tmp[8]; DWORD rb = 0;
            ReadFile(h, tmp, 8, &rb, NULL); totalRead += rb;
        }
        unsigned char tmp[12]; DWORD rb = 0;
        ReadFile(h, tmp, 12, &rb, NULL); totalRead += rb;
    }

    CloseHandle(h);
    return 0;
}
