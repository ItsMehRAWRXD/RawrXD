// q2k_type_verifier.cpp — standalone GGUF type dumper
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "F:\\rawrxd\\gemma3-1b-Q2_K.gguf";
    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "FAIL=open %s\n", path); return 1; }

    char magic[5] = {};
    fread(magic, 1, 4, f);
    uint32_t version = 0, n_tensors_lo = 0, n_meta_lo = 0;
    uint64_t n_tensors = 0, n_meta = 0;
    if (magic[0]=='G' && magic[1]=='G' && magic[2]=='U' && magic[3]=='F') {
        fread(&version, 4, 1, f);
        fread(&n_tensors, 8, 1, f);
        fread(&n_meta, 8, 1, f);
    } else if (memcmp(magic, "GGUF", 4) == 0) {
        // little-endian already read
        fread(&version, 4, 1, f);
        fread(&n_tensors_lo, 4, 1, f);
        fread(&n_meta_lo, 4, 1, f);
        n_tensors = n_tensors_lo; n_meta = n_meta_lo;
    } else {
        fprintf(stderr, "Unknown magic: %s\n", magic);
        fclose(f); return 1;
    }
    fprintf(stderr, "GGUF magic=%s version=%u tensors=%llu meta=%llu\n", magic, version, (unsigned long long)n_tensors, (unsigned long long)n_meta);

    // Skip metadata (rough: just find first tensor name that starts with a known prefix)
    // Search for "token_embd" in first 8KB
    std::vector<uint8_t> buf(8192);
    size_t nread = fread(buf.data(), 1, buf.size(), f);
    fclose(f);

    const char* targets[] = {"token_embd.weight", "blk.0.attn_q.weight", "blk.0.attn_k.weight", "blk.0.attn_v.weight", "blk.0.attn_norm.weight"};
    for (int t = 0; t < 5; ++t) {
        const char* name = targets[t];
        size_t nlen = strlen(name);
        for (size_t i = 0; i + nlen + 20 < nread; ++i) {
            if (memcmp(buf.data() + i, name, nlen) == 0) {
                // GGUF v3 descriptor: name bytes, then u32 ndim, then ndim*u64 shape, then u32 type, then u64 offset
                size_t p = i + nlen;
                uint32_t ndim = *reinterpret_cast<uint32_t*>(buf.data() + p); p += 4;
                if (ndim < 1 || ndim > 4) continue;
                for (uint32_t d = 0; d < ndim; ++d) p += 8; // skip shape
                uint32_t ttype = *reinterpret_cast<uint32_t*>(buf.data() + p); p += 4;
                uint64_t toff = *reinterpret_cast<uint64_t*>(buf.data() + p);
                fprintf(stderr, "TENSOR=%s type=%u ndim=%u offset=%llu\n", name, ttype, ndim, (unsigned long long)toff);
                break;
            }
        }
    }
    return 0;
}
