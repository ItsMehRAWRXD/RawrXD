#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <fstream>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif

const uint32_t GGUF_MAGIC = 0x46554747;

enum class GGUFType : uint32_t {
    F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7,
    Q8_0 = 8, Q8_K = 9, Q4_K_M = 12
};

struct GGUFTensor {
    std::string name;
    GGUFType type;
    std::vector<uint64_t> shape;
    uint8_t* data_ptr;
    size_t size_bytes;
    std::string source_shard;
};

class GGUFShardedLoader {
    struct MappedFile {
        std::string path;
        uint8_t* buffer;
        size_t size;
#ifdef _WIN32
        HANDLE file_handle;
        HANDLE mapping_handle;
#else
        int fd;
#endif
    };

    std::vector<MappedFile> mapped_shards;
    std::unordered_map<std::string, GGUFTensor> tensor_registry;

    template<typename T>
    T read_val(std::ifstream& f) {
        T val;
        f.read(reinterpret_cast<char*>(&val), sizeof(T));
        return val;
    }

    std::string read_string(std::ifstream& f) {
        uint64_t len = read_val<uint64_t>(f);
        std::string str(len, '\0');
        f.read(&str[0], len);
        return str;
    }

    bool map_file_to_memory(const std::string& path, MappedFile& mf) {
        mf.path = path;
#ifdef _WIN32
        mf.file_handle = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (mf.file_handle == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER size;
        GetFileSizeEx(mf.file_handle, &size);
        mf.size = static_cast<size_t>(size.QuadPart);

        mf.mapping_handle = CreateFileMappingA(mf.file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!mf.mapping_handle) { CloseHandle(mf.file_handle); return false; }

        mf.buffer = reinterpret_cast<uint8_t*>(MapViewOfFile(mf.mapping_handle, FILE_MAP_READ, 0, 0, 0));
        return mf.buffer != nullptr;
#else
        mf.fd = open(path.c_str(), O_RDONLY);
        if (mf.fd < 0) return false;

        struct stat sb;
        if (fstat(mf.fd, &sb) == -1) { close(mf.fd); return false; }
        mf.size = sb.st_size;

        mf.buffer = reinterpret_cast<uint8_t*>(mmap(NULL, mf.size, PROT_READ, MAP_SHARED, mf.fd, 0));
        if (mf.buffer == MAP_FAILED) { close(mf.fd); return false; }

        madvise(mf.buffer, mf.size, MADV_SEQUENTIAL);
        return true;
#endif
    }

    void unmap_files() {
        for (auto& mf : mapped_shards) {
            if (!mf.buffer) continue;
#ifdef _WIN32
            UnmapViewOfFile(mf.buffer);
            CloseHandle(mf.mapping_handle);
            CloseHandle(mf.file_handle);
#else
            munmap(mf.buffer, mf.size);
            close(mf.fd);
#endif
        }
        mapped_shards.clear();
    }

public:
    GGUFShardedLoader() {}
    ~GGUFShardedLoader() { unmap_files(); }

    bool load_shard(const std::string& shard_path) {
        std::ifstream f(shard_path, std::ios::binary);
        if (!f.is_open()) {
            std::cerr << "[-] Failed to open stream for shard: " << shard_path << "\n";
            return false;
        }

        uint32_t magic = read_val<uint32_t>(f);
        if (magic != GGUF_MAGIC) {
            std::cerr << "[-] Invalid GGUF magic token in shard: " << shard_path << "\n";
            return false;
        }

        uint32_t version = read_val<uint32_t>(f);
        uint64_t tensor_count = read_val<uint64_t>(f);
        uint64_t kv_count = read_val<uint64_t>(f);

        for (uint64_t i = 0; i < kv_count; ++i) {
            read_string(f);
            uint32_t value_type = read_val<uint32_t>(f);
            if (value_type == 9) {
                uint32_t sub_type = read_val<uint32_t>(f);
                uint64_t array_len = read_val<uint64_t>(f);
                if (sub_type <= 8) f.seekg(array_len * (1 << sub_type), std::ios::cur);
                else {
                    for (uint64_t j = 0; j < array_len; ++j) read_string(f);
                }
            } else if (value_type == 8) {
                read_string(f);
            } else {
                f.seekg(1 << (value_type & 0xF), std::ios::cur);
            }
        }

        MappedFile mf;
        if (!map_file_to_memory(shard_path, mf)) {
            std::cerr << "[-] Mmap allocation failed for: " << shard_path << "\n";
            return false;
        }
        mapped_shards.push_back(mf);

        struct TempTensorMeta {
            std::string name;
            std::vector<uint64_t> shape;
            GGUFType type;
            uint64_t offset;
        };
        std::vector<TempTensorMeta> temp_meta(tensor_count);

        for (uint64_t i = 0; i < tensor_count; ++i) {
            temp_meta[i].name = read_string(f);
            uint32_t n_dimensions = read_val<uint32_t>(f);
            temp_meta[i].shape.resize(n_dimensions);
            for (uint32_t d = 0; d < n_dimensions; ++d) {
                temp_meta[i].shape[d] = read_val<uint64_t>(f);
            }
            temp_meta[i].type = static_cast<GGUFType>(read_val<uint32_t>(f));
            temp_meta[i].offset = read_val<uint64_t>(f);
        }

        uint64_t current_pos = f.tellg();
        uint64_t alignment = 32;
        uint64_t data_offset_start = (current_pos + alignment - 1) & ~(alignment - 1);

        for (const auto& meta : temp_meta) {
            GGUFTensor tensor;
            tensor.name = meta.name;
            tensor.type = meta.type;
            tensor.shape = meta.shape;
            tensor.source_shard = shard_path;

            tensor.data_ptr = mf.buffer + data_offset_start + meta.offset;

            uint64_t elements = 1;
            for (auto dim : meta.shape) elements *= dim;
            tensor.size_bytes = elements;

            tensor_registry[tensor.name] = tensor;
        }

        std::cout << "[+] Registered " << tensor_count << " tensors from shard: " << shard_path << "\n";
        return true;
    }

    const GGUFTensor* get_tensor(const std::string& name) const {
        auto it = tensor_registry.find(name);
        if (it == tensor_registry.end()) return nullptr;
        return &(it->second);
    }
};

int main() {
    GGUFShardedLoader loader;
    std::cout << "[test] GGUFShardedLoader compiled successfully\n";
    return 0;
}
