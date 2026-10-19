#pragma once
#include <windows.h>
#include <stdint.h>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <queue>
#include <atomic>
#include <thread>
#include <functional>
#include <unordered_map>
#include <memory>
#include <iostream>

// The ROM container layout lives in core/Deep2Types.hpp, which is the
// single definition shared by the writer (gguf2rom), the multi-shard
// converter (gguf2rom_ms), this loader and the multi-shard manager. It
// used to be duplicated here with a different field order and size, which
// made the tensor table drift on every descriptor.
#include "core/Deep2Types.hpp"

namespace Deep2Rom {

    // Backward-compatible aliases
    using RomHeader = RomHeaderMultiShard;
    using TensorDescriptor = TensorDescriptorMultiShard;

    // ========================================================================
    // RAII TENSOR VIEW (Correct Lifetime Management)
    // ========================================================================
    class TensorView {
    public:
        TensorView() = default;
        TensorView(const uint8_t* ptr_, size_t size_, void* mapped_base_)
            : m_ptr(ptr_), m_size(size_), m_mapped_base(mapped_base_) {}

        TensorView(TensorView&& other) noexcept
            : m_ptr(other.m_ptr), m_size(other.m_size), m_mapped_base(other.m_mapped_base) {
            other.m_ptr = nullptr;
            other.m_size = 0;
            other.m_mapped_base = nullptr;
        }

        TensorView& operator=(TensorView&& other) noexcept {
            if (this != &other) {
                release();
                m_ptr = other.m_ptr;
                m_size = other.m_size;
                m_mapped_base = other.m_mapped_base;
                other.m_ptr = nullptr;
                other.m_size = 0;
                other.m_mapped_base = nullptr;
            }
            return *this;
        }

        TensorView(const TensorView&) = delete;
        TensorView& operator=(const TensorView&) = delete;

        ~TensorView() { release(); }

        const uint8_t* data() const { return m_ptr; }
        size_t size() const { return m_size; }
        bool valid() const { return m_ptr != nullptr; }
        explicit operator bool() const { return valid(); }

    private:
        const uint8_t* m_ptr = nullptr;
        size_t m_size = 0;
        void* m_mapped_base = nullptr;

        void release() {
            if (m_mapped_base) {
                ::UnmapViewOfFile(m_mapped_base);
                m_mapped_base = nullptr;
            }
            m_ptr = nullptr;
            m_size = 0;
        }
    };

    // ========================================================================
    // MOVE 8 & 9: MULTI-SHARD ASYNC FLICKERING MANAGER
    // ========================================================================
    class MultiShardFlickerManager {
    public:
        struct ShardInfo {
            HANDLE file_handle = INVALID_HANDLE_VALUE;
            HANDLE mapping_handle = nullptr;
            uint64_t file_size = 0;
            SYSTEM_INFO sys_info{};
            uint64_t granularity = 65536;
            HANDLE mapping = nullptr;
        };

        MultiShardFlickerManager() = default;
        ~MultiShardFlickerManager() { shutdown(); }

        MultiShardFlickerManager(const MultiShardFlickerManager&) = delete;
        MultiShardFlickerManager& operator=(const MultiShardFlickerManager&) = delete;

        bool register_shard(uint32_t shard_id, const std::wstring& path, uint64_t file_size) {
            std::lock_guard<std::mutex> lock(m_shard_mutex);

            if (m_shards.find(shard_id) != m_shards.end()) {
                return false; // Already registered
            }

            ShardInfo info;
            info.file_size = file_size;

            info.file_handle = ::CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr
            );

            if (info.file_handle == INVALID_HANDLE_VALUE) {
                return false;
            }

            ::GetSystemInfo(&info.sys_info);
            info.granularity = info.sys_info.dwAllocationGranularity;

            info.mapping = ::CreateFileMappingW(
                info.file_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);

            if (!info.mapping) {
                ::CloseHandle(info.file_handle);
                return false;
            }

            m_shards[shard_id] = std::move(info);
            return true;
        }

        // 64KB-aligned bounded mapping result
        struct MappingResult {
            bool success = false;
            const uint8_t* ptr = nullptr;
            size_t size = 0;
            void* mapped_base = nullptr;
            uint32_t shard_id = 0;
            uint64_t tensor_id = UINT64_MAX;
            uint64_t aligned_offset = 0;
            uint64_t delta = 0;
        };

        // Acquire a bounded, 64KB-aligned view of a tensor
        MappingResult map_tensor(uint32_t shard_id, uint64_t tensor_id,
                                 uint64_t absolute_offset, uint64_t tensor_bytes,
                                 uint64_t file_size) {
            auto it = m_shards.find(shard_id);
            if (it == m_shards.end()) {
                return { false, nullptr, 0, nullptr, shard_id, tensor_id, 0, 0 };
            }

            const auto& shard = it->second;
            if (absolute_offset >= file_size) {
                return { false, nullptr, 0, nullptr, shard_id, tensor_id, 0, 0 };
            }

            // Clamp tensor_bytes to available file data (CalcTensorBytes rounds up
            // to 64-byte alignment, which can extend past EOF for the last tensor).
            uint64_t available = file_size - absolute_offset;
            if (tensor_bytes > available) {
                tensor_bytes = available;
            }

            const uint64_t offset = absolute_offset;
            const uint64_t aligned_offset = offset & ~(m_granularity - 1);
            const uint64_t delta = offset - aligned_offset;
            const uint64_t map_size = delta + tensor_bytes;

            if (map_size > SIZE_MAX) {
                return { false, nullptr, 0, nullptr, shard_id, tensor_id, 0, 0 };
            }

            void* mapped_base = ::MapViewOfFile(
                shard.mapping,
                FILE_MAP_READ,
                static_cast<DWORD>(aligned_offset >> 32),
                static_cast<DWORD>(aligned_offset & 0xFFFFFFFF),
                static_cast<SIZE_T>(map_size)
            );

            if (!mapped_base) {
                return { false, nullptr, 0, nullptr, shard_id, tensor_id, 0, 0 };
            }

            const uint8_t* tensor_ptr = static_cast<const uint8_t*>(mapped_base) + (absolute_offset - aligned_offset);

            return { true, tensor_ptr, tensor_bytes, mapped_base, shard_id, tensor_id, aligned_offset, delta };
        }

        static void unmap_view(void* mapped_base) {
            if (mapped_base) ::UnmapViewOfFile(mapped_base);
        }

        // RAII wrapper for automatic lifetime management
        class ScopedView {
        public:
            ScopedView() = default;
            ScopedView(const uint8_t* p, size_t s, void* b) : m_ptr(p), m_size(s), m_mapped_base(b) {}
            ScopedView(ScopedView&& other) noexcept = default;
            ScopedView& operator=(ScopedView&& other) noexcept = default;
            ScopedView(const ScopedView&) = delete;
            ScopedView& operator=(const ScopedView&) = delete;
            ~ScopedView() { if (m_mapped_base) ::UnmapViewOfFile(m_mapped_base); }

            const uint8_t* data() const { return m_ptr; }
            size_t size() const { return m_size; }
            bool valid() const { return m_ptr != nullptr; }
            explicit operator bool() const { return m_ptr != nullptr; }

        private:
            const uint8_t* m_ptr = nullptr;
            size_t m_size = 0;
            void* m_mapped_base = nullptr;
        };

        // Acquire with automatic lifetime (RAII)
        ScopedView acquire_tensor(uint32_t shard_id, uint64_t tensor_id,
                                  uint64_t absolute_offset, uint64_t tensor_bytes,
                                  uint64_t file_size) {
            MappingResult result = map_tensor(shard_id, tensor_id, absolute_offset, tensor_bytes, file_size);
            if (!result.success) return {};
            return ScopedView{ result.ptr, result.size, result.mapped_base };
        }

        void shutdown() {
            for (auto& [id, info] : m_shards) {
                if (info.mapping) ::CloseHandle(info.mapping);
                if (info.file_handle != INVALID_HANDLE_VALUE) ::CloseHandle(info.file_handle);
            }
            m_shards.clear();
        }

    private:
        uint64_t m_granularity = 65536;
        std::unordered_map<uint32_t, ShardInfo> m_shards;
        std::mutex m_shard_mutex;
    };

    // ========================================================================
    // MOVE 2: ZERO-COPY LOADER INTERFACE (Extended for Multi-Shard)
    // ========================================================================
    class Win32RomLoader {
    public:
        Win32RomLoader() = default;
        ~Win32RomLoader() { unmap_rom(); }

        Win32RomLoader(const Win32RomLoader&) = delete;
        Win32RomLoader& operator=(const Win32RomLoader&) = delete;

        bool map_rom_manifest(const std::wstring& manifest_path) {
            unmap_rom();

            m_file_handle = ::CreateFileW(
                manifest_path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr
            );

            if (m_file_handle == INVALID_HANDLE_VALUE) {
                std::cerr << "[Emulator] Win32 Error: CreateFileW failed. Code: " << ::GetLastError() << "\n";
                return false;
            }

            LARGE_INTEGER file_size;
            if (!::GetFileSizeEx(m_file_handle, &file_size)) {
                ::CloseHandle(m_file_handle);
                return false;
            }
            m_file_size = static_cast<uint64_t>(file_size.QuadPart);

            m_mapping_handle = ::CreateFileMappingW(
                m_file_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);

            if (!m_mapping_handle) {
                ::CloseHandle(m_file_handle);
                return false;
            }

            m_view_ptr = static_cast<const uint8_t*>(::MapViewOfFile(
                m_mapping_handle, FILE_MAP_READ, 0, 0, 0));

            if (!m_view_ptr) {
                ::CloseHandle(m_mapping_handle);
                ::CloseHandle(m_file_handle);
                return false;
            }

            m_header = reinterpret_cast<const RomHeader*>(m_view_ptr);

            if (m_header->magic[0] != 'R' || m_header->magic[1] != 'A' || m_header->magic[2] != 'W') {
                std::cerr << "[Emulator] Rom Verification Error: Invalid virtual ROM signature alignment.\n";
                unmap_rom();
                return false;
            }

            if (m_header->metadata_count > 0 && m_header->metadata_offset > 0) {
                const TensorDescriptor* tensor_table = reinterpret_cast<const TensorDescriptor*>(m_view_ptr + m_header->metadata_offset);
                m_tensors.assign(tensor_table, tensor_table + m_header->metadata_count);
            }

            // Initialize flickering manager
            m_flicker_manager = std::make_unique<MultiShardFlickerManager>();

            return true;
        }

        // Alias for callers using the "to_virtual_space" naming
        bool map_rom_to_virtual_space(const std::wstring& file_path) {
            return map_rom_manifest(file_path);
        }

        bool register_shard_file(uint32_t shard_id, const std::wstring& path, uint64_t file_size) {
            if (!m_flicker_manager) return false;
            return m_flicker_manager->register_shard(shard_id, path, file_size);
        }

        void unmap_rom() {
            m_flicker_manager.reset();
            if (m_view_ptr) {
                ::UnmapViewOfFile(m_view_ptr);
                m_view_ptr = nullptr;
            }
            if (m_mapping_handle) {
                ::CloseHandle(m_mapping_handle);
                m_mapping_handle = nullptr;
            }
            if (m_file_handle != INVALID_HANDLE_VALUE) {
                ::CloseHandle(m_file_handle);
                m_file_handle = INVALID_HANDLE_VALUE;
            }
            m_header = nullptr;
            m_tensors.clear();
            m_file_size = 0;
        }

        // Accessors
        [[nodiscard]] const RomHeader* get_header() const { return m_header; }
        [[nodiscard]] const TensorDescriptor* get_tensors() const { return m_tensors.data(); }
        [[nodiscard]] size_t get_tensor_count() const { return m_tensors.size(); }
        [[nodiscard]] HANDLE get_file_handle() const { return m_file_handle; }
        [[nodiscard]] HANDLE get_mapping_handle() const { return m_mapping_handle; }
        [[nodiscard]] uint64_t get_file_size() const { return m_file_size; }
        [[nodiscard]] const std::vector<TensorDescriptor>& get_tensors_vector() const { return m_tensors; }

        // Flickering manager access
        MultiShardFlickerManager& get_flicker_manager() { return *m_flicker_manager; }
        const MultiShardFlickerManager& get_flicker_manager() const { return *m_flicker_manager; }

    private:
        HANDLE m_file_handle{ INVALID_HANDLE_VALUE };
        HANDLE m_mapping_handle{ nullptr };
        const uint8_t* m_view_ptr{ nullptr };
        uint64_t m_file_size = 0;

        const RomHeader* m_header{ nullptr };
        std::vector<TensorDescriptor> m_tensors;

        std::unique_ptr<MultiShardFlickerManager> m_flicker_manager;
    };
}
