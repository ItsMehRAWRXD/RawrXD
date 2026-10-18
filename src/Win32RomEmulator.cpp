#include "Win32RomEmulator.hpp"
#include <iostream>
#include <unordered_map>

namespace Deep2Rom {

    Win32RomLoader::~Win32RomLoader() {
        unmap_rom();
    }

    bool Win32RomLoader::map_rom_to_virtual_space(const std::wstring& file_path) {
        return map_rom_manifest(file_path);
    }

    void Win32RomLoader::unmap_rom() {
        // Shutdown flickering manager first
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
}
