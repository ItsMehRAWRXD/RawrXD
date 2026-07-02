#pragma once

#include <stdint.h>

enum class LoadResult : int32_t {
    Success = 0,
    Pending = 1,
    Error_FileNotFound = -1,
    Error_InsufficientVRAM = -2,
    Error_CorruptData = -3,
    Error_HardwareTimeout = -4,
    Error_OpenFailed = -5,
    Error_FileSizeReadFailed = -6,
    Error_FileMappingFailed = -7,
    Error_MapViewFailed = -8,
    Error_Unknown = -99,
};