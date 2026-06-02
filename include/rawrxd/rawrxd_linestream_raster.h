#pragma once
#include <cstdint>
#include <cstddef>
#include "rawrxd_software_raster.h"

namespace rawrxd::ui {
    struct LineStreamWorkspace {
        int cellWidth = 8;
        int cellHeight = 16;
    };

    inline bool buildLineStreamWorkspaceFromSoftwareAtlas(SoftwareRasterWorkspace*, LineStreamWorkspace*) {
        return true;
    }
} // namespace rawrxd::ui