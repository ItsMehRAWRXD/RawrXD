#pragma once
#include <cstdint>
#include <cstddef>
#include "rawrxd_software_raster.h"

namespace rawrxd::ui {
    struct LineStreamWorkspace {
    };

    inline bool buildLineStreamWorkspaceFromSoftwareAtlas(SoftwareRasterWorkspace*, LineStreamWorkspace*) {
        return true;
    }
}