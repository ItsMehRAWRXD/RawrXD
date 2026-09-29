#pragma once

// Rawr dump rebuild - Rebuilds model catalog from scratch
// This authority rebuilds the model catalog from scratch

namespace rawrxd::cli
{
    // Rebuild dump catalog
    void rebuildDumpCatalog();
    
    // Write rebuild receipt
    void writeRebuildReceipt();
}
