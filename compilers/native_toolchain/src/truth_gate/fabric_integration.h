/*
 * Truth Gate 003: Fabric Integration
 * 
 * Connects RawRamXD Fabric to model tensors
 */

#ifndef FABRIC_INTEGRATION_H
#define FABRIC_INTEGRATION_H

#include "gguf_integration.h"
#include "../fabric/rawramxd_fabric.h"

// Opaque fabric context
struct FabricContext;

// Initialize fabric for model
FabricContext* FabricIntegration_Init();

// Free fabric context
void FabricIntegration_Free(FabricContext* ctx);

// Register all model tensors with fabric
int FabricIntegration_RegisterModelTensors(FabricContext* ctx, GGUFModel* model);

// Set residency for active layer
int FabricIntegration_SetActiveLayerResidency(FabricContext* ctx, int layer_idx);

// Residency statistics
struct ResidencyStats {
    int total_tensors;
    int vram_resident;
    int ram_resident;
    int disk_resident;
    double vram_residency_percent;
    int prefetch_hits;
    int prefetch_misses;
    int spill_count;
    int restore_count;
};

ResidencyStats FabricIntegration_GetResidencyStats(FabricContext* ctx);

// Prefetch layer weights
bool FabricIntegration_PrefetchLayer(FabricContext* ctx, int layer_idx);

// Spill inactive layers
bool FabricIntegration_SpillInactiveLayers(FabricContext* ctx, int active_layer);

#endif // FABRIC_INTEGRATION_H
