#pragma once

// Model catalog authority - Builds RawrXD's own model catalog
// This authority builds RawrXD's own catalog from multiple sources
// and provides comprehensive model information even when Ollama commands do not

namespace rawrxd::models
{
    // Build catalog from scratch
    void buildCatalogFromScratch();
    
    // Scan model roots
    void scanModelRoots();
    
    // Scan aliases
    void scanAliases();
    
    // Scan Ollama manifests
    void scanOllamaManifests();
    
    // Scan local GGUF files
    void scanLocalGguf();
    
    // Deduplicate model records
    void dedupeModelRecords();
    
    // Probe all GGUF metadata
    void probeAllGgufMetadata();
    
    // Classify all models
    void classifyAllModels();
    
    // Apply user dump rules
    void applyUserDumpRules();
    
    // Write catalog receipt
    void writeCatalogReceipt();
}
