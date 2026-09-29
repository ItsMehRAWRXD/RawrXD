#pragma once

// Rawr dump authority - First-class model truth command
// This authority builds RawrXD's own model catalog from multiple sources
// and provides comprehensive model information even when Ollama commands do not

namespace rawrxd::cli
{
    // Run rawr dump command
    int runRawrDump(int argc, char* argv[]);
    
    // Write table format dump
    void writeTableDump();
    
    // Write JSON format dump
    void writeJsonDump();
    
    // Write markdown format dump
    void writeMarkdownDump();
    
    // Write dump receipt
    void writeDumpReceipt();
}
