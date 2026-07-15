//=============================================================================
// RawrXD DAP Server Entry Point
// Standalone executable that bridges VS Code to RawrXD debugger
//=============================================================================
#include "DAPAdapter.hpp"
#include "DebugBackend.h"
#include <windows.h>
#include <stdio.h>

using namespace RawrXD;
using namespace RawrXD::DAP;

int wmain(int argc, wchar_t* argv[]) {
    // DAP servers communicate over stdin/stdout
    // Make sure we're in binary mode
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    // Initialize DbgHelp
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    
    // Create debug session
    DebugSession session;
    
    // Create DAP adapter
    DAPAdapter adapter;
    adapter.AttachSession(&session);
    
    // Run the DAP protocol loop
    adapter.Run();
    
    return 0;
}
