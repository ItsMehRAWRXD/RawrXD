// RawrXD Agentic IDE
// Advanced AI-powered IDE with terminal integration and agentic capabilities
// Guard: only compiled when RAWRXD_AGENTIC_MAIN is defined in the CMake target.
// Default build target uses win32app/Win32IDE_Main.cpp (main_win32.cpp) instead.
#ifdef RAWRXD_AGENTIC_MAIN


<<<<<<< HEAD
#include <windows.h>
#include "RawrXD_Application.h"
#include "RawrXD_Editor.h"
#include "RawrXD_Lexer_MASM.h"
#include "RawrXD_StyleManager.h"
#include "agentic_ide.h"
#include <iostream>

=======

#include <windows.h>
#include "RawrXD_Application.h"
#include "RawrXD_Editor.h"
#include "RawrXD_Lexer_MASM.h"
#include "RawrXD_StyleManager.h"
#include "agentic_ide.h"
#include <iostream>

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Optional console for debug output if we want
    // AllocConsole();
    // FILE* fDummy;
    // freopen_s(&fDummy, "CONOUT$", "w", stdout);

    try {
        RawrXD::Application app(hInstance);
        
        RawrXD::Editor editor;
        editor.setTitle(L"RawrXD Agentic IDE (Win32 Native)");
        editor.resize(1024, 768);
        
        // Setup Logic
        RawrXD::MASMLexer masmLexer;
        RawrXD::StyleManager styleManager;
        styleManager.loadDarkTheme(); // Default to dark for "Hacker" feel
        
        editor.setLexer(&masmLexer);
        editor.setStyleManager(&styleManager);
        
        // Initial text
        editor.setText(L"; RawrXD Agentic IDE\n; Powered by Custom Win32 Engine\n\n.code\nmain proc\n    mov rax, 1\n    ret\nmain endp\n");
        
        editor.show();
        
        // Logic Engine (Background)
        RawrXD::AgenticIDE logic;
        logic.initialize();
        logic.setEditor(&editor); 
        logic.start(); // Start the brain!
        
<<<<<<< HEAD
        // The agent logic runs in the background thread, processing events
        // and responding to user interactions through the editor's event system.
        // The main loop handles UI events while the agent processes asynchronously.
=======
        // Start a background thread for agent logic if needed,
        // or just let the main loop run and agent responds to events.
        // For now, we just initialize it.
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

        return app.exec();

        
    } catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << std::endl;
        // MessageBoxA(NULL, e.what(), "Fatal Error", MB_ICONERROR);
        return 1;
    }
}

<<<<<<< HEAD
#endif // RAWRXD_AGENTIC_MAIN
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
