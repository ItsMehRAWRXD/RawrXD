#pragma once
#include "RawrXD_SignalSlot.h"
#include "RawrXD_Window.h"

namespace RawrXD {

class Application {
    HINSTANCE hInstance;
    static Application* instance;
    bool running = false;
    
public:
    Signal<int> aboutToQuit; // Exit code
    
    Application(HINSTANCE hInst);
    ~Application();
    
    static Application* getInstance() { return instance; }
    HINSTANCE getHInstance() const { return hInstance; }
    
    int exec();
    void quit(int returnCode = 0);
    void processEvents(); // Process pending messages (PeekMessage)
    
    static String applicationDirPath();
    static String applicationFilePath();
    static void setApplicationName(const String& name);
<<<<<<< HEAD
};

// Global accessor (C++20/Win32; no Qt)
#define rawrxdApp RawrXD::Application::getInstance()
=======
    
    // Clipboard methods
    void clipboardSetText(const String& text);
    String clipboardText();
};

// Global macro for accessing the app
#define qApp RawrXD::Application::getInstance()
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

} // namespace RawrXD
