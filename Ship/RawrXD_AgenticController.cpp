    // Events (C++20, no Qt)
    Event<std::wstring> ControllerError;           // emit controllerError(std::wstring)
    Event<> ControllerReady;                        // emit controllerReady()
    Event<std::wstring> LayoutHydrationRequested;  // emit layoutHydrationRequested(std::wstring)

