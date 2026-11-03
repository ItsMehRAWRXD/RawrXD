# Foreground State

After normal window activation, `GetForegroundWindow()` returned the test IDE main HWND `0x350A92`, owned by PID `15528`. `GetGUIThreadInfo()` succeeded for the IDE thread and reported a nonzero focused HWND.
