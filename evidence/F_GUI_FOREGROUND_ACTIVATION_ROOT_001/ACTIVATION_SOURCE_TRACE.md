# Activation Source Trace

The physical probe called `ShowWindowAsync(target, SW_RESTORE)` followed by `SetForegroundWindow(target)`, then sampled foreground ownership and `GetGUIThreadInfo` ten times at 100 ms intervals. No keyboard injection or unrestricted focus bypass was used.
