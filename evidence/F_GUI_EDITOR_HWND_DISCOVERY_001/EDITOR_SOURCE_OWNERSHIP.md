# Editor Source Ownership

`Win32IDE::createEditor()` creates the production editor as a child of the main window with `RICHEDIT_CLASSA` and control ID `IDC_EDITOR`. `Win32IDE_CommandIDs.h` defines `IDC_EDITOR=1001`. GhostText integration attaches the main controller to `m_hwndEditor`; terminal/output RichEdit controls are separate surfaces.
