# Extension panel classification

The sidebar creates controls at `Win32IDE_Sidebar.cpp:2474-2500`. The selected extension ID comes from `s_extensionDisplayIds` and the list selection.

- Activate (`IDC_EXT_INSTALL`): calls `activateExtension`, which calls `ProductExtensionRuntime::Activate` and can spawn the worker.
- Enable (`IDC_EXT_ENABLE`): calls `enableExtension`, which calls `ProductExtensionRuntime::Enable(extensionId, true)` and refreshes state; no host spawn call is present in that method.
- Disable (`IDC_EXT_DISABLE`): calls `ProductExtensionRuntime::Enable(extensionId, false)`; no host spawn call is present.
- Uninstall/details/reload: local UI/filesystem operations in the inspected handlers.

The numeric `11810-11814` command IDs are a different legacy/chat-action surface. They should not be substituted for the sidebar Activate control without runtime evidence.
