# Process Inventory

Non-invasive `Win32_Process` inventory found no currently running `rawrxd-win32ide-native.exe` process. The previously observed PID 18000 was not terminated by this task and is no longer present.

The guard now inventories all same-name native IDE processes before launch and records PID, creation time, full path, parent PID, and exact-candidate classification.
