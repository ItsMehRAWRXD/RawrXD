# RawrXD native UIAutomation harness

This is a dependency-free Windows PowerShell 5.1 discovery and primitive
control layer using the inbox UIAutomation and System.Drawing assemblies.
Run `inspect.ps1` against an exact candidate SHA. It captures the UIA tree and
screenshot but deliberately emits `NOT_VERIFIED`; project-specific T10/T080/
T15 drivers must add their own assertions and receipts.
