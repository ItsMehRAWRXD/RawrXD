# Active Session Check

Read-only process check found an active native IDE:

- PID: `11372`
- Path: `F:\rawrxd\build_ide\bin\rawrxd-win32ide-native.exe`
- Title: `RawrXD IDE  -  Untitled  -  Workspace`
- Responding: `True`

The repaired harness's process-isolation guard therefore correctly blocks `-Run`. No second GUI instance was launched and the active session was not touched.
