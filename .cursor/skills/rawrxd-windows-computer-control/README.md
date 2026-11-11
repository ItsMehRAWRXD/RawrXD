# RawrXD Windows Computer Control

This repository skill defines the safe protocol for physical Windows GUI
acceptance of RawrXD. It is a specification, not an installed UIAutomation
runtime. A real harness must run in an unlocked interactive desktop and should
use Python 3.11+, `pywinauto`/UI Automation, `psutil`, and screenshot capture.

Use a disposable workspace and separate evidence directory. Preserve the
candidate executable and fail closed on any identity mismatch.
