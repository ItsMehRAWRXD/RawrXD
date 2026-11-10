# Process Isolation

Precondition passed: no `RawrXD-Win32IDE-Native` process remained before launch. The harness launched one candidate process and attributed its main window to that process. After the failure, no native IDE process remained (`PROCESS_REMAINS=0`). No competing instance was started and no forced termination was issued by the operator.
