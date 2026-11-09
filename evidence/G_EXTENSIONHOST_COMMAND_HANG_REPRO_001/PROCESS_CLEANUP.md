# Process cleanup

The test-owned candidate process was PID 13636. `Alt+F4` was attempted first; the process remained alive. The authorized last-resort cleanup then force-stopped PID 13636 only. A subsequent process check found no PID 13636 and no candidate `RawrXD-ExtensionHost` process. The active F IDE was not targeted.

`CLEANUP=PASS_WITH_FORCED_STOP`.
