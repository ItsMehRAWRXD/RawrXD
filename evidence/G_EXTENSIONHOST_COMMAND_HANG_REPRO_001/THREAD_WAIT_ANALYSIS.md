# Thread and wait analysis

The main window was HWND 265390 in PID 13636. Initial and post-click process sampling reported `Responding=True`; CPU time increased from 4.625 to 11.046875 seconds during the five-second observation. No UI thread ID, stack, wait chain, lock owner, exception, or hang dump was available because the authorized reproduction did not enter a non-responsive state.

Classification: no blocking boundary demonstrated. `HANG_CAPTURE=NOT_REQUIRED_FOR_NON_REPRODUCTION`.
