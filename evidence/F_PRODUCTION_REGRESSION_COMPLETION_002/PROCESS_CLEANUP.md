# Process Cleanup

The Deep2 generation process exited `0` after normal model and runtime teardown.

The GUI automation path lost reliable input geometry while attempting the file-open workflow. The remaining native IDE process was then force-stopped by the test harness; no RawrXD-related process remained afterward.

This is cleanup evidence, not a clean GUI shutdown PASS.
