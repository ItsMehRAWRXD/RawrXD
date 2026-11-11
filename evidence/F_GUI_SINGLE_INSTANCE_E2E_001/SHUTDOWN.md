# Shutdown

The harness's `finally` cleanup left no native IDE process running after the editor-discovery failure. This is bounded cleanup evidence, not a graceful shutdown PASS; no normal close request was reached.
