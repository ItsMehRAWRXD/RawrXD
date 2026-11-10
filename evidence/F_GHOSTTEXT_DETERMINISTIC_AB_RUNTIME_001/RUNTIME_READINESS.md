# Runtime readiness

The candidate SHA was verified before the attempted run. The first launch was isolated, but a stale candidate window remained from the previous attempt; a second window was therefore created accidentally. Both candidate windows were closed through normal UI paths. This run is held and produces no A/B PASS.

```ini
RUNTIME=HELD
PRODUCTION_BINARY_TOUCHED=0
UNRELATED_PROCESSES_TERMINATED=0
```
