# Runtime test prerequisites

The exact future action is: open the Extensions sidebar, select a scanned extension whose runtime record is enabled, and click `Activate` (or double-click the selected list row). This is the first UI action with a complete static path to `ProductExtensionRuntime::Activate` and `SpawnHostUnlocked`.

Before a separately authorized test, verify:

1. Candidate IDE and worker hashes and isolated workspace/log configuration.
2. At least one valid extension record is discoverable under the candidate project root and is enabled.
3. The Activate control is present and its selected list row is non-empty.
4. Capture UI command/control identity, route entry, `CreateProcessA` result, child PID/hash, ready-event result, request/response, and shutdown breadcrumbs.
5. Use bounded 5-second readiness and 2-second graceful-stop observations already defined in source.

No runtime launch is authorized by this audit.
