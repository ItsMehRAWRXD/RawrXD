# Root cause classification

## Earliest demonstrated condition

`CHECKOUT_STILL_PROGRESSING`

The checkout is not proven stalled: both `git reset --hard --no-recurse-submodules` workers consumed additional CPU during the two samples and remained responsive. Missing files and the 301,819 status entries are therefore not sufficient evidence of source or repository corruption while initialization is active.

## Not established

- Filesystem corruption: not established.
- Git object database corruption: not established; the target commit is readable and no missing-object error was captured.
- Storage capacity failure: contradicted by approximately 1.49 TB free space.
- Security-filter interference: possible but unproven; filter listing was access-denied and Defender status alone is not causal evidence.
- Path-materialization failure: not established; no Git access/path error was captured.

The correct next action is observation/allowance for the existing checkout processes to complete, followed by a read-only final status check. Do not terminate, unlock, retry, reset, clean, or repair automatically.

