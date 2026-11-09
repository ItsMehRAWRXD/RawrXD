# Final verdict

`LEAF_COMMAND_ID=NOT_IDENTIFIED`

`COMMAND_TO_EXTENSIONHOST_ROUTE=NOT_ESTABLISHED`

`PREVIOUS_HANG=NOT_REPRODUCED`

`GRACEFUL_SHUTDOWN=FAIL_REPORTED`

`COMMAND_SURFACE_ROOT=UNVERIFIED`

`HANG_ROOT=UNVERIFIED`

`EXTENSIONHOST_REACHED=0`

`RUNTIME=HELD`

The exact leaf action needed to exercise ExtensionHost was not identified. The generic Commands menu and the extension-panel command IDs are not proven to be the same route. Shutdown contains several synchronous teardown points, but the observed failure boundary is unproven.
