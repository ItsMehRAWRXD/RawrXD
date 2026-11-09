# Command ID capture

The interaction captured menu text and accessibility identity (`Commands`), but no numeric leaf command ID. Opening the top-level menu emitted no observed leaf `WM_COMMAND` or `WM_MENUCOMMAND` evidence. No command was selected after the menu opened.

Result: `COMMAND_ID=NOT_CAPTURED`; `LEAF_COMMAND=NOT_SELECTED`.
