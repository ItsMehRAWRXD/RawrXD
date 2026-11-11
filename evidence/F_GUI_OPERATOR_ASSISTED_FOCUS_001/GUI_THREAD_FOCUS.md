# GUI Thread Focus

After the operator-assisted activation, the accessibility tree reported focus on the control exposed as `PowerShell Console`, ID `1001`, not the intended central editor. A central-pane click did not produce an unambiguous editor-focus witness.

Final post-close read-only focus sample belonged to Edge PID `10416`, not the terminated test process.

`EDITOR_FOCUS=FAIL_NOT_EDITOR`.
