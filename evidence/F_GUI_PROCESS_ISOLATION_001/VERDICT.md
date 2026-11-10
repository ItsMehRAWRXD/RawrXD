# Verdict

`PROCESS_ISOLATION=NOT_ESTABLISHED`

The source does not provide a single-instance restriction, but it also does not provide sufficient per-instance settings/log/request isolation for a safe concurrent run. A live IDE process is present now, so the harness correctly refuses physical execution.

Classification: `HELD_REQUIRED_USER_SESSION_STATE` rather than a production or harness defect.
