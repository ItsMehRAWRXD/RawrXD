# T10 Current Candidate Attempt

```ini
CANDIDATE_SHA256=2FB9E1B7351EF67AA4876318B6773DBD11AF31D0552ACFC90E61FD080F18A029
SOURCE_COMMIT=bbb26a9e2b230174d06747fa7b6abfc5fad412fb
```

The candidate launched successfully and exposed an Untitled editor tab. The
available native accessibility surface did not expose the editor control as an
editable element; coordinate input instead focused the integrated PowerShell
console. The attempted marker was cleared and no command was executed.

```ini
CANDIDATE_LAUNCH=PASS
UNSAVED_EDITOR_MARKER=NOT_CREATED
AUTOSAVE_SNAPSHOT=NOT_VERIFIED
HARD_KILL=NOT_RUN
COLD_RECOVERY=NOT_RUN
T10=NOT_VERIFIED
```

No T10 PASS is claimed. A desktop harness with reliable native editor focus is
required for the genuine unsaved-buffer fixture.
