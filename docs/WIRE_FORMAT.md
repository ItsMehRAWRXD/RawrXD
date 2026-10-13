# RawrXD native live event wire contract v1

- UTF-8 JSON Lines (newline-delimited); no actual multiline physical records.
- Required string properties: `ts`, `worker`, `kind`, `phase`, `title`, `detail`.
- `ts`: emitter's UTC timestamp, not necessarily worker's original timestamp.
- `seq`: monotonically increasing within one `Sink` object, not a global cursor.
- `task`: correlation identifier, optional (empty string if none).
- `exit_code`: `-1` if not known; nonzero is process failure when phase=fail.
- `sensitive`: writer replaces `title` and `detail` with `[redacted]` before persisting.
- `phase=start`: begun in actual tool worker; `progress`: actual streaming evidence; `info`: neither started nor completed; `ok`: verified success; `fail`: verified failure or abnormal termination.
- Writer currently tolerates multiple processes through the Windows `LockFileEx` region; on POSIX the std::ofstream path is only guaranteed thread-safe within one Sink instance; Linux is a functional test platform, not the production target.
- Reader accepts primitive additive fields but rejects version != 1 and malformed JSON. Renderer holds the latest 600 events, but full persisted log can grow; archive/rotate separately and observe disk free-space policy.
- A `q` key in the viewer detaches the observer, never changes worker state.
- Do not equate a real `reason` summary with a hidden internal model chain-of-thought.
