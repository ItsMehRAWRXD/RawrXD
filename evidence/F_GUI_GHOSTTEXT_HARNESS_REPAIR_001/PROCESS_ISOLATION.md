# Process Isolation

The repaired harness has a fail-closed isolation gate: it refuses to launch when any process with the production executable name already exists. It creates only a disposable fixture under this evidence directory and attributes all HWNDs to the newly launched PID. No GUI launch was performed during this repair because the required pre-launch host/active-session isolation condition was not established in this audit turn.
