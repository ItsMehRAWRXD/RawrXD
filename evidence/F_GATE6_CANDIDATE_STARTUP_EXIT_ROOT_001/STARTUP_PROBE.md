# Startup probe

The Gate 6 continuation attempted one isolated candidate launch with the existing delay variables set to A=5000 ms and B=50 ms. The process was initially observed as PID 23536, but no stable UI window could be bound. A later process inventory found a test-owned candidate PID 21920 with a main window handle, but the UI bridge could not observe or bind that window; PID 21920 then exited before interaction.

No GhostText request, editor click, model selection, or A/B action was performed in this attempt.
