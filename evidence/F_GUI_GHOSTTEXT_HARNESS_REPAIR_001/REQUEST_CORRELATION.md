# Request Correlation

Physical request correlation is held. The production controller already emits request IDs for trigger, request-sent, response, render, accept, dismiss, and cancellation events. The repaired harness does not synthesize these events; the next physical run must collect the application’s real output and correlate all events by request ID.
