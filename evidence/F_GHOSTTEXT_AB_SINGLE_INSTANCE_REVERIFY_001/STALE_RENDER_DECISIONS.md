# Stale render decisions

PASS for the observed stale-response decision: request A had `eligible=0` after its late response.

Not a full A/B race PASS because request B also had `eligible=0` due to `success=0`; no newer suggestion was rendered.
