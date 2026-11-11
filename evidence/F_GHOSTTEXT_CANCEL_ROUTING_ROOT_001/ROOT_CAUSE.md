# Root causes

## Cancellation

Physical evidence shows request 3 rendered after Escape. The exact first cause is not fully distinguishable because the runtime has no Escape-entry trace. The violated contract is that Escape did not produce an observable generation invalidation before the response commit.

## Stale responses

Not physically verified. Source fences exist, but no delayed A/B response race was captured.

## Model routing

The tested candidate routed Auto Local to `bigdaddyg-productivity-local:latest` while the UI showed `qwen3:8b`. The working tree contains a corrective routing implementation, but the tested binary was not rebuilt from it. The candidate is therefore not valid evidence for the corrected routing path.
