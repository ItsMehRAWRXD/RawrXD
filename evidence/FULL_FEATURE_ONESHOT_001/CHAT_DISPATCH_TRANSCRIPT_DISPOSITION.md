# CHAT_DISPATCH_TRANSCRIPT_DISPOSITION

ASOF_UTC=2026-11-09T13:45:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY_ESTIMATE=82
MATURITY_CHANGE=0
INVENT_PASS=0

```
ARTIFACT_CLASS=CHAT_DISPATCH_TEST_TRANSCRIPT
NE_DEFECT_REGISTER=1
MODEL_RESPONSE_DELIVERY=SUPPORTING_ONLY
CTRL_ENTER_CORRECTNESS=PASS_INPUT_EVENT_GATE
INPUT_EVENT_DISPATCH=PASS
TIP_SHA256=C43B01ABE886700B7A085C570575CCB9DED63A140000380ADCBE07ADEF33A629
SESSION_ID=ied_sess_20261109-084440
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
INTEGRATED_PASS=NOT_CLAIMED
```

## Observations → required verification

| Observation | Disposition |
|-------------|-------------|
| button/ctrl-enter/hold probes get model replies | Dispatch reaches a responding model; **input-event correctness UNVERIFIED** |
| Dispatch IDs restart across sections | Need **session/run IDs** to separate normal reset vs duplicate dispatch |
| Some entries lack responses | Classify: cancelled / interrupted / failed / pending |
| Model injects “BigDaddyG Productivity Mode” / echoes formatting | Inspect system prompt, chat template, session history — **not UI PASS evidence** |
| Model invents commands/packages for probe labels | Responses **cannot** prove UI probes passed |
| Emoji as `ðŸš€` / `ðŸ˜‰` | UTF-8 decode across capture / display / export — investigate |

## Next acceptance gate (controlling for tip_chat)

Instrument actual button + keyboard events; demonstrate:

```
ONE_DISPATCH_PER_BUTTON_CLICK=1
ONE_DISPATCH_PER_CTRL_ENTER=1
ENTER=NEWLINE
HELD_KEY_NO_UNINTENDED_REPEAT=1
RECEIPT_BINDS_FULL_EXE_SHA256=1
RECEIPT_BINDS_SESSION_ID=1
```

Prior measured tip probes (0F4A / B00D…) remain fail-closed: `EXACTLY_ONCE=NOT_VERIFIED` until this gate passes on an identified SHA+session.
