# Pipeline and CTest receipt

Pipeline probe executable SHA-256:
`26B0426D17A333465BEE63FA99ADBCEBC4BC18B77EE72833C1671FC3D1CD5ABD`

```text
DEVICE=AMD Radeon AI PRO R9700 QUEUE_FAMILY=0
PLE_PIPELINE=PASS HC_PIPELINE=PASS GDN_PIPELINE=PASS
DISPATCHES=0 EXECUTION=NOT_RUN
EXIT=0
```

CTest command:

```text
ctest --test-dir F:\rawrxd\build_ide -R "deep2_(vulkan_gdn_dispatch|qwen4exp_operator_contract)" --output-on-failure
```

Result:

```text
2/2 tests passed
Total Test time = 0.66 sec
```

