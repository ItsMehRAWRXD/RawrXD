# Sovereign SDK Bindings

This directory contains additive language bindings for the C ABI in include/sovereign_sdk.h.

## Python

File: bindings/python/sovereign_sdk.py

- Uses ctypes only (no extra dependency)
- Wires lifecycle and status calls

## Node.js

File: bindings/nodejs/sovereign_sdk.js

- Scaffold for ffi-napi/ref-napi integration
- Keeps ABI stable while SDK evolves

## Contract Rule

Do not add engine logic in bindings.
Bindings must only call exported C ABI functions.
