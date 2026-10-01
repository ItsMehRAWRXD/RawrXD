# Configuration format

The loader accepts a line-oriented `key=value` file. Blank lines and lines
beginning with `#` are ignored. Unknown keys are ignored.

| Key       | Type   | Valid range          | Required |
|-----------|--------|----------------------|----------|
| `host`    | string | non-empty            | yes      |
| `port`    | int    | 1 .. 65535 inclusive | yes      |
| `verbose` | bool   | `true` / `false`     | no       |

Any violation of the table above is a configuration error and must be
reported to the caller as `std::invalid_argument`. A loader that silently
accepts an out-of-range port will hand an unusable endpoint to the network
layer.
