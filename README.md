# OpenCode Go usage-limits plugin for Millivolt

Signed ABI v1 plugin that tracks OpenCode Go requests and, when a tracked
request supplies the provider credential, calls the OpenCode usage API to
publish rolling/weekly/monthly quota into Millivolt's dashboard.

## Install from GitHub release

In Millivolt Settings → Plugins, paste:

```text
github:hv-V6/millivolt-opencode-usage-limits@v0.7.0
```

or:

```text
github:hv-V6/millivolt-opencode-usage-limits@latest
```

`plugin_downloads_enabled` must be true and the proxy must trust the `release`
signer in [dist/trust.json](dist/trust.json). Installation requires a restart;
after restart, send one OpenCode Go request through the proxy to populate the
quota descriptor.

## Package

- Release asset: `opencode-usage-limits-0.7.0.mvplugin`
- Capabilities: `log`, `emit_metric`, `read:records`, `read:config`,
  `declare_tool`, `declare_ui_panel`, `http:fetch`
- ABI: v1
- Min Millivolt: 0.3.26

The guest never supplies HTML or JS. All dashboard output is bounded, escaped
descriptor data rendered by Millivolt core.

## Build from source

```sh
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o dist/usage-limits.wasm ./cmd/usage-wasm
go test ./...
```

MIT licensed.
