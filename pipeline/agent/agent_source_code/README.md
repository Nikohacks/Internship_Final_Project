# Sentinel Agent

A Windows single-binary event agent configured by `agent.yaml`.

## Build

From this directory:

```powershell
.\build.ps1
```

Or manually:

```powershell
go build -trimpath -ldflags="-s -w" -o sentinel-agent.exe .
```

## Run

```powershell
.\sentinel-agent.exe -config .\agent.yaml
```

Run PowerShell as Administrator when the Security channel requires elevated access.

## Outputs

The default configuration enables both outputs:

- `terminal`: prints each event as JSON containing `tag`, integer `time`, and `record`.
- `forward`: sends Fluent Forward Forward-mode batches to `127.0.0.1:22424`.

Disable either output by setting `enabled: false`, or add another output entry with the same supported type.

The input supports `system` and `Security` channels, a polling interval, lookback window, tag, and the rendered text field name. The YAML parser supports this documented agent schema without external Go dependencies.
