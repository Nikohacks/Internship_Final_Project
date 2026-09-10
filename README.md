# Windows SOC Log Monitoring Platform

A local security operations dashboard for collecting Windows Event Logs, normalizing them into ECS-style fields, storing them in VictoriaLogs, evaluating vmalert rules, and reviewing alerts through a React dashboard.

The repository contains the application code, the custom Windows agent, and service configuration. Third-party executables such as VictoriaLogs, Fluentd, and vmalert are intentionally not committed.

## Architecture

```text
Windows Event Logs
        |
        v
pipeline/agent/sentinel-agent.exe
        |
        | Fluent Forward :22424
        v
Fluentd + ecs_normalizer
        |
        | HTTP JSON lines
        v
VictoriaLogs :9428
        |
        +--> vmalert rules --> backend webhook :8000
        |
        +--> backend timeseries API

React dashboard :5173 --> backend API :8000
```

## Repository Layout

```text
backend/                         FastAPI API, SQLite alert store
configs/fluentd-configuration/  Fluentd pipeline configuration
configs/vmalert-rules/           vmalert rule files
frontend/                        React + Vite dashboard
pipeline/agent/                  Go Windows Event Log agent and agent.yaml
pipeline/fluentd/                Fluentd plugins/runtime files used locally
```

## Requirements

Install these tools separately on Windows:

- Windows 10/11 with access to the `System` and `Security` Event Log channels
- Go 1.22 or newer for building the custom agent
- Python 3.11 or newer
- Node.js and npm
- VictoriaLogs Windows release
- Fluentd or Fluent Package for Windows
- vmalert Windows release

Download the third-party tools from their official release pages. Do not commit their extracted binaries or data directories to this repository.

## Configuration

The checked-in configuration files are:

- Fluentd: `configs/fluentd-configuration/conf.conf`
- vmalert: `configs/vmalert-rules/alerts.yml`
- Agent: `pipeline/agent/agent.yaml`
- Backend environment: `backend/.env` (create locally; do not commit secrets)

The Fluentd configuration expects the custom normalizer plugin to be available in its plugin directory. The current plugin is:

```text
pipeline/fluentd/opt/fluent/plugins/filter_ecs_normalizer.rb
```

The Fluentd HTTP output targets:

```text
http://127.0.0.1:9428/insert/jsonline
```

The agent forwards events to:

```text
127.0.0.1:22424
```

The default agent configuration enables terminal output and may enable or disable Fluentd forwarding depending on the current local `pipeline/agent/agent.yaml`. Set the forward output to `enabled: true` when sending events through Fluentd.

## Build the Agent

Open PowerShell in `pipeline/agent`:

```powershell
cd pipeline\agent
.\build.ps1
```

If PowerShell execution policies block scripts, build directly:

```powershell
go build -trimpath -ldflags="-s -w" -o sentinel-agent.exe .
```

The output is:

```text
pipeline/agent/sentinel-agent.exe
```

## Python Backend Setup

Create a virtual environment and install the backend dependencies:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create `backend/.env` with local settings, for example:

```dotenv
DATABASE_URL=sqlite:///data/alerts.db
VICTORIA_LOGS_URL=http://localhost:9428
VICTORIA_METRICS_URL=http://localhost:8428
BACKEND_PORT=8000
```

The backend creates its SQLite tables during startup. Keep the local database under `backend/data/`.

## Frontend Setup

```powershell
cd frontend
npm install
npm run dev
```

Vite serves the dashboard at:

```text
http://localhost:5173
```

The Vite proxy forwards `/api` requests to the backend at `http://127.0.0.1:8000`.

For a production build:

```powershell
npm run build
```

## Start the Services

Use separate PowerShell windows. Start them in this order.

### 1. VictoriaLogs

From the directory containing the downloaded VictoriaLogs executable:

```powershell
.\victoria-logs.exe -storageDataPath=".\victoria_data" -httpListenAddr=":9428"
```

Use an absolute storage path if the working directory is not stable:

```powershell
.\victoria-logs.exe -storageDataPath="D:\SOC\victoria_data" -httpListenAddr=":9428"
```

### 2. Fluentd

Use the downloaded Fluentd executable and point it to the repository configuration and plugin directory. Replace the paths with absolute paths on your machine:

```powershell
.\fluentd.exe `
  -p "D:\path\to\pipeline\fluentd\opt\fluent\plugins" `
  -c "D:\path\to\configs\fluentd-configuration\conf.conf"
```

The Fluentd forward input listens on port `22424`.

If Fluentd reports that `ecs_normalizer` is unavailable, confirm that the plugin path contains `filter_ecs_normalizer.rb` and that `-p` points to that directory.

### 3. vmalert

From the directory containing the downloaded vmalert executable:

```powershell
.\vmalert.exe `
  --rule "D:\path\to\configs\vmalert-rules\alerts.yml" `
  --datasource.url "http://127.0.0.1:9428" `
  --rule.defaultRuleType "vlogs" `
  --notifier.url "http://127.0.0.1:8000"
```

vmalert sends firing alerts to the backend notifier endpoint.

### 4. Backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn main:app --reload --port 8000
```

The backend provides:

- `GET /api/alerts`
- `GET /api/alerts/stats`
- `PATCH /api/alerts/{alert_id}/status`
- `GET /api/logs/timeseries`
- `POST /api/v2/alerts`

### 5. Custom Agent

After Fluentd is listening:

```powershell
cd pipeline\agent
.\sentinel-agent.exe -config .\agent.yaml
```

Run PowerShell as Administrator when the Security channel requires elevated access.

The agent supports these output types in `agent.yaml`:

```yaml
outputs:
  - name: terminal
    type: terminal
    enabled: true

  - name: fluentd
    type: forward
    enabled: true
    host: 127.0.0.1
    port: 22424
    time_as_integer: true
```

Use terminal output to inspect events locally. Use forward output to send them to Fluentd. Both can be enabled at the same time.

## Verify the Pipeline

Check each boundary in order:

1. VictoriaLogs is listening on `9428`.
2. Fluentd is listening on `22424`.
3. The agent prints terminal records and reports successful forward output.
4. Fluentd logs show the `windows.winevtlog` tag and normalizer activity.
5. VictoriaLogs contains fields such as `event.code`, `event.provider`, `host.name`, `message`, and `log.level`.
6. vmalert can query VictoriaLogs and reach the backend notifier on port `8000`.
7. The dashboard loads at `http://localhost:5173`.

Useful local checks:

```powershell
Get-NetTCPConnection -LocalPort 9428,8000,22424,5173 -ErrorAction SilentlyContinue
```

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/alerts/stats
```

## Dashboard Workflow

- **Overview** shows total logs, total alerts, and resolved alerts.
- **Alert queue** supports filtering and SOC handling states: firing, acknowledged, investigating, escalated, resolved, and false positive.
- **Log volume** shows time-series counts by severity with preset and custom time ranges.

## Troubleshooting

### Agent says `flag provided but not defined: -config`

The executable is an old build. Rebuild from `pipeline/agent` and confirm the new executable exposes `-config`:

```powershell
.\sentinel-agent.exe -h
```

### Agent sends events but Fluentd shows nothing

Confirm Fluentd owns port `22424`, confirm the agent forward output is enabled, and confirm the agent and Fluentd are using the same port. The agent's successful write only confirms a TCP write; Fluentd must also decode and route the Fluent Forward frame.

### VictoriaLogs reports a missing `_msg` field

Ensure the Fluentd HTTP endpoint includes the agent's rendered text field:

```text
_msg_field=Message,MESSAGE,log,message,rendered_text
```

### Security events are missing

Run the agent from an elevated PowerShell session and confirm Windows Event Log access is available for the `Security` channel.

The repository should contain source code and configuration templates; each user supplies the compatible third-party binaries locally.
