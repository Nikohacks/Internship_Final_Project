from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import logging
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from database import init_db, get_db, Alert

app = FastAPI(title="Alert & Log API", version="1.0")
logger = logging.getLogger(__name__)
VICTORIA_LOGS_URL = os.getenv("VICTORIA_LOGS_URL", "http://localhost:9428").rstrip("/")
TIMESERIES_LEVELS = ("critical", "high", "medium", "low")
ALERT_STATUSES = ("firing", "acknowledged", "investigating", "escalated", "resolved", "false_positive")
INTERVAL_PATTERN = re.compile(r"^\d+(ms|s|m|h|d|w)$")
LOG_LEVEL_FIELD = "log.level"
LOG_LEVEL_SEVERITY = {
    "0": "critical", "1": "critical", "2": "critical",
    "3": "high",
    "4": "medium", "5": "medium",
    "6": "low", "7": "low",
}

# --- CORS Middleware (for React) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---
class AlertItem(BaseModel):
    startsAt: str
    endsAt: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    generatorURL: Optional[str] = None

class AlertResponse(BaseModel):
    id: int
    alert_name: str
    status: str
    severity: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    starts_at: Optional[datetime]
    ends_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str

# --- Database Initialization ---
@app.on_event("startup")
def startup():
    init_db()
    print("✅ Database initialized (alerts.db created)")

# --- Health & Test Endpoints ---
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/test-db")
def test_db(db: Session = Depends(get_db)):
    count = db.query(Alert).count()
    return {"message": f"Database connected. Current alerts count: {count}"}

# ================== PHASE 4: Query APIs ==================

@app.get("/api/alerts", response_model=List[AlertResponse])
def get_alerts(
    db: Session = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status: firing, resolved, all"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    alert_name: Optional[str] = Query(None, description="Filter by alert name (partial match)"),
    limit: int = Query(50, ge=1, le=200, description="Number of results per page"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    Get a list of alerts with filtering and pagination.
    """
    query = db.query(Alert)

    # Filters
    if status and status.lower() != "all":
        query = query.filter(Alert.status == status.lower())
    if severity:
        query = query.filter(Alert.severity == severity)
    if alert_name:
        query = query.filter(Alert.alert_name.ilike(f"%{alert_name}%"))

    # Order by most recent first
    query = query.order_by(Alert.created_at.desc())

    # Pagination
    alerts = query.offset(offset).limit(limit).all()
    return alerts

@app.get("/api/alerts/stats")
def get_alert_stats(db: Session = Depends(get_db)):
    """
    Get summary statistics of alerts.
    """
    total = db.query(Alert).count()
    firing = db.query(Alert).filter(Alert.status == "firing").count()
    resolved = db.query(Alert).filter(Alert.status == "resolved").count()

    # Count by severity
    severity_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_map = {sev: count for sev, count in severity_counts}

    return {
        "total": total,
        "firing": firing,
        "resolved": resolved,
        "by_severity": severity_map
    }


@app.patch("/api/alerts/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db)):
    """Update an alert's SOC handling state."""
    status = payload.status.strip().lower()
    if status not in ALERT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported status. Choose one of: {', '.join(ALERT_STATUSES)}",
        )

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert


def _format_logs_query(start: datetime, end: datetime, interval: str,
                       levels: Optional[str], query: Optional[str]) -> str:
    """Build the LogsQL aggregation while keeping user filters separate."""
    start_text = start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    end_text = end.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    filters = [f'_time:>="{start_text}"', f'_time:<="{end_text}"']

    if levels:
        requested = [level.strip().lower() for level in levels.split(",") if level.strip()]
        invalid = [level for level in requested if level not in TIMESERIES_LEVELS]
        if invalid:
            raise HTTPException(status_code=400, detail=f"Unsupported levels: {', '.join(invalid)}")
        raw_levels = [raw for raw, severity in LOG_LEVEL_SEVERITY.items() if severity in requested]
        level_filters = " OR ".join(f'{LOG_LEVEL_FIELD}:"{level}"' for level in raw_levels)
        filters.append(f"({level_filters})")

    if query and query.strip():
        filters.append(f"({query.strip()})")

    return " AND ".join(filters) + f" | stats by ({LOG_LEVEL_FIELD}, _time:{interval}) count()"


def _read_timeseries_response(payload: str) -> List[Dict[str, Any]]:
    """Accept VictoriaLogs JSON, JSON arrays, and newline-delimited JSON."""
    try:
        decoded = json.loads(payload)
        rows = decoded.get("data", decoded) if isinstance(decoded, dict) else decoded
        if isinstance(rows, list):
            return rows
    except json.JSONDecodeError:
        pass

    rows = []
    for line in payload.splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _normalize_timeseries(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for row in rows:
        timestamp = row.get("time", row.get("_time"))
        level = row.get("level", row.get("severity", row.get(LOG_LEVEL_FIELD)))
        count = row.get("count", row.get("count()", row.get("count(*)", row.get("_count", 0))))
        if timestamp is None or level is None:
            continue
        try:
            count = int(count)
        except (TypeError, ValueError):
            continue
        raw_level = str(level).lower()
        normalized.append({
            "time": timestamp,
            "level": LOG_LEVEL_SEVERITY.get(raw_level, raw_level),
            "count": count,
        })
    return normalized


@app.get("/api/logs/timeseries")
def get_logs_timeseries(
    start: datetime = Query(..., description="ISO datetime at the beginning of the range"),
    end: datetime = Query(..., description="ISO datetime at the end of the range"),
    interval: str = Query("5m", description="VictoriaLogs bucket interval"),
    levels: Optional[str] = Query(None, description="Comma-separated severity levels"),
    query: Optional[str] = Query(None, description="Additional LogsQL filter"),
):
    if start.tzinfo is None or end.tzinfo is None:
        raise HTTPException(status_code=400, detail="start and end must include a timezone")
    if end <= start:
        raise HTTPException(status_code=400, detail="end must be after start")
    if not INTERVAL_PATTERN.fullmatch(interval):
        raise HTTPException(status_code=400, detail="interval must look like 5m, 1h, or 1d")

    logs_query = _format_logs_query(start, end, interval, levels, query)
    endpoint = f"{VICTORIA_LOGS_URL}/select/logsql/query?{urlencode({'query': logs_query})}"
    try:
        request = Request(endpoint, headers={"Accept": "application/json"})
        with urlopen(request, timeout=10) as response:
            rows = _read_timeseries_response(response.read().decode("utf-8"))
        return {"data": _normalize_timeseries(rows)}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        logger.exception("VictoriaLogs rejected timeseries query: %s", detail)
        raise HTTPException(status_code=502, detail="VictoriaLogs rejected the timeseries query") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.exception("VictoriaLogs timeseries request failed")
        raise HTTPException(status_code=502, detail="VictoriaLogs is unavailable") from exc

@app.get("/debug/alerts")
def debug_alerts(db: Session = Depends(get_db)):
    """
    Quick debug endpoint to see all alerts without sqlite3 CLI.
    """
    alerts = db.query(Alert).order_by(Alert.id.desc()).limit(20).all()
    return [
        {
            "id": a.id,
            "alert_name": a.alert_name,
            "status": a.status,
            "severity": a.severity,
            "starts_at": a.starts_at.isoformat() if a.starts_at else None,
            "ends_at": a.ends_at.isoformat() if a.ends_at else None,
            "labels": a.labels,
        }
        for a in alerts
    ]

# ================== PHASE 3: Webhook with Deduplication ==================

@app.post("/api/v2/alerts")
async def receive_alerts(alerts: List[AlertItem], db: Session = Depends(get_db)):
    """
    Receives alerts from vmalert.
    - Every alert is treated as firing.
    - Duplicates are skipped based on (alertname + labels + starts_at).
    """
    try:
        print(f"📨 Received {len(alerts)} alert(s) from vmalert")
        now_utc = datetime.now(timezone.utc)
        inserted_count = 0
        skipped_duplicate_count = 0

        for alert_item in alerts:
            alert_name = alert_item.labels.get("alertname", "unknown")
            severity = alert_item.labels.get("severity", "unknown")
            labels_json = json.dumps(alert_item.labels, sort_keys=True)

            # Parse starts_at (required)
            try:
                starts_at = datetime.fromisoformat(alert_item.startsAt.replace("Z", "+00:00"))
            except Exception:
                starts_at = now_utc

            # We ignore ends_at for status; only store it if you want,
            # but we'll set it to None because we treat everything as firing.
            ends_at = None

            # --- Check for duplicate ---
            # Find all alerts with same name and same start time
            potential_duplicates = db.query(Alert).filter(
                Alert.alert_name == alert_name,
                Alert.starts_at == starts_at
            ).all()

            duplicate_found = False
            for existing in potential_duplicates:
                # Compare labels exactly
                if json.dumps(existing.labels, sort_keys=True) == labels_json:
                    duplicate_found = True
                    break

            if duplicate_found:
                skipped_duplicate_count += 1
                print(f"⏭️ Skipped duplicate: {alert_name} (starts_at={starts_at})")
                continue

            # --- Insert as firing ---
            new_alert = Alert(
                alert_name=alert_name,
                status="firing",          # always firing
                severity=severity,
                labels=alert_item.labels,
                annotations=alert_item.annotations,
                starts_at=starts_at,
                ends_at=None,             # firing alerts have no end time
                created_at=now_utc
            )
            db.add(new_alert)
            inserted_count += 1
            print(f"✅ INSERTED firing: {alert_name}")

        db.commit()
        msg = f"Inserted {inserted_count} alerts"
        if skipped_duplicate_count:
            msg += f", skipped {skipped_duplicate_count} duplicates"
        print(f"✅ {msg}")
        return {"status": "success", "message": msg}

    except Exception as e:
        db.rollback()
        print(f"❌ Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# --- Legacy /webhook endpoint (optional) ---
@app.post("/webhook")
async def webhook_legacy(alerts: List[AlertItem], db: Session = Depends(get_db)):
    return await receive_alerts(alerts, db)