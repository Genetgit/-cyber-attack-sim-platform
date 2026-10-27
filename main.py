import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.client import RunnerClient
from app.config import settings
from app.database import Base, async_session, engine, get_db
from app.detection import run_detection_engine
from app.llm import call_llm_analysis
from app.models import AlertModel, EventModel, VerificationModel
from app.schemas import (Alert, AlertDetailResponse, DefenseApplyRequest, DefenseApplyResponse, Event,
                         EventIngestRequest, EventIngestResponse, VerificationDetailResponse,
                         VerificationRequest, VerificationResponse, to_naive_utc)
from app.verification import run_verification_pipeline

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield

app = FastAPI(title="Adaptive Cyber Attack Simulation & Defense Verification Platform API",
              version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---- errors always use {"error": "message"} ----
@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)

@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    msg = "; ".join(f"{'.'.join(str(x) for x in e['loc'] if x != 'body')}: {e['msg']}" for e in exc.errors())
    return JSONResponse({"error": f"Invalid request: {msg}"}, status_code=422)

@app.exception_handler(Exception)
async def unexpected_error(request: Request, exc: Exception):
    return JSONResponse({"error": "Internal server error"}, status_code=500)

async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    if x_api_key != settings.API_KEY:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or missing API key.")

AUTH = [Depends(verify_api_key)]

def to_alert(a: AlertModel) -> Alert:
    return Alert(alert_id=a.alert_id, rule_id=a.rule_id, title=a.title, severity=a.severity, risk_score=a.risk_score,
                 host_id=a.host_id, src_ip=a.src_ip, mitre_technique=a.mitre_technique, first_seen=a.first_seen,
                 last_seen=a.last_seen, event_ids=[e.event_id for e in a.events], status=a.status,
                 ai_analysis=a.ai_analysis)

async def get_alert_or_404(db: AsyncSession, alert_id: str) -> AlertModel:
    a = await db.get(AlertModel, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a

@app.post("/api/events", response_model=EventIngestResponse, dependencies=AUTH)
async def ingest_events(payload: EventIngestRequest, db: AsyncSession = Depends(get_db)):
    ids = [e.event_id for e in payload.events]
    seen = set((await db.execute(select(EventModel.event_id).where(EventModel.event_id.in_(ids)))).scalars())
    new = []
    for e in payload.events:
        if e.event_id in seen:      # duplicate event_id: ignore, keeps ingestion idempotent
            continue
        seen.add(e.event_id)
        new.append(EventModel(event_id=e.event_id, timestamp=to_naive_utc(e.timestamp), host_id=e.host_id,
                              source=e.source, event_type=e.event_type, src_ip=e.src_ip,
                              username=e.username, raw=e.raw))
    db.add_all(new)
    await db.commit()
    await run_detection_engine(db, new)
    return EventIngestResponse(accepted=len(new))

@app.get("/api/events", response_model=List[Event], dependencies=AUTH)
async def list_events(limit: int = Query(50, ge=1, le=500), db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(EventModel).order_by(desc(EventModel.timestamp)).limit(limit))
    return rows.scalars().all()

@app.get("/api/alerts", response_model=List[Alert], dependencies=AUTH)
async def list_alerts(db: AsyncSession = Depends(get_db)):
    rows = await db.execute(select(AlertModel).order_by(desc(AlertModel.last_seen)))
    return [to_alert(a) for a in rows.scalars().all()]

@app.get("/api/alerts/{alert_id}", response_model=AlertDetailResponse, dependencies=AUTH)
async def get_alert_detail(alert_id: str, db: AsyncSession = Depends(get_db)):
    a = await get_alert_or_404(db, alert_id)
    events = sorted(a.events, key=lambda e: e.timestamp)
    return AlertDetailResponse(**to_alert(a).model_dump(), events=[Event.model_validate(e) for e in events])

@app.post("/api/alerts/{alert_id}/analyze", response_model=Alert, dependencies=AUTH)
async def analyze_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    a = await get_alert_or_404(db, alert_id)
    events = [Event.model_validate(e).model_dump(mode="json") for e in sorted(a.events, key=lambda e: e.timestamp)]
    a.ai_analysis = await call_llm_analysis(to_alert(a).model_dump(mode="json", exclude={"ai_analysis"}), events)
    await db.commit()
    return to_alert(a)

@app.post("/api/defenses/apply", response_model=DefenseApplyResponse, dependencies=AUTH)
async def apply_defense(payload: DefenseApplyRequest, db: AsyncSession = Depends(get_db)):
    alert = await get_alert_or_404(db, payload.alert_id)
    run = await RunnerClient().run_defense(payload.defense_id, alert.src_ip)
    if run.get("status") == "success":
        alert.status = "defended"
        alert.applied_defense = payload.defense_id
        await db.commit()
    return DefenseApplyResponse(run_id=run.get("run_id", "unknown"), status=run.get("status", "failed"))

@app.post("/api/verifications", response_model=VerificationResponse, dependencies=AUTH)
async def start_verification(payload: VerificationRequest, background_tasks: BackgroundTasks,
                             db: AsyncSession = Depends(get_db)):
    await get_alert_or_404(db, payload.alert_id)
    vid = str(uuid.uuid4())
    db.add(VerificationModel(verification_id=vid, alert_id=payload.alert_id, result="running"))
    await db.commit()
    background_tasks.add_task(run_verification_pipeline, vid, payload.alert_id, async_session)
    return VerificationResponse(verification_id=vid, status="running")

@app.get("/api/verifications/{verification_id}", response_model=VerificationDetailResponse, dependencies=AUTH)
async def get_verification(verification_id: str, db: AsyncSession = Depends(get_db)):
    v = await db.get(VerificationModel, verification_id)
    if not v:
        raise HTTPException(404, "Verification not found")
    return v

# Serve the dashboard from the same origin (http://localhost:8000/). Must stay last.
_ui = Path(__file__).resolve().parent.parent / "frontend"
if _ui.is_dir():
    app.mount("/", StaticFiles(directory=_ui, html=True), name="ui")
