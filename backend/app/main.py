import os
import threading
import time
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.db import engine, Base, SessionLocal
from app.api import auth, alerts, stats, rules, simulation, reports, audit
from app.services.snort_parser import parse_snort_alert_line
from app.models.alert import Alert

# Initialize Database Tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Network Intrusion Detection System (NIDS) using Snort for Ethical Hacking & Cybersecurity"
)

# Enable CORS for development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Set up Template rendering and Static files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")
TEMPLATES_DIR = os.path.join(FRONTEND_DIR, "templates")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Include API Routers under /api
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(stats.router, prefix=settings.API_V1_STR)
app.include_router(rules.router, prefix=settings.API_V1_STR)
app.include_router(simulation.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(audit.router, prefix=settings.API_V1_STR)

# --- Frontend Page Routes ---

@app.get("/", response_class=HTMLResponse)
def page_dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html", {"title": "SOC Dashboard"})

@app.get("/alerts-page", response_class=HTMLResponse)
def page_alerts(request: Request):
    return templates.TemplateResponse(request, "alerts.html", {"title": "Alert Investigation"})

@app.get("/rules-page", response_class=HTMLResponse)
def page_rules(request: Request):
    return templates.TemplateResponse(request, "rules.html", {"title": "Snort Rules"})

@app.get("/simulator-page", response_class=HTMLResponse)
def page_simulator(request: Request):
    return templates.TemplateResponse(request, "simulator.html", {"title": "Lab Attack Simulator"})

@app.get("/reports-page", response_class=HTMLResponse)
def page_reports(request: Request):
    return templates.TemplateResponse(request, "reports.html", {"title": "Security Reports"})

@app.get("/login", response_class=HTMLResponse)
def page_login(request: Request):
    return templates.TemplateResponse(request, "login.html", {"title": "SOC Login"})

# --- Background Snort Log File Listener ---
def snort_log_listener():
    """Background worker to tail snort.alert file and insert live alerts."""
    alert_file = settings.SNORT_ALERT_FILE
    if not os.path.exists(alert_file):
        try:
            with open(alert_file, "w") as f:
                f.write("# Snort Alert Log File initialized\n")
        except Exception:
            return

    try:
        with open(alert_file, "r") as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1.5)
                    continue
                
                alert_dict = parse_snort_alert_line(line)
                if alert_dict:
                    db = SessionLocal()
                    try:
                        # Check duplicate
                        exists = db.query(Alert).filter(Alert.raw_alert == alert_dict["raw_alert"]).first()
                        if not exists:
                            alert = Alert(**alert_dict)
                            db.add(alert)
                            db.commit()
                    except Exception:
                        db.rollback()
                    finally:
                        db.close()
    except Exception as e:
        print(f"Snort log listener encountered note: {e}")

@app.on_event("startup")
def startup_event():
    # Start background Snort log listener thread
    t = threading.Thread(target=snort_log_listener, daemon=True)
    t.start()
