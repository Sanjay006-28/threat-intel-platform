import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.database import engine, Base, apply_schema_migrations
from app.config import settings
from app.watcher import AutoIngestWatcher
from app.collectors.runner import run_all_collectors, expire_stale_iocs
from app import models

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Ensure database tables exist and apply backwards-compatible migrations safely
Base.metadata.create_all(bind=engine)
apply_schema_migrations(engine)

watcher = AutoIngestWatcher()
scheduler = AsyncIOScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SENTINEL Threat Intel Platform...")
    
    # 1. Initialize default admin account safely in DB
    try:
        from app.routes.auth import ensure_admin_user
        ensure_admin_user()
    except Exception as e:
        logger.warning(f"Admin initialization notice: {e}")

    # 2. Start directory auto-ingestion watcher daemon
    try:
        watcher.start()
    except Exception as e:
        logger.warning(f"Could not start directory watcher: {e}")

    # 3. Start APScheduler for automated threat intelligence & IOC lifecycle
    try:
        # Schedule recurring threat feed sync (default: every 6 hours)
        scheduler.add_job(
            run_all_collectors,
            "interval",
            minutes=settings.SCHEDULER_INTERVAL_MINUTES,
            id="feed_collector_sync",
            replace_existing=True,
            max_instances=1
        )
        # Schedule daily IOC expiration and deactivation
        scheduler.add_job(
            expire_stale_iocs,
            "interval",
            hours=24,
            id="ioc_expiration_cleanup",
            replace_existing=True,
            max_instances=1
        )
        scheduler.start()
        logger.info(f"[+] Automated Feed Scheduler active (Sync interval: {settings.SCHEDULER_INTERVAL_MINUTES} mins, TTL: {settings.IOC_TTL_DAYS} days).")
    except Exception as e:
        logger.warning(f"Could not start background scheduler: {e}")
        
    yield
    
    logger.info("Shutting down SENTINEL...")
    try:
        scheduler.shutdown(wait=False)
    except Exception:
        pass

    try:
        watcher.stop()
    except Exception:
        pass

app = FastAPI(title="SENTINEL Threat Intel & IOC Correlation Platform", lifespan=lifespan)

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow static assets
        if request.url.path.startswith("/static"):
            return await call_next(request)

        # Allow public authentication endpoints
        allowed_paths = ["/login", "/register", "/logout"]
        if request.url.path in allowed_paths:
            return await call_next(request)

        # Dev auto-login fallback only if explicitly enabled
        if settings.DEV_AUTO_LOGIN:
            if not request.session.get("user"):
                request.session["user"] = settings.ADMIN_USERNAME
                request.session["role"] = "admin"
            return await call_next(request)

        # Enforce authenticated session
        if not request.session.get("user"):
            if request.url.path.startswith("/api/"):
                return JSONResponse(status_code=401, content={"detail": "Authentication required"})
            return RedirectResponse(url="/login", status_code=303)

        # Enforce forced first-login password change for default credentials
        if request.session.get("force_password_change"):
            if request.url.path != "/change-password":
                return RedirectResponse(url="/change-password", status_code=303)

        return await call_next(request)

# Middlewares
app.add_middleware(AuthMiddleware)
app.add_middleware(
    SessionMiddleware, 
    secret_key=settings.SECRET_KEY,
    max_age=settings.SESSION_MAX_AGE_SECONDS,
    same_site="lax"
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

from app.routes import (
    dashboard, iocs, feeds, logs, alerts, lookup, auth, 
    settings as settings_routes, incidents
)

# Register routes
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(iocs.router)
app.include_router(feeds.router)
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(lookup.router)
app.include_router(settings_routes.router)
