import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import engine, Base
from app.config import settings
from app.watcher import AutoIngestWatcher

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Create tables
from app import models
Base.metadata.create_all(bind=engine)

watcher = AutoIngestWatcher()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SENTINEL Threat Intel Platform...")
    # Start auto-ingestion directory watcher
    try:
        watcher.start()
    except Exception as e:
        logger.warning(f"Could not start directory watcher: {e}")
        
    yield
    
    logger.info("Shutting down SENTINEL...")
    try:
        watcher.stop()
    except Exception:
        pass

app = FastAPI(title="SENTINEL Threat Intel & IOC Correlation Platform", lifespan=lifespan)

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow static files through
        if request.url.path.startswith("/static"):
            return await call_next(request)

        # In dev mode with auto-login enabled:
        if settings.DEV_AUTO_LOGIN:
            if not request.session.get("user"):
                request.session["user"] = settings.ADMIN_USERNAME
            return await call_next(request)

        # In production mode: enforce authentication
        allowed_paths = ["/login", "/register"]
        if not request.session.get("user") and request.url.path not in allowed_paths:
            return RedirectResponse(url="/login")

        return await call_next(request)

# Middlewares (reverse order of execution)
app.add_middleware(AuthMiddleware)
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

from app.routes import dashboard, iocs, feeds, logs, alerts, lookup, auth, settings as settings_routes

# Routes
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(iocs.router)
app.include_router(feeds.router)
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(lookup.router)
app.include_router(settings_routes.router)
