import time
import logging
from collections import defaultdict
from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import bcrypt

from app.config import settings
from app.database import get_db, SessionLocal
from app.models import User
from app.audit import log_audit

logger = logging.getLogger(__name__)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# In-memory brute force tracker: ip -> [timestamp, timestamp, ...]
_LOGIN_ATTEMPTS = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 900 # 15 minutes

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    # Filter attempts within lockout window
    _LOGIN_ATTEMPTS[ip] = [t for t in _LOGIN_ATTEMPTS[ip] if now - t < LOCKOUT_SECONDS]
    return len(_LOGIN_ATTEMPTS[ip]) >= MAX_ATTEMPTS

def record_failed_attempt(ip: str):
    _LOGIN_ATTEMPTS[ip].append(time.time())

def clear_attempts(ip: str):
    if ip in _LOGIN_ATTEMPTS:
        del _LOGIN_ATTEMPTS[ip]

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except Exception:
        return False

def ensure_admin_user():
    """Ensures default admin user is safely hashed and present in the database."""
    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
        if not admin_user:
            hashed = hash_password(settings.ADMIN_PASSWORD)
            admin_user = User(
                username=settings.ADMIN_USERNAME,
                password_hash=hashed,
                role="admin"
            )
            db.add(admin_user)
            db.commit()
            logger.info(f"Initialized secure '{settings.ADMIN_USERNAME}' account in database.")
    except Exception as e:
        logger.error(f"Error initializing admin user: {e}")
        db.rollback()
    finally:
        db.close()

# Initialize admin on module load
ensure_admin_user()

@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"request": request})

@router.post("/login")
def perform_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"

    if is_rate_limited(client_ip):
        log_audit(db, username, "login_blocked", f"Rate limit triggered from IP {client_ip}", client_ip)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": "Too many failed login attempts. Please wait 15 minutes."}
        )

    clean_user = username.strip()
    user = db.query(User).filter(User.username == clean_user).first()
    
    if user and verify_password(password, user.password_hash):
        clear_attempts(client_ip)
        request.session["user"] = user.username
        request.session["role"] = user.role
        log_audit(db, user.username, "login_success", f"User logged in ({user.role})", client_ip)
        
        # Enforce forced password change if default admin credentials are in use
        if user.username == settings.ADMIN_USERNAME and verify_password("changeme123", user.password_hash):
            request.session["force_password_change"] = True
            return RedirectResponse(url="/change-password", status_code=303)

        return RedirectResponse(url="/", status_code=303)
        
    record_failed_attempt(client_ip)
    log_audit(db, clean_user or "unknown", "login_failure", f"Invalid credentials from IP {client_ip}", client_ip)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request, "error": "Invalid username or password"}
    )

@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html", context={"request": request})

@router.post("/register")
def perform_register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_user = username.strip()

    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"request": request, "error": "Password must be at least 8 characters long."}
        )

    if db.query(User).filter(User.username == clean_user).first():
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"request": request, "error": "Username already exists."}
        )
        
    hashed = hash_password(password)
    new_user = User(username=clean_user, password_hash=hashed, role="analyst")
    db.add(new_user)
    db.commit()
    
    log_audit(db, clean_user, "user_registered", f"New user account registered", client_ip)
    
    # Auto login after register
    request.session["user"] = clean_user
    request.session["role"] = "analyst"
    return RedirectResponse(url="/", status_code=303)

@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    current_user = request.session.get("user", "anonymous")
    log_audit(db, current_user, "logout", "User session ended", client_ip)
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

@router.get("/change-password")
def change_password_page(request: Request):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request=request, 
        name="change_password.html", 
        context={
            "request": request, 
            "username": request.session.get("user"),
            "is_forced": bool(request.session.get("force_password_change"))
        }
    )

@router.post("/change-password")
def perform_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    current_user_name = request.session.get("user")
    if not current_user_name:
        return RedirectResponse(url="/login", status_code=303)

    client_ip = request.client.host if request.client else "127.0.0.1"
    user = db.query(User).filter(User.username == current_user_name).first()

    if not user or not verify_password(current_password, user.password_hash):
        log_audit(db, current_user_name, "password_change_failed", "Incorrect current password", client_ip)
        return templates.TemplateResponse(
            request=request,
            name="change_password.html",
            context={
                "request": request,
                "username": current_user_name,
                "is_forced": bool(request.session.get("force_password_change")),
                "error": "Current password is incorrect."
            }
        )

    if new_password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="change_password.html",
            context={
                "request": request,
                "username": current_user_name,
                "is_forced": bool(request.session.get("force_password_change")),
                "error": "New passwords do not match."
            }
        )

    if len(new_password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="change_password.html",
            context={
                "request": request,
                "username": current_user_name,
                "is_forced": bool(request.session.get("force_password_change")),
                "error": "New password must be at least 8 characters long."
            }
        )

    if new_password.lower() in ["changeme123", "admin", "password", "administrator"]:
        return templates.TemplateResponse(
            request=request,
            name="change_password.html",
            context={
                "request": request,
                "username": current_user_name,
                "is_forced": bool(request.session.get("force_password_change")),
                "error": "New password cannot be a default or easily guessed value."
            }
        )

    user.password_hash = hash_password(new_password)
    db.commit()

    if "force_password_change" in request.session:
        del request.session["force_password_change"]

    log_audit(db, user.username, "password_changed", "User password successfully updated", client_ip)
    return RedirectResponse(url="/", status_code=303)
