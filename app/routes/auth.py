from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import bcrypt
from app.config import settings
from app.database import get_db
from app.models import User

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except Exception:
        return False

@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"request": request})

@router.post("/login")
def perform_login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    # Fallback to .env admin
    if username == settings.ADMIN_USERNAME and password == settings.ADMIN_PASSWORD:
        request.session["user"] = username
        return RedirectResponse(url="/", status_code=303)
        
    # Check DB
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.password_hash):
        request.session["user"] = username
        return RedirectResponse(url="/", status_code=303)
        
    return templates.TemplateResponse(request=request, name="login.html", context={"request": request, "error": "Invalid credentials"})

@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html", context={"request": request})

@router.post("/register")
def perform_register(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == username).first() or username == settings.ADMIN_USERNAME:
        return templates.TemplateResponse(request=request, name="register.html", context={"request": request, "error": "Username already exists"})
        
    hashed = hash_password(password)
    new_user = User(username=username, password_hash=hashed)
    db.add(new_user)
    db.commit()
    
    # Auto login after register
    request.session["user"] = username
    return RedirectResponse(url="/", status_code=303)

@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

