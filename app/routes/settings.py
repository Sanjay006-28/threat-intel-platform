import os
import re
import secrets
import urllib.parse
import ipaddress
import math
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple

from fastapi import APIRouter, Request, Depends, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Whitelist, AuditLog, User
from app.config import settings
from app.audit import log_audit
from app.normalizer import detect_and_normalize
from app.notifications import validate_webhook_url, mask_webhook_url, resolve_and_validate_destination
from app.crypto import encrypt_webhook_url, decrypt_webhook_url, get_active_webhook_url

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

def get_or_create_csrf(request: Request) -> str:
    """Retrieves or generates a secure session CSRF token."""
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_hex(32)
        request.session["csrf_token"] = token
    return token

def verify_csrf(request: Request, csrf_token: Optional[str] = None) -> bool:
    """Verifies that the submitted CSRF token matches the authenticated session token."""
    expected = request.session.get("csrf_token")
    if not expected:
        return True  # If session does not have a CSRF token yet
    if csrf_token and secrets.compare_digest(csrf_token, expected):
        return True
    header_csrf = request.headers.get("x-csrf-token")
    if header_csrf and secrets.compare_digest(header_csrf, expected):
        return True
    return False

def parse_expiration(expires_in: Optional[str]) -> Optional[datetime]:
    """Parses relative duration options or ISO timestamps into UTC datetimes."""
    if not expires_in or expires_in in ["never", "none", "permanent", "0", ""]:
        return None
    now = datetime.now(timezone.utc)
    if expires_in == "1":
        return now + timedelta(days=1)
    if expires_in == "7":
        return now + timedelta(days=7)
    if expires_in == "30":
        return now + timedelta(days=30)
    if expires_in == "90":
        return now + timedelta(days=90)
    try:
        dt = datetime.fromisoformat(expires_in.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    return None

def validate_whitelist_policy(typ: str, val: str, desc: str, reason: str) -> Tuple[bool, str, str, str]:
    """
    Validates and normalizes whitelist policies.
    Returns (is_valid, normalized_type, normalized_value, error_message).
    """
    clean_val = (val or "").strip()
    clean_type = (typ or "").lower().strip()
    clean_desc = (desc or "").strip()
    clean_reason = (reason or "").strip()

    if not clean_val:
        return False, clean_type, clean_val, "Indicator value is required."

    if not clean_desc or len(clean_desc) < 3:
        return False, clean_type, clean_val, "A meaningful description (at least 3 characters) is required."

    if not clean_reason or len(clean_reason) < 3:
        return False, clean_type, clean_val, "A clear justification/reason (at least 3 characters) is required."

    if clean_type in ["ipv4", "ip"]:
        try:
            ip = ipaddress.IPv4Address(clean_val)
            return True, "ipv4", str(ip), ""
        except ValueError:
            return False, clean_type, clean_val, f"Invalid IPv4 address format: '{clean_val}'."

    elif clean_type == "ipv6":
        try:
            ip = ipaddress.IPv6Address(clean_val)
            return True, "ipv6", str(ip), ""
        except ValueError:
            return False, clean_type, clean_val, f"Invalid IPv6 address format: '{clean_val}'."

    elif clean_type == "cidr":
        try:
            net = ipaddress.ip_network(clean_val, strict=False)
            # Broad CIDR protection: prefix < 16 for IPv4, < 48 for IPv6
            if net.version == 4 and net.prefixlen < 16:
                return False, clean_type, clean_val, f"Dangerously broad IPv4 CIDR /{net.prefixlen}. Subnets must be /16 or narrower (e.g. /24, /16) to prevent accidental global alert suppression."
            if net.version == 6 and net.prefixlen < 48:
                return False, clean_type, clean_val, f"Dangerously broad IPv6 CIDR /{net.prefixlen}. Subnets must be /48 or narrower."
            return True, "cidr", str(net), ""
        except ValueError:
            return False, clean_type, clean_val, f"Invalid CIDR network format: '{clean_val}'."

    elif clean_type == "domain":
        domain_str = clean_val.lower().rstrip(".")
        if "://" in domain_str or "/" in domain_str or ":" in domain_str:
            return False, clean_type, clean_val, f"Invalid domain: '{clean_val}'. Domains must not include protocols (http://), ports, or paths."
        pattern = r"^(?=.{1,253}$)(?:(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
        if not re.match(pattern, domain_str) and not domain_str.endswith(".local") and not domain_str.endswith(".internal"):
            return False, clean_type, clean_val, f"Invalid domain syntax: '{clean_val}'."
        return True, "domain", domain_str, ""

    elif clean_type == "url":
        url_lower = clean_val.strip()
        if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
            return False, clean_type, clean_val, f"Invalid URL: '{clean_val}'. Must begin with http:// or https://."
        try:
            parsed = urllib.parse.urlparse(url_lower)
            if not parsed.netloc:
                return False, clean_type, clean_val, f"Invalid URL: missing host destination in '{clean_val}'."
            return True, "url", url_lower, ""
        except Exception:
            return False, clean_type, clean_val, f"Malformed URL format: '{clean_val}'."

    elif clean_type in ["md5", "sha1", "sha256", "hash"]:
        hex_val = clean_val.lower()
        if clean_type == "md5":
            if not re.match(r"^[a-f0-9]{32}$", hex_val):
                return False, clean_type, clean_val, "Invalid MD5 hash: must be exactly 32 hexadecimal characters."
            return True, "md5", hex_val, ""
        elif clean_type == "sha1":
            if not re.match(r"^[a-f0-9]{40}$", hex_val):
                return False, clean_type, clean_val, "Invalid SHA-1 hash: must be exactly 40 hexadecimal characters."
            return True, "sha1", hex_val, ""
        elif clean_type == "sha256":
            if not re.match(r"^[a-f0-9]{64}$", hex_val):
                return False, clean_type, clean_val, "Invalid SHA-256 hash: must be exactly 64 hexadecimal characters."
            return True, "sha256", hex_val, ""
        else: # generic hash
            if len(hex_val) == 32 and re.match(r"^[a-f0-9]{32}$", hex_val):
                return True, "md5", hex_val, ""
            elif len(hex_val) == 40 and re.match(r"^[a-f0-9]{40}$", hex_val):
                return True, "sha1", hex_val, ""
            elif len(hex_val) == 64 and re.match(r"^[a-f0-9]{64}$", hex_val):
                return True, "sha256", hex_val, ""
            else:
                return False, clean_type, clean_val, "Invalid hash format: must be valid MD5 (32-char), SHA-1 (40-char), or SHA-256 (64-char)."

    elif clean_type == "email":
        email_str = clean_val.lower()
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email_str):
            return False, clean_type, clean_val, f"Invalid email format: '{clean_val}'."
        return True, "email", email_str, ""

    else:
        norm_type, norm_val = detect_and_normalize(clean_val, is_feed_ioc=False)
        if norm_val:
            return True, norm_type or clean_type, norm_val, ""
        return False, clean_type, clean_val, f"Unsupported or unrecognizable indicator type: '{clean_type}'."

@router.get("/settings")
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    csrf_token = get_or_create_csrf(request)
    whitelist = db.query(Whitelist).filter(Whitelist.is_deleted == False).order_by(Whitelist.id.desc()).all()
    current_webhook = get_active_webhook_url()
    masked_webhook = mask_webhook_url(current_webhook)
    now = datetime.now(timezone.utc)
    
    policies_data = []
    for p in whitelist:
        exp = p.expires_at.replace(tzinfo=timezone.utc) if p.expires_at and p.expires_at.tzinfo is None else p.expires_at
        is_expired = exp is not None and exp <= now
        if not p.is_active:
            status_label = "DISABLED"
            badge_class = "bg-secondary text-light"
        elif is_expired:
            status_label = "EXPIRED"
            badge_class = "bg-danger text-light"
        else:
            status_label = "ACTIVE"
            badge_class = "bg-success text-light"
            
        policies_data.append({
            "id": p.id,
            "type": p.type,
            "value": p.value,
            "description": p.description,
            "reason": p.reason,
            "is_active": p.is_active,
            "created_by": p.created_by or "system",
            "status_label": status_label,
            "badge_class": badge_class,
            "is_expired": is_expired,
            "expires_display": exp.strftime("%Y-%m-%d %H:%M UTC") if exp else "Permanent",
            "created_display": p.created_at.strftime("%Y-%m-%d %H:%M UTC") if p.created_at else "--",
        })

    msg = request.query_params.get("msg", "")
    err = request.query_params.get("err", "")
    
    # Complete secrets are strictly excluded from template context to prevent HTML exposure
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "whitelist_items": policies_data,
            "whitelist": whitelist,
            "webhook_url": masked_webhook,
            "masked_webhook_url": masked_webhook,
            "csrf_token": csrf_token,
            "current_user": user,
            "success_msg": msg,
            "error_msg": err
        }
    )

@router.post("/settings/webhook")
def save_webhook(
    request: Request,
    webhook_url: str = Form(""),
    csrf_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if not verify_csrf(request, csrf_token):
        encoded_err = urllib.parse.quote("CSRF validation failed. Please refresh the page and try again.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    client_ip = request.client.host if request.client else "127.0.0.1"
    clean_url = (webhook_url or "").strip()
    current_active = get_active_webhook_url()

    # Case 1: Masking preservation - blank input or submission with masked placeholder
    # Retains the existing stored secret without destruction or overwrite
    if not clean_url or "********" in clean_url:
        if current_active:
            encoded_msg = urllib.parse.quote("Existing webhook secret retained.")
            return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)
        else:
            encoded_err = urllib.parse.quote("No webhook URL provided.")
            return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    # Case 2: Operator explicitly requests to clear or disable the webhook
    if clean_url.upper() in ["CLEAR", "NONE", "REMOVE", "DELETE", "DISABLE"]:
        settings.ALERT_WEBHOOK_URL = ""
        settings.ALERT_WEBHOOK_URL_ENCRYPTED = ""
        if "webhook_url" in request.session:
            request.session.pop("webhook_url", None)

        env_path = ".env"
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                new_lines = [l for l in lines if not l.startswith("ALERT_WEBHOOK_URL=") and not l.startswith("ALERT_WEBHOOK_URL_ENCRYPTED=")]
                with open(env_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
            except Exception:
                pass

        log_audit(db, user, "settings_webhook_updated", "Webhook destination cleared / removed", client_ip)
        encoded_msg = urllib.parse.quote("Webhook configuration cleared successfully.")
        return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

    # Case 3: New webhook destination submitted - validate with SSRF & DNS rebinding protection
    is_valid, err_msg, _ = resolve_and_validate_destination(clean_url)
    if not is_valid:
        encoded_err = urllib.parse.quote(f"Webhook rejected: {err_msg}")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    # Encrypt the webhook URL at rest with authenticated Fernet encryption
    encrypted_token = encrypt_webhook_url(clean_url)
    settings.ALERT_WEBHOOK_URL_ENCRYPTED = encrypted_token
    settings.ALERT_WEBHOOK_URL = clean_url

    # Persist encrypted ciphertext into .env (purge any legacy plaintext)
    env_path = ".env"
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = []
            found = False
            for line in lines:
                if line.startswith("ALERT_WEBHOOK_URL_ENCRYPTED="):
                    new_lines.append(f"ALERT_WEBHOOK_URL_ENCRYPTED={encrypted_token}\n")
                    found = True
                elif line.startswith("ALERT_WEBHOOK_URL="):
                    continue  # Purge plaintext
                else:
                    new_lines.append(line)
            if not found:
                new_lines.append(f"ALERT_WEBHOOK_URL_ENCRYPTED={encrypted_token}\n")
            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception:
            pass

    masked = mask_webhook_url(clean_url)
    log_audit(db, user, "settings_webhook_updated", f"Webhook destination updated: {masked}", client_ip)
    encoded_msg = urllib.parse.quote("Webhook configuration saved successfully with authenticated encryption at rest.")
    return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

@router.post("/settings/whitelist/add")
def add_whitelist(
    request: Request,
    type: str = Form(...),
    value: str = Form(...),
    description: str = Form(""),
    reason: str = Form(""),
    expires_in: str = Form("never"),
    csrf_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if not verify_csrf(request, csrf_token):
        encoded_err = urllib.parse.quote("CSRF validation failed. Please refresh the page and try again.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    client_ip = request.client.host if request.client else "127.0.0.1"

    is_valid, norm_type, norm_val, err_msg = validate_whitelist_policy(type, value, description, reason)
    if not is_valid:
        encoded_err = urllib.parse.quote(err_msg)
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    exp_dt = parse_expiration(expires_in)
    now = datetime.now(timezone.utc)

    # Check for existing records (handle unique constraint safely)
    existing = db.query(Whitelist).filter(Whitelist.value == norm_val).first()
    if existing:
        if not existing.is_deleted:
            encoded_err = urllib.parse.quote(f"An active whitelist policy for '{norm_val}' already exists (Policy #{existing.id}).")
            return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)
        
        # Reactivate soft-deleted policy
        existing.is_deleted = False
        existing.is_active = True
        existing.type = norm_type
        existing.description = description.strip()
        existing.reason = reason.strip()
        existing.created_by = user
        existing.updated_at = now
        existing.expires_at = exp_dt
        db.commit()
        log_audit(db, user, "whitelist_created", f"Reactivated whitelist policy #{existing.id} for {norm_type} [{norm_val}]. Reason: {reason.strip()}", client_ip)
        encoded_msg = urllib.parse.quote(f"Whitelist policy for '{norm_val}' restored and updated.")
        return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

    # Create brand new policy
    entry = Whitelist(
        type=norm_type,
        value=norm_val,
        description=description.strip(),
        reason=reason.strip(),
        is_active=True,
        is_deleted=False,
        created_by=user,
        created_at=now,
        updated_at=now,
        expires_at=exp_dt
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    log_audit(db, user, "whitelist_created", f"Added {norm_type} [{norm_val}] (Policy #{entry.id}) to whitelist. Reason: {reason.strip()}", client_ip)
    encoded_msg = urllib.parse.quote(f"Whitelist policy #{entry.id} created successfully.")
    return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

@router.post("/settings/whitelist/{id}/edit")
def edit_whitelist(
    request: Request,
    id: int,
    description: str = Form(...),
    reason: str = Form(...),
    expires_in: str = Form("keep"),
    csrf_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if not verify_csrf(request, csrf_token):
        encoded_err = urllib.parse.quote("CSRF validation failed. Please refresh the page and try again.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    client_ip = request.client.host if request.client else "127.0.0.1"

    entry = db.query(Whitelist).filter(Whitelist.id == id, Whitelist.is_deleted == False).first()
    if not entry:
        encoded_err = urllib.parse.quote("Whitelist policy not found.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    clean_desc = description.strip()
    clean_reason = reason.strip()
    if not clean_desc or len(clean_desc) < 3 or not clean_reason or len(clean_reason) < 3:
        encoded_err = urllib.parse.quote("Description and justification must each be at least 3 characters.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    entry.description = clean_desc
    entry.reason = clean_reason
    entry.updated_at = datetime.now(timezone.utc)

    if expires_in != "keep":
        entry.expires_at = parse_expiration(expires_in)

    db.commit()
    log_audit(db, user, "whitelist_updated", f"Updated policy #{entry.id} ({entry.type}: {entry.value})", client_ip)
    encoded_msg = urllib.parse.quote(f"Whitelist policy #{entry.id} updated.")
    return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

@router.post("/settings/whitelist/{id}/toggle")
def toggle_whitelist(
    request: Request,
    id: int,
    csrf_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if not verify_csrf(request, csrf_token):
        encoded_err = urllib.parse.quote("CSRF validation failed. Please refresh the page and try again.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    client_ip = request.client.host if request.client else "127.0.0.1"

    entry = db.query(Whitelist).filter(Whitelist.id == id, Whitelist.is_deleted == False).first()
    if not entry:
        encoded_err = urllib.parse.quote("Whitelist policy not found.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    entry.is_active = not entry.is_active
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()

    action = "whitelist_activated" if entry.is_active else "whitelist_deactivated"
    log_audit(db, user, action, f"Policy #{entry.id} ({entry.value}) changed to {'Active' if entry.is_active else 'Disabled'}", client_ip)
    
    state_word = "enabled" if entry.is_active else "disabled"
    encoded_msg = urllib.parse.quote(f"Policy #{entry.id} has been {state_word}.")
    return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

@router.post("/settings/whitelist/{id}/delete")
def delete_whitelist(
    request: Request,
    id: int,
    csrf_token: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if not verify_csrf(request, csrf_token):
        encoded_err = urllib.parse.quote("CSRF validation failed. Please refresh the page and try again.")
        return RedirectResponse(url=f"/settings?err={encoded_err}", status_code=303)

    client_ip = request.client.host if request.client else "127.0.0.1"

    entry = db.query(Whitelist).filter(Whitelist.id == id, Whitelist.is_deleted == False).first()
    if entry:
        entry.is_deleted = True
        entry.is_active = False
        entry.updated_at = datetime.now(timezone.utc)
        db.commit()
        log_audit(db, user, "whitelist_deleted", f"Soft-deleted whitelist policy #{entry.id} ({entry.type}: {entry.value})", client_ip)
        encoded_msg = urllib.parse.quote(f"Whitelist policy #{id} removed from active suppression.")
        return RedirectResponse(url=f"/settings?msg={encoded_msg}", status_code=303)

    return RedirectResponse(url="/settings", status_code=303)

# Synonymous route for backwards compatibility
@router.post("/settings/whitelist/remove/{id}")
def remove_whitelist(request: Request, id: int, csrf_token: Optional[str] = Form(None), db: Session = Depends(get_db)):
    return delete_whitelist(request, id, csrf_token, db)

def parse_audit_date(date_str: Optional[str], is_end: bool = False) -> Optional[datetime]:
    """Parses date/datetime strings from filter inputs into datetime objects."""
    if not date_str:
        return None
    clean = date_str.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(clean, fmt)
            if fmt == "%Y-%m-%d" and is_end:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            return dt
        except ValueError:
            pass
    return None

def sanitize_audit_detail(text: Optional[str]) -> str:
    """Masks secret tokens, passwords, and sensitive keys from audit log detail strings."""
    if not text:
        return "--"
    sanitized = re.sub(
        r'(https?://[^\s/]+/api/webhooks/[^/\s]+/)[\w\-]+',
        r'\1********',
        text
    )
    sanitized = re.sub(
        r'(Bearer\s+)[\w\-\.]{12,}',
        r'\1********',
        sanitized,
        flags=re.IGNORECASE
    )
    sanitized = re.sub(
        r'((?:password|token|api_key|secret|apikey)\s*[:=]\s*)([^\s&,]+)',
        r'\1********',
        sanitized,
        flags=re.IGNORECASE
    )
    return sanitized

@router.get("/audit-logs")
def audit_logs_page(request: Request, db: Session = Depends(get_db)):
    # 1. Require authentication
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    # 2. Extract and sanitize query parameters
    q = request.query_params.get("q", "").strip()
    selected_user = request.query_params.get("user", "").strip()
    selected_action = request.query_params.get("action", "").strip()
    start_date_str = request.query_params.get("start_date", "").strip()
    end_date_str = request.query_params.get("end_date", "").strip()
    client_ip = request.query_params.get("client_ip", "").strip()

    try:
        per_page = int(request.query_params.get("per_page", 25))
        if per_page not in [25, 50, 100]:
            per_page = 25
    except (ValueError, TypeError):
        per_page = 25

    try:
        page = int(request.query_params.get("page", 1))
        if page < 1:
            page = 1
    except (ValueError, TypeError):
        page = 1

    # 3. Dynamically populate available filter values
    audit_users = [u[0] for u in db.query(AuditLog.user).distinct().all() if u[0]]
    db_users = [u[0] for u in db.query(User.username).all() if u[0]]
    available_users = sorted(list(set(audit_users + db_users + ["admin", "system"])))

    available_actions = sorted([a[0] for a in db.query(AuditLog.action).distinct().all() if a[0]])

    # 4. Construct parameterized read-only query
    query = db.query(AuditLog)

    # Search filter (case-insensitive across action, details, user, ip_address, and integer IDs)
    if q:
        search_clauses = [
            AuditLog.action.ilike(f"%{q}%"),
            AuditLog.details.ilike(f"%{q}%"),
            AuditLog.user.ilike(f"%{q}%"),
            AuditLog.ip_address.ilike(f"%{q}%")
        ]
        clean_num = q.lstrip("#").strip()
        if clean_num.isdigit():
            search_clauses.append(AuditLog.id == int(clean_num))
        query = query.filter(or_(*search_clauses))

    # User filter
    if selected_user and selected_user.lower() != "all":
        query = query.filter(AuditLog.user == selected_user)

    # Action filter
    if selected_action and selected_action.lower() != "all":
        query = query.filter(AuditLog.action == selected_action)

    # Client IP filter
    if client_ip:
        query = query.filter(AuditLog.ip_address.ilike(f"%{client_ip}%"))

    # Date range filters
    start_dt = parse_audit_date(start_date_str, is_end=False)
    if start_dt:
        query = query.filter(AuditLog.timestamp >= start_dt)

    end_dt = parse_audit_date(end_date_str, is_end=True)
    if end_dt:
        query = query.filter(AuditLog.timestamp <= end_dt)

    # 5. Database-side pagination without arbitrary 200 record caps
    total_records = query.count()
    total_pages = max(1, math.ceil(total_records / per_page))
    if page > total_pages and total_records > 0:
        page = total_pages

    # Deterministic newest-first sort by timestamp desc and id desc
    offset = (page - 1) * per_page
    logs_raw = query.order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).offset(offset).limit(per_page).all()

    # Sanitize logs for presentation to guarantee credentials are never exposed
    sanitized_logs = []
    for log in logs_raw:
        sanitized_logs.append({
            "id": log.id,
            "timestamp": log.timestamp,
            "user": log.user,
            "action": log.action,
            "details": sanitize_audit_detail(log.details),
            "ip_address": log.ip_address or "127.0.0.1"
        })

    # 6. Active filter preservation URL generator
    def build_page_url(p: int) -> str:
        params = {}
        if q:
            params["q"] = q
        if selected_user and selected_user.lower() != "all":
            params["user"] = selected_user
        if selected_action and selected_action.lower() != "all":
            params["action"] = selected_action
        if start_date_str:
            params["start_date"] = start_date_str
        if end_date_str:
            params["end_date"] = end_date_str
        if client_ip:
            params["client_ip"] = client_ip
        if per_page != 25:
            params["per_page"] = per_page
        params["page"] = p
        return f"/audit-logs?{urllib.parse.urlencode(params)}"

    prev_page_url = build_page_url(page - 1) if page > 1 else None
    next_page_url = build_page_url(page + 1) if page < total_pages else None

    # Calculate active filter count for UI badge
    active_filters_count = 0
    if q:
        active_filters_count += 1
    if selected_user and selected_user.lower() != "all":
        active_filters_count += 1
    if selected_action and selected_action.lower() != "all":
        active_filters_count += 1
    if start_date_str:
        active_filters_count += 1
    if end_date_str:
        active_filters_count += 1
    if client_ip:
        active_filters_count += 1

    # Numeric page links window (up to 5 pages around current page)
    start_p = max(1, page - 2)
    end_p = min(total_pages, start_p + 4)
    if end_p - start_p < 4:
        start_p = max(1, end_p - 4)
    page_numbers = [
        {"num": p, "url": build_page_url(p), "is_current": p == page}
        for p in range(start_p, end_p + 1)
    ]

    return templates.TemplateResponse(
        request=request,
        name="audit_logs.html",
        context={
            "request": request,
            "audit_logs": sanitized_logs,
            "total_records": total_records,
            "current_page": page,
            "total_pages": total_pages,
            "per_page": per_page,
            "prev_page_url": prev_page_url,
            "next_page_url": next_page_url,
            "page_numbers": page_numbers,
            "available_users": available_users,
            "available_actions": available_actions,
            "current_filters": {
                "q": q,
                "user": selected_user,
                "action": selected_action,
                "start_date": start_date_str,
                "end_date": end_date_str,
                "client_ip": client_ip,
                "per_page": per_page
            },
            "active_filters_count": active_filters_count
        }
    )
