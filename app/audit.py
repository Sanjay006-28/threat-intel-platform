import logging
from sqlalchemy.orm import Session
from app.models import AuditLog

logger = logging.getLogger(__name__)

def log_audit(db: Session, user: str, action: str, details: str = "", ip_address: str = None) -> None:
    """
    Records an auditable security or operational event in the database.
    """
    try:
        entry = AuditLog(
            user=user or "anonymous",
            action=action,
            details=details,
            ip_address=ip_address
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to record audit log: {e}")
        try:
            db.rollback()
        except Exception:
            pass

