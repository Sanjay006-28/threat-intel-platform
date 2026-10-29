import logging
import requests
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger(__name__)

def send_alert_webhook(
    alert_id: int,
    matched_value: str,
    matched_type: str,
    severity: str,
    score: int,
    webhook_url: Optional[str] = None
) -> bool:
    """
    Sends an automated alert notification to a Discord, Slack, or generic HTTP webhook.
    """
    url = webhook_url or getattr(settings, "ALERT_WEBHOOK_URL", "")
    if not url:
        logger.info(f"[Notification] Alert #{alert_id} ({severity.upper()}) detected: {matched_value} (No webhook configured).")
        return False

    # Discord / Slack compatible payload format
    payload = {
        "username": "SENTINEL Threat Intel",
        "avatar_url": "https://img.icons8.com/color/96/shield.png",
        "content": f"🚨 **CRITICAL SECURITY ALERT DETECTED** 🚨",
        "embeds": [
            {
                "title": f"Incident #{alert_id}: {matched_type.upper()} Malicious Match",
                "description": f"The correlation engine detected communication with a confirmed threat indicator.",
                "color": 15158332 if severity == "critical" else 15105570,
                "fields": [
                    {"name": "Threat Indicator", "value": f"`{matched_value}`", "inline": True},
                    {"name": "Severity", "value": f"**{severity.upper()}**", "inline": True},
                    {"name": "Score", "value": f"{score}/100", "inline": True},
                    {"name": "Action Required", "value": "Review alert console and deploy firewall containment.", "inline": False}
                ],
                "footer": {"text": "SENTINEL // Cyber Threat Intelligence Console"}
            }
        ]
    }

    try:
        resp = requests.post(url, json=payload, timeout=4.0)
        if resp.status_code in [200, 204]:
            logger.info(f"[+] Webhook alert delivered successfully for Alert #{alert_id}.")
            return True
        else:
            logger.warning(f"[!] Webhook delivery failed with status {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"[!] Webhook error: {e}")
        return False
