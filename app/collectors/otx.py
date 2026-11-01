import logging
import requests
from typing import List, Dict, Any
from app.collectors.base import BaseCollector
from app.config import settings

logger = logging.getLogger(__name__)

class OTXCollector(BaseCollector):
    def __init__(self):
        super().__init__("AlienVault_OTX", 360)

    def fetch(self) -> List[Dict[str, Any]]:
        api_key = settings.OTX_API_KEY
        if not api_key or "your_otx" in api_key.lower():
            logger.info("[*] AlienVault OTX skipped: No API key provided.")
            return []

        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": api_key}
        records = []
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            for pulse in data.get("results", []):
                for ind in pulse.get("indicators", []):
                    records.append({
                        "raw_value": ind.get("indicator"),
                        "confidence": 70, # Default confidence for OTX
                        "tags": pulse.get("tags", []),
                        "description": pulse.get("name", "")
                    })
            return records
        except Exception as e:
            logger.error(f"[!] AlienVault OTX fetch failed: {e}")
            raise
