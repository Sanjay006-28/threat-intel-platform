from abc import ABC, abstractmethod
from typing import List, Dict, Any
from app.normalizer import detect_and_normalize

class BaseCollector(ABC):
    """
    Base interface for IOC collectors.
    """
    def __init__(self, feed_name: str, interval_minutes: int = 360):
        self.feed_name = feed_name
        self.interval_minutes = interval_minutes

    @abstractmethod
    def fetch(self) -> List[Dict[str, Any]]:
        """
        Fetches data from the threat intel source.
        Returns a list of dicts with at least 'raw_value' and optionally 'tags', 'confidence', 'description'.
        """
        pass

    def normalize_records(self, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalizes fetched records using the normalizer.
        Sets is_feed_ioc=True to reject RFC1918/loopback ranges.
        """
        normalized = []
        seen = set()
        for rec in raw_records:
            raw_val = rec.get("raw_value")
            if not raw_val:
                continue
            
            ioc_type, norm_val = detect_and_normalize(raw_val, is_feed_ioc=True)
            if not ioc_type or not norm_val:
                continue
                
            dedupe_key = (ioc_type, norm_val)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            
            normalized.append({
                "type": ioc_type,
                "value": norm_val,
                "confidence": rec.get("confidence", 50),
                "tags": rec.get("tags", []),
                "description": rec.get("description", ""),
                "feed_name": self.feed_name,
                "reference_url": rec.get("reference_url", "")
            })
        return normalized
