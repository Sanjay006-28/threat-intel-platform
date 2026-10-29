import csv
import json
import requests
from typing import List, Dict, Any
from app.collectors.base import BaseCollector

class ThreatFoxCollector(BaseCollector):
    def __init__(self):
        super().__init__("ThreatFox", 360)

    def fetch(self) -> List[Dict[str, Any]]:
        url = "https://threatfox.abuse.ch/export/json/recent/"
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            records = []
            for item in data.values():
                if isinstance(item, list):
                    for entry in item:
                        records.append({
                            "raw_value": entry.get("ioc_value"),
                            "confidence": entry.get("confidence_level", 50),
                            "tags": [entry.get("threat_type")],
                            "description": entry.get("malware_printable", "")
                        })
            return records
        except Exception as e:
            print(f"[!] ThreatFox fetch failed: {e}")
            return []

class URLhausCollector(BaseCollector):
    def __init__(self):
        super().__init__("URLhaus", 360)

    def fetch(self) -> List[Dict[str, Any]]:
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        records = []
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            reader = csv.reader([line for line in lines if not line.startswith('#')])
            for row in reader:
                if len(row) > 2:
                    records.append({
                        "raw_value": row[2], # url
                        "confidence": 85,
                        "tags": row[4].split(",") if len(row) > 4 else ["malware"],
                        "description": "URLhaus payload delivery"
                    })
            return records
        except Exception as e:
            print(f"[!] URLhaus fetch failed: {e}")
            return []

class FeodoTrackerCollector(BaseCollector):
    def __init__(self):
        super().__init__("FeodoTracker", 360)

    def fetch(self) -> List[Dict[str, Any]]:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            records = []
            for item in resp.json():
                records.append({
                    "raw_value": item.get("ip_address"),
                    "confidence": 95,
                    "tags": ["botnet", item.get("malware")],
                    "description": f"Feodo C2"
                })
            return records
        except Exception as e:
            print(f"[!] FeodoTracker fetch failed: {e}")
            return []

class MalwareBazaarCollector(BaseCollector):
    def __init__(self):
        super().__init__("MalwareBazaar", 360)

    def fetch(self) -> List[Dict[str, Any]]:
        url = "https://bazaar.abuse.ch/export/csv/recent/"
        records = []
        try:
            resp = requests.get(url, timeout=20)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            reader = csv.reader([line for line in lines if not line.startswith('#')])
            for row in reader:
                if len(row) > 2:
                    records.append({
                        "raw_value": row[1], # sha256
                        "confidence": 90,
                        "tags": [row[8]] if len(row) > 8 else ["malware"],
                        "description": "MalwareBazaar hash"
                    })
            return records
        except Exception as e:
            print(f"[!] MalwareBazaar fetch failed: {e}")
            return []
