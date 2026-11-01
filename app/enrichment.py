import socket
import logging
import time
import ipaddress
import requests
from typing import Dict, Any, Optional
from collections import OrderedDict
from app.config import settings

logger = logging.getLogger(__name__)

# Bounded LRU + TTL Cache (max 2000 entries, 24 hour TTL)
_CACHE_MAX_SIZE = 2000
_CACHE_TTL_SECONDS = 86400 # 24 hours
_ENRICHMENT_CACHE: OrderedDict[str, Dict[str, Any]] = OrderedDict()

def _get_from_cache(key: str) -> Optional[Dict[str, Any]]:
    if key in _ENRICHMENT_CACHE:
        entry = _ENRICHMENT_CACHE[key]
        if time.time() - entry.get("_timestamp", 0) < _CACHE_TTL_SECONDS:
            _ENRICHMENT_CACHE.move_to_end(key)
            return entry.get("data")
        else:
            del _ENRICHMENT_CACHE[key]
    return None

def _put_in_cache(key: str, data: Dict[str, Any]):
    if len(_ENRICHMENT_CACHE) >= _CACHE_MAX_SIZE:
        _ENRICHMENT_CACHE.popitem(last=False) # Evict oldest entry
    _ENRICHMENT_CACHE[key] = {
        "_timestamp": time.time(),
        "data": data
    }

def get_reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Resolves reverse DNS PTR record for an IP address with strict timeout protection."""
    try:
        prev_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        finally:
            socket.setdefaulttimeout(prev_timeout)
    except Exception:
        return None

def enrich_ip(ip: str, timeout: float = 1.5, skip_rdns: bool = False) -> Dict[str, Any]:
    """
    Enriches an IP with GeoIP, Country, ISP/Org, ASN, Coordinates (Lat/Lon), and Reverse DNS.
    Uses bounded TTL caching and fails safely without hanging page requests.
    """
    cached = _get_from_cache(ip)
    if cached:
        return cached

    enrichment_data = {
        "value": ip,
        "type": "ip",
        "country": "Unknown",
        "country_code": "XX",
        "city": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "as_number": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "reverse_dns": None,
        "is_enriched": False
    }

    # Handle internal RFC1918 / Loopback addresses immediately without external WAN queries
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            enrichment_data.update({
                "country": "Internal / RFC1918",
                "country_code": "LAN",
                "city": "Local Network",
                "isp": "Enterprise Intranet",
                "org": "Private RFC1918 Subnet",
                "lat": 0.0,
                "lon": 0.0,
                "is_enriched": True
            })
            _put_in_cache(ip, enrichment_data)
            return enrichment_data
    except ValueError:
        return enrichment_data

    # 1. Reverse DNS with socket timeout (optional, skipped for fast map rendering)
    if not skip_rdns:
        enrichment_data["reverse_dns"] = get_reverse_dns(ip, timeout=1.0)

    # 2. GeoIP / ASN via secure TLS endpoint (HTTPS) with strict timeout to prevent plaintext data leakage
    try:
        url = f"https://ipwho.is/{ip}"
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "SENTINEL-SOC/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") is True:
                enrichment_data["country"] = data.get("country", "Unknown")
                enrichment_data["country_code"] = data.get("country_code", "XX")
                enrichment_data["city"] = data.get("city", "Unknown")
                conn = data.get("connection", {}) or {}
                enrichment_data["isp"] = conn.get("isp") or data.get("isp", "Unknown")
                enrichment_data["org"] = conn.get("org") or data.get("org", "Unknown")
                enrichment_data["as_number"] = f"AS{conn.get('asn', '')}".strip() if conn.get("asn") else "Unknown"
                enrichment_data["lat"] = float(data.get("latitude") or 0.0)
                enrichment_data["lon"] = float(data.get("longitude") or 0.0)
                enrichment_data["is_enriched"] = True
    except Exception as e:
        logger.debug(f"GeoIP enrichment request timeout or failure for {ip}: {e}")

    _put_in_cache(ip, enrichment_data)
    return enrichment_data

def enrich_ioc(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Enriches any IOC based on its type using cached lookups."""
    clean_val = ioc_value.strip()
    norm_type = ioc_type.lower()
    
    if norm_type in ["ipv4", "ipv6", "ip"]:
        return enrich_ip(clean_val)
    
    if norm_type == "domain":
        cached = _get_from_cache(clean_val)
        if cached:
            return cached
            
        result = {
            "value": clean_val,
            "type": "domain",
            "resolved_ips": [],
            "lat": 0.0,
            "lon": 0.0,
            "country": "Unknown",
            "is_enriched": False
        }
        _put_in_cache(clean_val, result)
        return result

    return {"value": clean_val, "type": norm_type, "is_enriched": False}
