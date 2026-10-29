import socket
import logging
import requests
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# In-memory cache for IP and domain enrichment to prevent redundant network lookups
_ENRICHMENT_CACHE: Dict[str, Dict[str, Any]] = {}

def get_reverse_dns(ip: str) -> Optional[str]:
    """Resolves reverse DNS PTR record for an IP address."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None

def enrich_ip(ip: str, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Enriches an IP with GeoIP, Country, ISP/Org, ASN, Coordinates (Lat/Lon), and Reverse DNS.
    Uses in-memory cache and safe fallbacks.
    """
    if ip in _ENRICHMENT_CACHE:
        return _ENRICHMENT_CACHE[ip]

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

    # 1. Reverse DNS
    enrichment_data["reverse_dns"] = get_reverse_dns(ip)

    # 2. GeoIP / ASN / Coordinates via lightweight public API with strict timeout
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as,lat,lon"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                enrichment_data["country"] = data.get("country", "Unknown")
                enrichment_data["country_code"] = data.get("countryCode", "XX")
                enrichment_data["city"] = data.get("city", "Unknown")
                enrichment_data["isp"] = data.get("isp", "Unknown")
                enrichment_data["org"] = data.get("org", "Unknown")
                enrichment_data["as_number"] = data.get("as", "Unknown")
                enrichment_data["lat"] = data.get("lat", 0.0)
                enrichment_data["lon"] = data.get("lon", 0.0)
                enrichment_data["is_enriched"] = True
    except Exception as e:
        logger.debug(f"GeoIP enrichment failed for {ip}: {e}")

    _ENRICHMENT_CACHE[ip] = enrichment_data
    return enrichment_data

def enrich_ioc(ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """Enriches any IOC based on its type."""
    if ioc_type in ["ipv4", "ipv6", "ip"]:
        return enrich_ip(ioc_value)
    
    if ioc_type == "domain":
        if ioc_value in _ENRICHMENT_CACHE:
            return _ENRICHMENT_CACHE[ioc_value]
        
        resolved_ips = []
        lat, lon, country = 0.0, 0.0, "Unknown"
        try:
            _, _, ip_list = socket.gethostbyname_ex(ioc_value)
            resolved_ips = ip_list
            if resolved_ips:
                first_ip_data = enrich_ip(resolved_ips[0])
                lat = first_ip_data.get("lat", 0.0)
                lon = first_ip_data.get("lon", 0.0)
                country = first_ip_data.get("country", "Unknown")
        except Exception:
            pass
        
        result = {
            "value": ioc_value,
            "type": "domain",
            "resolved_ips": resolved_ips,
            "lat": lat,
            "lon": lon,
            "country": country,
            "is_enriched": len(resolved_ips) > 0
        }
        _ENRICHMENT_CACHE[ioc_value] = result
        return result

    return {"value": ioc_value, "type": ioc_type, "is_enriched": False}
