from typing import Dict, Any

def calculate_score(ioc_confidence: int, source_count: int, ioc_type: str, hit_count: int = 1) -> int:
    """
    Calculates the threat score (strictly bounded 0-100) based on IOC confidence,
    independent threat feeds, indicator fidelity, and log occurrence frequency.
    """
    conf = max(0, min(100, int(ioc_confidence or 50)))
    
    # 1. Base score from indicator confidence (up to 70% weighted base)
    score = conf

    # 2. Corroboration bonus: Independent threat intelligence feeds confirming the IOC
    if source_count > 1:
        # +5 points per extra independent feed, capped at 20
        feed_bonus = min(20, (source_count - 1) * 5)
        score += feed_bonus

    # 3. Indicator fidelity bonus: High-fidelity atomic artifacts (hashes, exact URLs)
    if ioc_type in ["md5", "sha1", "sha256", "url"]:
        score += 10

    # 4. Repeated log observation bonus: Higher risk when multiple internal events observed
    if hit_count > 1:
        # +2 points per repeated hit, capped at 20
        hit_bonus = min(20, (hit_count - 1) * 2)
        score += hit_bonus

    # Strictly clamp final score between 0 and 100
    return max(0, min(100, score))

def explain_score(ioc_confidence: int, source_count: int, ioc_type: str, hit_count: int = 1) -> Dict[str, Any]:
    """
    Provides an explainable breakdown of the risk score for SOC analysts.
    """
    conf = max(0, min(100, int(ioc_confidence or 50)))
    feed_bonus = min(20, (source_count - 1) * 5) if source_count > 1 else 0
    type_bonus = 10 if ioc_type in ["md5", "sha1", "sha256", "url"] else 0
    hit_bonus = min(20, (hit_count - 1) * 2) if hit_count > 1 else 0
    
    total = max(0, min(100, conf + feed_bonus + type_bonus + hit_bonus))
    
    return {
        "base_confidence": conf,
        "feed_corroboration_bonus": feed_bonus,
        "independent_sources": source_count,
        "indicator_type_bonus": type_bonus,
        "ioc_type": ioc_type,
        "repeated_hits_bonus": hit_bonus,
        "hit_count": hit_count,
        "final_score": total,
        "severity": get_severity(total)
    }

def get_severity(score: int) -> str:
    """
    Maps numerical score to standardized SOC severity level.
    Critical: >= 85
    High:     70 - 84
    Medium:   45 - 69
    Low:      < 45
    """
    if score >= 85:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 45:
        return "medium"
    else:
        return "low"
