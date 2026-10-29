def calculate_score(ioc_confidence: int, source_count: int, ioc_type: str, hit_count: int) -> int:
    """
    Calculates the threat score (0-100+) based on IOC properties and hit counts.
    """
    # Base score from IOC confidence (0-100)
    score = ioc_confidence
    
    # Bonus for multiple sources agreeing
    if source_count > 1:
        score += min(20, (source_count - 1) * 5)
        
    # Bonus for explicit malicious types
    if ioc_type in ["md5", "sha1", "sha256", "url"]:
        score += 10
        
    # Bonus for repeated hits in logs
    if hit_count > 1:
        score += min(20, (hit_count - 1) * 2)
        
    return score

def get_severity(score: int) -> str:
    """Maps numerical score to severity level."""
    if score >= 90:
        return "critical"
    elif score >= 75:
        return "high"
    elif score >= 50:
        return "medium"
    else:
        return "low"
