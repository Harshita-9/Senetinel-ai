import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List
import ipaddress

def hash_string(text: str) -> str:
    """Generate SHA256 hash of a string"""
    return hashlib.sha256(text.encode()).hexdigest()

def is_valid_ip(ip_string: str) -> bool:
    """Validate IP address"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def is_private_ip(ip_string: str) -> bool:
    """Check if IP is private"""
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_private
    except ValueError:
        return False

def format_currency(amount: float) -> str:
    """Format amount as currency"""
    return f"${amount:,.2f}"

def calculate_time_diff(start: datetime, end: datetime) -> Dict[str, Any]:
    """Calculate time difference with breakdown"""
    delta = end - start
    
    hours, remainder = divmod(delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return {
        "days": delta.days,
        "hours": hours,
        "minutes": minutes,
        "seconds": seconds,
        "total_seconds": delta.total_seconds(),
        "total_minutes": delta.total_seconds() / 60,
        "total_hours": delta.total_seconds() / 3600
    }

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input"""
    text = text[:max_length]
    
    dangerous_chars = ['<', '>', '&', '"', "'", '/', '\\']
    for char in dangerous_chars:
        text = text.replace(char, '')
    
    return text.strip()

def extract_ip_from_text(text: str) -> List[str]:
    """Extract IP addresses from text"""
    import re
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, text)

def calculate_severity_score(
    attack_type: str,
    confidence: float,
    impact: str
) -> float:
    """Calculate overall severity score (0-100)"""
    
    attack_weights = {
        "ransomware": 0.95,
        "zero_day": 0.90,
        "malware": 0.80,
        "sql_injection": 0.75,
        "phishing": 0.70,
        "xss": 0.60,
        "brute_force": 0.55,
        "ddos": 0.65,
        "unknown": 0.50
    }
    
    impact_weights = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.50,
        "low": 0.25
    }
    
    attack_weight = attack_weights.get(attack_type.lower(), 0.50)
    impact_weight = impact_weights.get(impact.lower(), 0.50)
    
    score = (attack_weight * 0.4 + confidence * 0.3 + impact_weight * 0.3) * 100
    
    return min(100, max(0, score))

def generate_incident_summary(incident_data: Dict) -> str:
    """Generate human-readable incident summary"""
    attack_type = incident_data.get('attack_type', 'Unknown')
    severity = incident_data.get('severity', 'unknown')
    source = incident_data.get('source_ip', 'unknown')
    timestamp = incident_data.get('timestamp', datetime.utcnow())
    
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)
    
    summary = f"[{severity.upper()}] {attack_type} attack detected from {source} at {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
    
    return summary

def parse_attack_indicators(payload: str) -> List[str]:
    """Parse and extract attack indicators from payload"""
    indicators = []
    
    sql_patterns = [
        "' OR '1'='1", "UNION SELECT", "DROP TABLE", 
        "'; --", "1=1", "admin'--"
    ]
    
    xss_patterns = [
        "<script>", "javascript:", "onerror=",
        "alert(", "document.cookie"
    ]
    
    cmd_patterns = [
        "; ls", "| cat", "&& whoami", "$(", "`"
    ]
    
    for pattern in sql_patterns:
        if pattern.lower() in payload.lower():
            indicators.append(f"SQL_INJECTION:{pattern}")
    
    for pattern in xss_patterns:
        if pattern.lower() in payload.lower():
            indicators.append(f"XSS:{pattern}")
    
    for pattern in cmd_patterns:
        if pattern in payload:
            indicators.append(f"CMD_INJECTION:{pattern}")
    
    return indicators

def estimate_mttr(attack_type: str, severity: str, auto_remediation: bool) -> float:
    """Estimate Mean Time To Resolution (minutes)"""
    base_times = {
        "ransomware": 240,
        "malware": 120,
        "sql_injection": 45,
        "xss": 30,
        "brute_force": 15,
        "ddos": 60,
        "zero_day": 360,
        "unknown": 90
    }
    
    severity_multipliers = {
        "critical": 2.0,
        "high": 1.5,
        "medium": 1.0,
        "low": 0.5
    }
    
    base = base_times.get(attack_type.lower(), 90)
    multiplier = severity_multipliers.get(severity.lower(), 1.0)
    
    mttr = base * multiplier
    
    if auto_remediation:
        mttr *= 0.1
    
    return mttr

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def get_attack_description(attack_type: str) -> str:
    """Get human-readable attack description"""
    descriptions = {
        "sql_injection": "An attempt to manipulate database queries by injecting malicious SQL code",
        "xss": "Cross-Site Scripting attack attempting to inject malicious scripts into web pages",
        "brute_force": "Systematic attempt to gain access by trying multiple password combinations",
        "ddos": "Distributed Denial of Service attack overwhelming system resources",
        "malware": "Malicious software designed to damage or gain unauthorized access",
        "ransomware": "Malware that encrypts data and demands payment for decryption",
        "phishing": "Social engineering attack attempting to steal credentials or sensitive data",
        "zero_day": "Exploitation of previously unknown vulnerability",
        "unknown": "Suspicious activity requiring further investigation"
    }
    
    return descriptions.get(attack_type.lower(), "Unknown attack pattern detected")

def calculate_risk_score(
    severity: str,
    confidence: float,
    data_sensitivity: str = "medium",
    business_criticality: str = "medium"
) -> int:
    """Calculate overall risk score (0-100)"""
    
    severity_scores = {
        "critical": 40,
        "high": 30,
        "medium": 20,
        "low": 10
    }
    
    sensitivity_scores = {
        "critical": 25,
        "high": 20,
        "medium": 15,
        "low": 10
    }
    
    criticality_scores = {
        "critical": 25,
        "high": 20,
        "medium": 15,
        "low": 10
    }
    
    score = (
        severity_scores.get(severity.lower(), 20) +
        (confidence * 10) +
        sensitivity_scores.get(data_sensitivity.lower(), 15) +
        criticality_scores.get(business_criticality.lower(), 15)
    )
    
    return min(100, int(score))

def json_serial(obj):
    """JSON serializer for objects not serializable by default"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def safe_json_dumps(data: Any) -> str:
    """Safely serialize data to JSON"""
    try:
        return json.dumps(data, default=json_serial, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def get_time_window(hours: int = 24) -> Dict[str, datetime]:
    """Get time window for queries"""
    now = datetime.utcnow()
    return {
        "start": now - timedelta(hours=hours),
        "end": now
    }

def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data like IPs, emails, etc."""
    if len(data) <= visible_chars:
        return mask_char * len(data)
    
    return data[:visible_chars] + mask_char * (len(data) - visible_chars)