"""
Dashboard API - Security Overview and Analytics
Real-time security metrics, charts, and incident summaries
"""

from fastapi import APIRouter, Depends, Query
from typing import Optional
from datetime import datetime, timedelta

from app.core.security import get_current_user
from app.models.user import User, UserRole

router = APIRouter()


@router.get("/overview", tags=["Dashboard"])
async def get_security_overview(
    hours: int = Query(24, description="Time range in hours"),
    current_user: User = Depends(get_current_user)
):
    """Get overall security posture overview"""
    # Demo data - in production, aggregate from all engines
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "period_hours": hours,
        "security_score": 87,
        "threat_level": "medium",
        "summary": {
            "total_events": 15847,
            "critical_alerts": 12,
            "high_alerts": 45,
            "medium_alerts": 234,
            "low_alerts": 892,
            "blocked_attacks": 1456,
            "active_threats": 8
        },
        "engines_status": {
            "ddos": {"status": "active", "alerts_24h": 23, "blocked": 18},
            "malware": {"status": "active", "scans_24h": 456, "detections": 12},
            "sqli": {"status": "active", "alerts_24h": 89, "blocked": 67},
            "bruteforce": {"status": "active", "alerts_24h": 145, "blocked_ips": 34},
            "logs": {"status": "active", "events_analyzed": 12456, "anomalies": 78}
        }
    }


@router.get("/alerts", tags=["Dashboard"])
async def get_recent_alerts(
    limit: int = Query(50, description="Maximum alerts to return"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    status: Optional[str] = Query(None, description="Filter by status: new, investigating, resolved"),
    current_user: User = Depends(get_current_user)
):
    """Get recent security alerts"""
    # Demo alerts
    alerts = [
        {
            "id": "ALT-2024-001",
            "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
            "severity": "critical",
            "type": "ddos_attack",
            "source": "192.168.1.100",
            "target": "web-server-01",
            "description": "DDoS attack detected with 5000 req/s",
            "status": "investigating",
            "auto_response_triggered": True
        },
        {
            "id": "ALT-2024-002",
            "timestamp": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
            "severity": "high",
            "type": "sql_injection",
            "source": "10.0.0.55",
            "target": "database-01",
            "description": "SQL injection attempt in login form",
            "status": "blocked",
            "auto_response_triggered": True
        },
        {
            "id": "ALT-2024-003",
            "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            "severity": "high",
            "type": "brute_force",
            "source": "203.0.113.50",
            "target": "auth-service",
            "description": "Brute force attack: 500 failed login attempts",
            "status": "blocked",
            "auto_response_triggered": True
        }
    ]
    
    # Apply filters
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    if status:
        alerts = [a for a in alerts if a["status"] == status]
    
    return {
        "total": len(alerts),
        "limit": limit,
        "alerts": alerts[:limit]
    }


@router.get("/metrics/attacks", tags=["Dashboard"])
async def get_attack_metrics(
    days: int = Query(7, description="Number of days"),
    interval: str = Query("hour", description="Aggregation interval: hour, day"),
    current_user: User = Depends(get_current_user)
):
    """Get attack metrics over time"""
    # Demo time-series data
    metrics = []
    base_time = datetime.utcnow() - timedelta(days=days)
    
    for i in range(days * 24):
        timestamp = base_time + timedelta(hours=i)
        metrics.append({
            "timestamp": timestamp.isoformat(),
            "ddos_attempts": int(10 + 5 * (i % 5)),
            "sqli_attempts": int(5 + 3 * (i % 7)),
            "bruteforce_attempts": int(20 + 10 * (i % 3)),
            "malware_detections": int(2 + (i % 4)),
            "blocked_count": int(30 + 15 * (i % 6))
        })
    
    return {
        "period_days": days,
        "interval": interval,
        "data_points": len(metrics),
        "metrics": metrics
    }


@router.get("/metrics/top-sources", tags=["Dashboard"])
async def get_top_attack_sources(
    limit: int = Query(10, description="Number of top sources"),
    hours: int = Query(24, description="Time range in hours"),
    current_user: User = Depends(get_current_user)
):
    """Get top attacking IP addresses"""
    sources = [
        {"ip": "203.0.113.50", "country": "CN", "attacks": 1245, "last_seen": "5 min ago"},
        {"ip": "198.51.100.23", "country": "RU", "attacks": 892, "last_seen": "12 min ago"},
        {"ip": "192.0.2.100", "country": "BR", "attacks": 567, "last_seen": "1 hour ago"},
        {"ip": "198.18.0.55", "country": "US", "attacks": 445, "last_seen": "2 hours ago"},
        {"ip": "203.0.113.75", "country": "IN", "attacks": 334, "last_seen": "3 hours ago"}
    ]
    
    return {
        "period_hours": hours,
        "top_sources": sources[:limit]
    }


@router.get("/metrics/top-targets", tags=["Dashboard"])
async def get_top_targets(
    hours: int = Query(24, description="Time range in hours"),
    current_user: User = Depends(get_current_user)
):
    """Get most targeted systems/services"""
    targets = [
        {"service": "web-server-01", "type": "HTTP", "attacks": 2345, "success_rate": "0.2%"},
        {"service": "auth-service", "type": "Authentication", "attacks": 1567, "success_rate": "0.0%"},
        {"service": "database-01", "type": "SQL", "attacks": 892, "success_rate": "0.1%"},
        {"service": "api-gateway", "type": "REST API", "attacks": 678, "success_rate": "0.3%"},
        {"service": "mail-server", "type": "SMTP", "attacks": 445, "success_rate": "0.0%"}
    ]
    
    return {
        "period_hours": hours,
        "top_targets": targets
    }


@router.get("/incidents", tags=["Dashboard"])
async def get_active_incidents(
    status: str = Query("active", description="Incident status"),
    current_user: User = Depends(get_current_user)
):
    """Get active security incidents"""
    incidents = [
        {
            "id": "INC-2024-001",
            "title": "DDoS Attack on Web Infrastructure",
            "severity": "critical",
            "status": "active",
            "created_at": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "assigned_to": "SOC Team Alpha",
            "affected_systems": ["web-server-01", "web-server-02", "load-balancer-01"],
            "timeline_events": 12
        },
        {
            "id": "INC-2024-002",
            "title": "Suspected Malware Infection",
            "severity": "high",
            "status": "investigating",
            "created_at": (datetime.utcnow() - timedelta(hours=5)).isoformat(),
            "assigned_to": "Malware Analysis Team",
            "affected_systems": ["workstation-045"],
            "timeline_events": 8
        }
    ]
    
    return {
        "total": len(incidents),
        "incidents": incidents
    }


@router.get("/compliance/status", tags=["Dashboard"])
async def get_compliance_status(current_user: User = Depends(get_current_user)):
    """Get compliance status for various standards"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "standards": {
            "GDPR": {
                "status": "compliant",
                "score": 95,
                "last_audit": "2024-01-15",
                "next_audit": "2024-04-15"
            },
            "HIPAA": {
                "status": "compliant",
                "score": 92,
                "last_audit": "2024-01-10",
                "next_audit": "2024-07-10"
            },
            "SOC2": {
                "status": "in_progress",
                "score": 88,
                "last_audit": "2023-12-01",
                "next_audit": "2024-06-01"
            },
            "PCI-DSS": {
                "status": "compliant",
                "score": 97,
                "last_audit": "2024-02-01",
                "next_audit": "2025-02-01"
            }
        }
    }


@router.get("/reports/summary", tags=["Dashboard"])
async def generate_summary_report(
    days: int = Query(7, description="Report period in days"),
    format: str = Query("json", description="Output format: json, pdf"),
    current_user: User = Depends(get_current_user)
):
    """Generate security summary report"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    report = {
        "report_id": f"RPT-{datetime.utcnow().strftime('%Y%m%d')}-001",
        "generated_at": datetime.utcnow().isoformat(),
        "period_days": days,
        "executive_summary": {
            "overall_security_posture": "Good",
            "total_attacks_blocked": 15847,
            "critical_incidents": 2,
            "mean_time_to_detect": "2.3 minutes",
            "mean_time_to_respond": "8.7 minutes"
        },
        "key_findings": [
            "DDoS attacks increased by 15% compared to previous week",
            "SQL injection attempts decreased by 23%",
            "New threat actor group identified targeting authentication services",
            "All critical systems maintained 99.9% uptime"
        ],
        "recommendations": [
            "Increase rate limiting thresholds for API endpoints",
            "Update WAF rules for latest SQL injection patterns",
            "Implement additional monitoring for authentication services",
            "Schedule penetration testing for Q2"
        ]
    }
    
    return report
