from fastapi import APIRouter, WebSocket
from pydantic import BaseModel
from typing import Dict, Any, List
from datetime import datetime, timedelta
import asyncio

router = APIRouter()

# Store active WebSocket connections
active_connections: List[WebSocket] = []


class DashboardStats(BaseModel):
    """Dashboard statistics response."""
    total_detections: int
    ddos_attacks: int
    malware_scans: int
    sqli_attempts: int
    bruteforce_attacks: int
    log_threats: int
    critical_alerts: int
    high_risk_events: int
    last_updated: datetime


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Get real-time security dashboard statistics.
    
    Returns aggregated metrics from all detection systems.
    """
    # In production, fetch from database
    # For demo, return sample data
    now = datetime.utcnow()
    
    return DashboardStats(
        total_detections=1247,
        ddos_attacks=23,
        malware_scans=456,
        sqli_attempts=89,
        bruteforce_attacks=34,
        log_threats=156,
        critical_alerts=12,
        high_risk_events=45,
        last_updated=now
    )


@router.get("/recent-alerts")
async def get_recent_alerts(limit: int = 20):
    """Get recent security alerts."""
    # Sample alerts for demonstration
    alerts = [
        {
            "id": i,
            "type": ["DDoS", "Malware", "SQLi", "BruteForce"][i % 4],
            "severity": ["critical", "high", "medium", "low"][i % 4],
            "description": f"Security event detected from IP 192.168.1.{i}",
            "timestamp": (datetime.utcnow() - timedelta(minutes=i*5)).isoformat(),
            "status": "new" if i % 3 == 0 else "acknowledged"
        }
        for i in range(limit)
    ]
    return {"alerts": alerts, "total": len(alerts)}


@router.get("/threat-map")
async def get_threat_map():
    """Get geographic threat distribution."""
    # Sample threat map data
    return {
        "threats_by_country": {
            "US": 234,
            "CN": 189,
            "RU": 156,
            "BR": 89,
            "IN": 67,
            "DE": 45,
            "FR": 34,
            "GB": 28
        },
        "top_attack_vectors": [
            {"type": "DDoS", "count": 456, "percentage": 35},
            {"type": "SQL Injection", "count": 312, "percentage": 24},
            {"type": "Brute Force", "count": 267, "percentage": 20},
            {"type": "Malware", "count": 189, "percentage": 14},
            {"type": "Other", "count": 91, "percentage": 7}
        ],
        "last_24h_trend": [
            {"hour": i, "attacks": 50 + (i % 12) * 10}
            for i in range(24)
        ]
    }


@router.get("/system-health")
async def get_system_health():
    """Get system health status."""
    return {
        "status": "healthy",
        "uptime_hours": 720,
        "models": {
            "ddos_detector": {"status": "loaded", "accuracy": 0.995},
            "malware_detector": {"status": "loaded", "accuracy": 0.987},
            "sqli_detector": {"status": "loaded", "accuracy": 0.992},
            "bruteforce_detector": {"status": "loaded", "accuracy": 0.989},
            "log_analyzer": {"status": "loaded", "accuracy": 0.994}
        },
        "performance": {
            "avg_response_time_ms": 45,
            "requests_per_minute": 1234,
            "error_rate": 0.001
        }
    }


async def broadcast_alert(alert_data: Dict[str, Any]):
    """Broadcast alert to all connected WebSocket clients."""
    if not active_connections:
        return
    
    message = {
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Send to all connections
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except Exception:
            disconnected.append(connection)
    
    # Remove disconnected clients
    for conn in disconnected:
        active_connections.remove(conn)


@router.post("/broadcast-test")
async def test_broadcast(message: dict):
    """Test broadcast functionality."""
    await broadcast_alert(message)
    return {"status": "broadcast_sent", "connected_clients": len(active_connections)}
