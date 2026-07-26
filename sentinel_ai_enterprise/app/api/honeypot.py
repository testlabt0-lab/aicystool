"""
Honeypot API - Deception Technology
Manage honeypot instances and retrieve captured data
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from datetime import datetime

from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.honeypot.service import HoneypotService, HoneypotStats

router = APIRouter()


@router.get("/status", tags=["Honeypot"])
async def get_honeypot_status(current_user: User = Depends(get_current_user)):
    """Get status of all honeypot services"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    stats = HoneypotService.get_stats()
    return {
        "status": "active",
        "services": stats["services"],
        "total_attacks": stats["total_attacks"],
        "unique_attackers": stats["unique_attackers"],
        "last_updated": datetime.utcnow().isoformat()
    }


@router.get("/attacks", tags=["Honeypot"])
async def get_honeypot_attacks(
    limit: int = 100,
    offset: int = 0,
    service_type: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Retrieve captured attack data from honeypots"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    attacks = HoneypotService.get_attacks(
        limit=limit,
        offset=offset,
        service_type=service_type,
        severity=severity
    )
    
    return {
        "total": len(attacks),
        "limit": limit,
        "offset": offset,
        "attacks": attacks
    }


@router.get("/attackers", tags=["Honeypot"])
async def get_attackers(
    limit: int = 50,
    current_user: User = Depends(get_current_user)
):
    """Get list of unique attackers with profiling data"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    attackers = HoneypotService.get_attackers(limit=limit)
    return {
        "total": len(attackers),
        "attackers": attackers
    }


@router.get("/commands", tags=["Honeypot"])
async def get_captured_commands(
    limit: int = 100,
    service_type: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get captured commands from honeypots"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    commands = HoneypotService.get_commands(limit=limit, service_type=service_type)
    return {
        "total": len(commands),
        "commands": commands
    }


@router.post("/deploy/{service_type}", tags=["Honeypot"])
async def deploy_honeypot(
    service_type: str,
    port: Optional[int] = None,
    current_user: User = Depends(get_current_user)
):
    """Deploy a new honeypot service"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    valid_services = ["ssh", "http", "https", "mysql", "postgresql", "redis", "telnet"]
    if service_type.lower() not in valid_services:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid service type. Valid options: {', '.join(valid_services)}"
        )
    
    success = HoneypotService.deploy_service(service_type, port)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to deploy honeypot")
    
    return {
        "message": f"Honeypot {service_type} deployed successfully",
        "service_type": service_type,
        "port": port or HoneypotService.get_default_port(service_type)
    }


@router.delete("/stop/{service_id}", tags=["Honeypot"])
async def stop_honeypot(
    service_id: str,
    current_user: User = Depends(get_current_user)
):
    """Stop a running honeypot service"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    success = HoneypotService.stop_service(service_id)
    if not success:
        raise HTTPException(status_code=404, detail="Service not found")
    
    return {"message": f"Honeypot {service_id} stopped successfully"}


@router.get("/analytics/summary", tags=["Honeypot"])
async def get_honeypot_analytics(
    hours: int = 24,
    current_user: User = Depends(get_current_user)
):
    """Get honeypot analytics summary"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    analytics = HoneypotService.get_analytics(hours=hours)
    return analytics


@router.get("/top-attacks", tags=["Honeypot"])
async def get_top_attacks(
    limit: int = 10,
    current_user: User = Depends(get_current_user)
):
    """Get top most severe attacks"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    attacks = HoneypotService.get_top_attacks(limit=limit)
    return {
        "period": "last_24_hours",
        "top_attacks": attacks
    }
