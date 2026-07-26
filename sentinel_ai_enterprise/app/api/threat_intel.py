"""
Threat Intelligence API
Integration with external threat feeds and reputation services
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime

from app.core.security import get_current_user
from app.models.user import User, UserRole
from app.integrations.threat_intel import ThreatIntelligenceService

router = APIRouter()


@router.get("/ip/{ip_address}", tags=["Threat Intelligence"])
async def check_ip_reputation(
    ip_address: str,
    current_user: User = Depends(get_current_user)
):
    """Check IP address reputation across multiple threat intelligence sources"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST, UserRole.OPERATOR]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await ThreatIntelligenceService.check_ip(ip_address)
    return result


@router.get("/domain/{domain}", tags=["Threat Intelligence"])
async def check_domain_reputation(
    domain: str,
    current_user: User = Depends(get_current_user)
):
    """Check domain reputation"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST, UserRole.OPERATOR]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await ThreatIntelligenceService.check_domain(domain)
    return result


@router.get("/hash/{file_hash}", tags=["Threat Intelligence"])
async def check_file_hash(
    file_hash: str,
    current_user: User = Depends(get_current_user)
):
    """Check file hash (MD5/SHA1/SHA256) against malware databases"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST, UserRole.OPERATOR]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    result = await ThreatIntelligenceService.check_hash(file_hash)
    return result


@router.get("/indicators", tags=["Threat Intelligence"])
async def get_threat_indicators(
    type: str = Query("all", description="Type of indicator: ip, domain, hash, url"),
    limit: int = Query(100, description="Maximum number of indicators to return"),
    hours: int = Query(24, description="Time range in hours"),
    current_user: User = Depends(get_current_user)
):
    """Get latest threat indicators from all sources"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    indicators = await ThreatIntelligenceService.get_indicators(
        indicator_type=type,
        limit=limit,
        hours=hours
    )
    
    return {
        "total": len(indicators),
        "type": type,
        "period_hours": hours,
        "indicators": indicators
    }


@router.get("/feeds/status", tags=["Threat Intelligence"])
async def get_feed_status(current_user: User = Depends(get_current_user)):
    """Get status of all threat intelligence feeds"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    status = ThreatIntelligenceService.get_feeds_status()
    return status


@router.post("/feeds/refresh/{feed_name}", tags=["Threat Intelligence"])
async def refresh_feed(
    feed_name: str,
    current_user: User = Depends(get_current_user)
):
    """Manually refresh a specific threat intelligence feed"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    success = await ThreatIntelligenceService.refresh_feed(feed_name)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to refresh feed")
    
    return {
        "message": f"Feed {feed_name} refreshed successfully",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/campaigns", tags=["Threat Intelligence"])
async def get_active_campaigns(
    limit: int = Query(20, description="Maximum number of campaigns"),
    current_user: User = Depends(get_current_user)
):
    """Get active threat campaigns"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    campaigns = await ThreatIntelligenceService.get_campaigns(limit=limit)
    return {
        "total": len(campaigns),
        "campaigns": campaigns
    }


@router.get("/trends", tags=["Threat Intelligence"])
async def get_threat_trends(
    days: int = Query(7, description="Number of days for trend analysis"),
    current_user: User = Depends(get_current_user)
):
    """Get threat intelligence trends"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    trends = await ThreatIntelligenceService.get_trends(days=days)
    return trends


@router.post("/bulk/check", tags=["Threat Intelligence"])
async def bulk_check_indicators(
    indicators: List[str],
    indicator_type: str = Query("ip", description="Type: ip, domain, hash"),
    current_user: User = Depends(get_current_user)
):
    """Bulk check multiple indicators"""
    if current_user.role not in [UserRole.ADMIN, UserRole.ANALYST]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    if len(indicators) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 indicators per request")
    
    results = await ThreatIntelligenceService.bulk_check(
        indicators=indicators,
        indicator_type=indicator_type
    )
    
    return {
        "total_checked": len(results),
        "malicious_count": sum(1 for r in results if r.get("is_malicious", False)),
        "results": results
    }
