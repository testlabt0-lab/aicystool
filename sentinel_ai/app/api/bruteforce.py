from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

router = APIRouter()


class LoginAttemptInput(BaseModel):
    """Login attempt data for brute force detection."""
    username: str = Field(..., description="Username attempted")
    ip_address: str = Field(..., description="Source IP address")
    success: bool = Field(..., description="Login success status")
    user_agent: Optional[str] = None
    timestamp: Optional[datetime] = None


class BruteForceDetectionResponse(BaseModel):
    """Brute force detection response."""
    is_attack: bool
    confidence: float
    risk_level: str
    attack_type: Optional[str]
    details: Dict[str, Any]
    recommendations: List[str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


@router.post("/detect", response_model=BruteForceDetectionResponse)
async def detect_bruteforce(attempt: LoginAttemptInput):
    """
    Detect brute force and credential stuffing attacks.
    
    Analyzes login attempt patterns using behavioral analysis and anomaly detection
    to identify brute force attacks, credential stuffing, and password guessing.
    """
    from app.models.bruteforce_detector import bruteforce_detector
    
    try:
        # Convert to dict
        attempt_data = attempt.model_dump()
        
        # Run detection
        result = bruteforce_detector.detect(attempt_data)
        
        return BruteForceDetectionResponse(
            is_attack=result["is_attack"],
            confidence=result["confidence"],
            risk_level=result["risk_level"],
            attack_type=result.get("attack_type"),
            details=result.get("details", {}),
            recommendations=result.get("recommendations", [])
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {str(e)}"
        )


@router.post("/batch-detect")
async def batch_detect_bruteforce(attempts: List[LoginAttemptInput]):
    """
    Analyze multiple login attempts for brute force patterns.
    """
    from app.models.bruteforce_detector import bruteforce_detector
    
    try:
        attacks_detected = 0
        results = []
        
        for attempt in attempts:
            result = bruteforce_detector.detect(attempt.model_dump())
            if result["is_attack"]:
                attacks_detected += 1
            results.append({
                "username": attempt.username,
                "ip_address": attempt.ip_address,
                **result
            })
        
        return {
            "total_attempts": len(attempts),
            "attacks_detected": attacks_detected,
            "attack_rate": round(attacks_detected / len(attempts), 4) if attempts else 0,
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch detection failed: {str(e)}"
        )


@router.get("/model/status")
async def get_model_status():
    """Get brute force detection model status."""
    from app.models.bruteforce_detector import bruteforce_detector
    
    return {
        "model_loaded": bruteforce_detector.is_trained,
        "thresholds": {
            "max_attempts_per_user": bruteforce_detector.max_attempts_per_user,
            "max_attempts_per_ip": bruteforce_detector.max_attempts_per_ip,
            "time_window_seconds": bruteforce_detector.time_window_seconds
        }
    }
