from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime

router = APIRouter()


class SQLQueryInput(BaseModel):
    """SQL query for injection detection."""
    query: str = Field(..., description="SQL query to analyze")
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


class SQLiDetectionResponse(BaseModel):
    """SQL injection detection response."""
    is_sqli: bool
    confidence: float
    risk_level: str
    attack_type: Optional[str]
    patterns_matched: List[str]
    query_analysis: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    recommendation: str


@router.post("/detect", response_model=SQLiDetectionResponse)
async def detect_sqli(query_input: SQLQueryInput):
    """
    Detect SQL injection attacks in queries.
    
    Uses NLP and pattern analysis to identify various SQL injection techniques
    including Union-based, Boolean-based, Time-based, and Error-based attacks.
    """
    from app.models.sqli_detector import sqli_detector
    
    try:
        # Run detection
        result = sqli_detector.detect(query_input.query)
        
        # Generate recommendation
        if result["is_sqli"]:
            recommendation = f"BLOCK: Detected {result['attack_type']}. Sanitize input and use parameterized queries."
        elif result["risk_level"] in ["medium", "high"]:
            recommendation = "WARNING: Suspicious query pattern. Review and validate input."
        else:
            recommendation = "Query appears safe. Continue standard input validation."
        
        return SQLiDetectionResponse(
            is_sqli=result["is_sqli"],
            confidence=result["confidence"],
            risk_level=result["risk_level"],
            attack_type=result.get("attack_type"),
            patterns_matched=result.get("patterns_matched", []),
            query_analysis=result.get("query_analysis", {}),
            recommendation=recommendation
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {str(e)}"
        )


@router.post("/batch-detect")
async def batch_detect_sqli(queries: List[str]):
    """
    Batch detect SQL injection in multiple queries.
    
    Efficiently analyze multiple SQL queries in a single request.
    """
    from app.models.sqli_detector import sqli_detector
    
    try:
        results = []
        for query in queries:
            result = sqli_detector.detect(query)
            results.append({
                "query": query[:100] + "..." if len(query) > 100 else query,
                **result
            })
        
        sqli_count = sum(1 for r in results if r.get("is_sqli", False))
        
        return {
            "total_queries": len(queries),
            "sqli_detected": sqli_count,
            "detection_rate": round(sqli_count / len(queries), 4) if queries else 0,
            "results": results
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch detection failed: {str(e)}"
        )


@router.get("/model/status")
async def get_model_status():
    """Get SQLi detection model status."""
    from app.models.sqli_detector import sqli_detector
    
    return {
        "model_loaded": sqli_detector.is_trained,
        "pattern_count": len(sqli_detector.sqli_patterns),
        "feature_names": list(sqli_detector.extract_features("SELECT 1").keys())
    }
