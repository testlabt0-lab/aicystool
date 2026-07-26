from fastapi import APIRouter, UploadFile, File, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
import aiofiles

router = APIRouter()


class LogAnalysisInput(BaseModel):
    """Log entries for analysis."""
    log_lines: List[str] = Field(..., description="List of log lines to analyze")
    log_type: Optional[str] = Field(default="auto", description="Type of logs: system, application, security, access")


class LogAnalysisResponse(BaseModel):
    """Log analysis response."""
    threats_detected: int
    entries_analyzed: int
    threat_rate: float
    summary: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    recommendations: List[str]


@router.post("/analyze", response_model=LogAnalysisResponse)
async def analyze_logs(input_data: LogAnalysisInput):
    """
    Analyze log entries for security threats.
    
    Uses pattern matching and ML anomaly detection to identify:
    - Privilege escalation attempts
    - Malware indicators
    - Data exfiltration
    - Reconnaissance activities
    - Lateral movement
    - Persistence mechanisms
    """
    from app.models.log_analyzer import log_analyzer
    
    try:
        # Run analysis
        result = log_analyzer.analyze(input_data.log_lines)
        
        # Extract top recommendations
        all_recommendations = set()
        for r in result.get("results", []):
            all_recommendations.update(r.get("recommendations", []))
        
        return LogAnalysisResponse(
            threats_detected=result["threats_detected"],
            entries_analyzed=result["entries_analyzed"],
            threat_rate=result["threat_rate"],
            summary=result.get("summary", {}),
            recommendations=list(all_recommendations)[:10]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.post("/analyze-file")
async def analyze_log_file(file: UploadFile = File(...)):
    """
    Analyze log file for security threats.
    
    Supports various log formats including syslog, Apache, Nginx, Windows Event Logs.
    """
    from app.models.log_analyzer import log_analyzer
    
    try:
        # Read file
        contents = await file.read()
        log_text = contents.decode('utf-8', errors='ignore')
        
        # Split into lines
        log_lines = [line.strip() for line in log_text.split('\n') if line.strip()]
        
        if not log_lines:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty log file"
            )
        
        # Run analysis
        result = log_analyzer.analyze(log_lines)
        
        return {
            **result,
            "file_name": file.filename,
            "file_size": len(contents),
            "recommendations": list(set(
                rec for r in result.get("results", []) 
                for rec in r.get("recommendations", [])
            ))[:10]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File analysis failed: {str(e)}"
        )


@router.get("/model/status")
async def get_model_status():
    """Get log analysis model status."""
    from app.models.log_analyzer import log_analyzer
    
    return {
        "model_loaded": log_analyzer.is_trained,
        "threat_categories": list(log_analyzer.threat_patterns.keys()),
        "pattern_count": sum(len(p) for p in log_analyzer.threat_patterns.values())
    }
