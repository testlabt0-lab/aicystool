from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

router = APIRouter()


class NetworkTrafficInput(BaseModel):
    """Network traffic data for DDoS detection."""
    packets_per_second: float = Field(..., description="Packets per second")
    bytes_per_second: float = Field(..., description="Bytes per second")
    unique_source_ips: int = Field(default=1, description="Unique source IP count")
    unique_dest_ips: int = Field(default=1, description="Unique destination IP count")
    flags: Dict[str, int] = Field(default_factory=dict, description="TCP flag counts")
    avg_packet_size: float = Field(default=0, description="Average packet size")
    variance_packet_size: float = Field(default=0, description="Packet size variance")
    source_ip_entropy: float = Field(default=0, description="Source IP entropy")
    dest_port_entropy: float = Field(default=0, description="Destination port entropy")
    connections_per_second: float = Field(default=0, description="Connections per second")
    failed_connections_ratio: float = Field(default=0, description="Failed connection ratio")
    icmp_ratio: float = Field(default=0, description="ICMP protocol ratio")
    udp_ratio: float = Field(default=0, description="UDP protocol ratio")
    tcp_ratio: float = Field(default=0, description="TCP protocol ratio")
    source_ip: Optional[str] = None


class DDoSDetectionResponse(BaseModel):
    """DDoS detection response."""
    is_attack: bool
    confidence: float
    risk_level: str
    attack_type: Optional[str]
    details: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    recommendation: str


@router.post("/detect", response_model=DDoSDetectionResponse)
async def detect_ddos(traffic: NetworkTrafficInput):
    """
    Detect DDoS attacks in network traffic.
    
    Analyzes network traffic patterns using ML to identify potential DDoS attacks
    including SYN Flood, UDP Flood, HTTP Flood, and other volumetric attacks.
    """
    from app.models.ddos_detector import ddos_detector
    
    try:
        # Convert to dict for model
        traffic_data = traffic.model_dump()
        
        # Run detection
        result = ddos_detector.predict(traffic_data)
        
        # Generate recommendation
        if result["is_attack"]:
            recommendation = f"Block traffic from suspicious sources. Detected {result['attack_type']} attack."
        else:
            recommendation = "Traffic appears normal. Continue monitoring."
        
        return DDoSDetectionResponse(
            is_attack=result["is_attack"],
            confidence=result["confidence"],
            risk_level=result["risk_level"],
            attack_type=result.get("attack_type"),
            details=result.get("details", {}),
            recommendation=recommendation
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {str(e)}"
        )


@router.get("/model/status")
async def get_model_status():
    """Get DDoS detection model status."""
    from app.models.ddos_detector import ddos_detector
    
    return {
        "model_loaded": ddos_detector.is_trained,
        "model_path": ddos_detector.model_path,
        "feature_count": len(ddos_detector.feature_names)
    }
