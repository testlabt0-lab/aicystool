"""
Sentinel AI Enterprise - Main Application
Advanced Cybersecurity Detection System with AI/ML
"""

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
import logging

from app.core.config import settings
from app.core.security import setup_security
from app.api import ddos, malware, sqli, bruteforce, logs, honeypot, threat_intel, dashboard, auth
from app.services.correlation import CorrelationEngine
from app.services.auto_response import AutoResponseSystem
from app.core.database import init_db

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("🚀 Starting Sentinel AI Enterprise...")
    
    # Initialize database
    await init_db()
    logger.info("✅ Database initialized")
    
    # Initialize correlation engine
    CorrelationEngine.initialize()
    logger.info("✅ Correlation Engine initialized")
    
    # Initialize auto-response system
    AutoResponseSystem.initialize()
    logger.info("✅ Auto-Response System initialized")
    
    # Setup security
    setup_security()
    logger.info("✅ Security configured")
    
    logger.info(f"🎯 Sentinel AI Enterprise ready on port {settings.PORT}")
    logger.info(f"📊 Dashboard: http://localhost:{settings.PORT}/dashboard")
    logger.info(f"📚 API Docs: http://localhost:{settings.PORT}/docs")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down Sentinel AI Enterprise...")
    CorrelationEngine.shutdown()
    AutoResponseSystem.shutdown()
    logger.info("✅ Shutdown complete")


app = FastAPI(
    title="Sentinel AI Enterprise",
    description="""
    ## Advanced Cybersecurity Detection System
    
    ### Features:
    - **DDoS Detection**: ML-based detection with automatic mitigation
    - **Malware Analysis**: Deep learning for binary file analysis
    - **SQL Injection Detection**: NLP-powered query analysis
    - **Brute Force Detection**: Behavioral analysis and anomaly detection
    - **Log Analysis**: Real-time threat detection in logs
    - **Honeypot System**: Advanced deception technology
    - **Threat Intelligence**: Integration with external threat feeds
    - **Event Correlation**: Multi-stage attack detection
    - **Auto Response**: Automated incident response
    
    ### Compliance:
    - GDPR compliant
    - HIPAA ready
    - SOC 2 Type II compatible
    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-Sentinel-Version"] = "2.0.0"
    return response


# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error_type": type(exc).__name__,
            "request_id": getattr(request.state, "request_id", "unknown")
        }
    )


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """System health check"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "engines": {
            "ddos": "active",
            "malware": "active",
            "sqli": "active",
            "bruteforce": "active",
            "logs": "active"
        },
        "services": {
            "correlation": "active",
            "auto_response": "active",
            "honeypot": "active",
            "threat_intel": "active"
        },
        "timestamp": time.time()
    }


# Include routers
app.include_router(ddos.router, prefix="/api/v1/ddos", tags=["DDoS Detection"])
app.include_router(malware.router, prefix="/api/v1/malware", tags=["Malware Detection"])
app.include_router(sqli.router, prefix="/api/v1/sqli", tags=["SQL Injection"])
app.include_router(bruteforce.router, prefix="/api/v1/bruteforce", tags=["Brute Force"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["Log Analysis"])
app.include_router(honeypot.router, prefix="/api/v1/honeypot", tags=["Honeypot"])
app.include_router(threat_intel.router, prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint with system information"""
    return {
        "name": "Sentinel AI Enterprise",
        "version": "2.0.0",
        "description": "Advanced Cybersecurity Detection System",
        "features": [
            "DDoS Detection & Mitigation",
            "Malware Analysis",
            "SQL Injection Detection",
            "Brute Force Detection",
            "Log Analysis",
            "Honeypot System",
            "Threat Intelligence",
            "Event Correlation",
            "Automated Response"
        ],
        "documentation": "/docs",
        "dashboard": "/dashboard",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
