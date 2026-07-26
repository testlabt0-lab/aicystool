from fastapi import FastAPI, Request, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import structlog
from app.core.config import get_settings, Settings
from app.core.database import init_db

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Sentinel AI Security Platform")
    settings = get_settings()
    
    # Initialize database
    try:
        init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    
    # Load ML models
    from app.models.ddos_detector import ddos_detector
    from app.models.malware_detector import malware_detector
    from app.models.sqli_detector import sqli_detector
    from app.models.bruteforce_detector import bruteforce_detector
    from app.models.log_analyzer import log_analyzer
    
    logger.info("All ML models loaded successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Sentinel AI")


# Create FastAPI app
settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise AI-Powered Cybersecurity Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting middleware."""
    # Implement proper rate limiting with Redis in production
    response = await call_next(request)
    return response


# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "type": type(exc).__name__}
    )


# Import routers
from app.api import ddos, malware, sqli, bruteforce, logs, dashboard

# Include routers
app.include_router(ddos.router, prefix=f"{settings.API_V1_PREFIX}/ddos", tags=["DDoS Detection"])
app.include_router(malware.router, prefix=f"{settings.API_V1_PREFIX}/malware", tags=["Malware Detection"])
app.include_router(sqli.router, prefix=f"{settings.API_V1_PREFIX}/sqli", tags=["SQL Injection Detection"])
app.include_router(bruteforce.router, prefix=f"{settings.API_V1_PREFIX}/bruteforce", tags=["Brute Force Detection"])
app.include_router(logs.router, prefix=f"{settings.API_V1_PREFIX}/logs", tags=["Log Analysis"])
app.include_router(dashboard.router, prefix=f"{settings.API_V1_PREFIX}/dashboard", tags=["Dashboard"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": "1.0.0",
        "description": "AI-Powered Cybersecurity Platform",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "api_v1": settings.API_V1_PREFIX
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": "1.0.0"
    }


# WebSocket for real-time alerts
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time security alerts."""
    await websocket.accept()
    
    # Store connection in a global set (use Redis in production)
    from app.api.dashboard import active_connections
    active_connections.append(websocket)
    
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back or process messages
            await websocket.send_json({"status": "connected", "message": "Alert stream active"})
    except WebSocketDisconnect:
        active_connections.remove(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        active_connections.remove(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
