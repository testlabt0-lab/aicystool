"""
Authentication and Authorization API
JWT-based authentication with RBAC support
"""

from fastapi import APIRouter, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, SecurityScopes
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
import bcrypt

from app.core.config import settings
from app.core.database import get_db
from app.models.user import User, UserRole, Token, TokenData

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/token",
    scopes={
        "admin": "Full administrative access",
        "analyst": "Security analysis access",
        "viewer": "Read-only access",
        "operator": "Operational access"
    }
)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def authenticate_user(username: str, password: str):
    """Authenticate user against database"""
    # In production, this would query the database
    # For demo, we'll use hardcoded admin user
    if username == "admin" and bcrypt.checkpw(password.encode(), settings.ADMIN_PASSWORD_HASH.encode()):
        return User(
            id="1",
            username="admin",
            email="admin@sentinel.ai",
            role=UserRole.ADMIN,
            disabled=False
        )
    elif username == "analyst" and password == "analyst123":
        return User(
            id="2",
            username="analyst",
            email="analyst@sentinel.ai",
            role=UserRole.ANALYST,
            disabled=False
        )
    elif username == "operator" and password == "operator123":
        return User(
            id="3",
            username="operator",
            email="operator@sentinel.ai",
            role=UserRole.OPERATOR,
            disabled=False
        )
    return None


async def get_current_user(
    security_scopes: SecurityScopes,
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get current authenticated user with scope validation"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_scopes = payload.get("scopes", [])
        token_data = TokenData(scopes=token_scopes, username=username)
    except JWTError:
        raise credentials_exception
    
    # Get user (in production, query database)
    user_roles = {
        "admin": UserRole.ADMIN,
        "analyst": UserRole.ANALYST,
        "operator": UserRole.OPERATOR
    }
    
    if username not in user_roles:
        raise credentials_exception
    
    user = User(
        id="1",
        username=username,
        email=f"{username}@sentinel.ai",
        role=user_roles[username],
        disabled=False
    )
    
    # Validate scopes
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    return user


@router.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 token endpoint for login"""
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Map roles to scopes
    role_scopes = {
        UserRole.ADMIN: ["admin", "analyst", "operator", "viewer"],
        UserRole.ANALYST: ["analyst", "operator", "viewer"],
        UserRole.OPERATOR: ["operator", "viewer"],
        UserRole.VIEWER: ["viewer"]
    }
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "scopes": role_scopes[user.role]
        },
        expires_delta=access_token_expires
    )
    
    refresh_token = create_refresh_token(data={"sub": user.username})
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/refresh", response_model=Token, tags=["Authentication"])
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    
    # Create new access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username},
        expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.get("/me", tags=["Authentication"])
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role.value,
        "disabled": current_user.disabled
    }


@router.post("/logout", tags=["Authentication"])
async def logout(token: str = Depends(oauth2_scheme)):
    """Logout user (invalidate token)"""
    # In production, add token to blacklist
    return {"message": "Successfully logged out"}


@router.get("/users", tags=["User Management"])
async def list_users(current_user: User = Depends(get_current_user)):
    """List all users (admin only)"""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Demo users
    return {
        "users": [
            {"username": "admin", "role": "admin", "email": "admin@sentinel.ai"},
            {"username": "analyst", "role": "analyst", "email": "analyst@sentinel.ai"},
            {"username": "operator", "role": "operator", "email": "operator@sentinel.ai"}
        ]
    }
