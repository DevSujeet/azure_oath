from fastapi import APIRouter, Depends, Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.token_validator import verify_access_token

router = APIRouter()
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Dependency to verify the Access Token and extract user details."""
    token = credentials.credentials
    payload = await verify_access_token(token)
    return payload

@router.get("/protected")
async def protected_route(user: dict = Depends(get_current_user)):
    """A basic protected route."""
    return {"message": "Access granted", "user": user}

@router.get("/admin")
async def admin_route(user: dict = Depends(get_current_user)):
    """Route accessible only by users with the 'Admin' role."""
    roles = user.get("roles", [])
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"message": "Welcome Admin", "user": user}
