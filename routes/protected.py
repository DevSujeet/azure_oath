from fastapi import APIRouter, Depends, Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.token_validator import get_current_user, validate_token
from role_dependency import role_based_authorization_with_optional_permissions_oauth

router = APIRouter(
    prefix="/protected",
    tags=["Protected"],
    responses={404: {"description": "x_user_id field is required in header"}}
)


@router.get("/get_current_user")
async def protected_route(user: dict = Depends(get_current_user)):
    """A basic protected route."""
    
    return {"message": "Access granted", "user": user}

@router.get("/check_admin_role")
async def admin_route(user: dict = Depends(get_current_user)):
    """Route accessible only by users with the 'Admin' role."""
    roles = user.get("roles", [])
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="Permission denied")
    return {"message": "Welcome Admin", "user": user}

#############
@router.get("/check_for_valid_token", dependencies=[Depends(validate_token)])
async def protected_resource():
    '''
    validate_token is still called as a dependency,
      though the validate_token is not used in the function call.
    '''
    return {"message": "This is a protected resource"}

@router.get("/check_admin_role_2") #, dependencies=[Depends(validate_token)]
async def admin_resource(decoded_token: dict = Depends(validate_token)):
    '''
    dependencies=[Depends(validate_token)]: This ensures validate_token is executed before the route handler (admin_resource) is called.
    decoded_token: dict = Depends(validate_token): This also executes validate_token, but it injects the returned value (decoded_token) into the route handler as a parameter.

This leads to duplicate execution of validate_token. While it won't cause errors, it is unnecessary.
    you do not need to specify dependencies=[Depends(validate_token)] in this case
    because decoded_token: dict = Depends(validate_token) already ensures:
    - validate_token is called as a dependency
    '''
    roles = decoded_token.get("roles", [])
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role permissions")
    return {"message": "Welcome, Admin"}


@router.get("/require_permission_test")
async def permission_route(user: dict = Depends(role_based_authorization_with_optional_permissions_oauth(["read_item"]))):
    """Example of an editor-only route."""
    return {"message": "Welcome Editor", "user": user}



