from ast import Dict, List
from typing import List, Dict
from fastapi import Depends, HTTPException, Request
# from src.auth_saml.auth import get_current_user
from auth.token_validator import get_current_user
from utils.roles_utils import ROLES_CONFIG

def check_permission(role: str, permission: str):
    """Check if a role has the required permission."""
    role_permissions = ROLES_CONFIG.get(role, {}).get("permissions", [])
    if permission not in role_permissions:
        raise HTTPException(status_code=403, detail="Permission Denied")

async def role_based_authorization(permission: str):
    async def wrapper(request: Request):
        # Extract user role from request headers (or other sources like JWT)
        user_role = request.headers.get("X-User-Role")
        if not user_role:
            raise HTTPException(status_code=401, detail="Role not provided")
        check_permission(user_role, permission)
    return wrapper


def role_based_authorization(permission: str):
    '''
    This dependency function will be used in the FastAPI route to check
      if the user has the required permission.
      get_current_user function is used to extract the user details from the JWT token.
    Check:- if the user has the required permission.
    '''
    async def wrapper(current_user: Dict = Depends(get_current_user)):
        # Extract user roles
        user_roles = current_user.get("roles", [])
        
        # Check if any role of the user has the required permission
        for role in user_roles:
            role_permissions = ROLES_CONFIG.get(role, {}).get("permissions", [])
            if permission in role_permissions:
                return  # Permission granted

        # If no role matches, raise an exception
        raise HTTPException(status_code=403, detail="Permission Denied")
    
    return wrapper


# def role_based_authorization_for_optional_permissions_saml(permissions: List[str]):
#     '''
#     This dependency function will be used in the FastAPI route to check
#       if the user has the required permission.
#       get_current_user function is used to extract the user details from the JWT token.
#     Check:- if the user has the required permissions.https://www.youtube.com/shorts/iowRsiDE6-Q
#       this is required when multiple permissions can be allowed.
#       eg:- read and *read (restricted read - to read only the non-restricted docs)
#     '''
#     async def wrapper(current_user: Dict = Depends(get_current_user)):
#         # Extract user roles
#         user_roles = current_user.get("roles", [])
        
#         # Check if any role of the user has the required permission
#         permissions_granted = []
#         for role in user_roles:
#             role_permissions = ROLES_CONFIG.get(role, {}).get("permissions", [])
#             common_permission = [item for item in permissions if item in role_permissions]
#             if common_permission:
#                 permissions_granted.extend(common_permission)
            
#         # If no role matches, raise an exception
#         if len(permissions_granted) == 0:
#             raise HTTPException(status_code=403, detail="Permission Denied")
        
#         return {
#                 "current_user":current_user,
#                 "permissions_granted": permissions_granted
#             }
    
#     return wrapper


def role_based_authorization_with_optional_permissions_oauth(permissions: List[str]):
    '''
    This dependency function will be used in the FastAPI route to check
      if the user has the required permission.
      get_current_user function is used to extract the user details from the JWT token.
    Check:- if the user has the required permissions.
      this is required when multiple permissions can be allowed.
      eg:- read and *read (restricted read - to read only the non-restricted docs)
    '''
    async def wrapper(current_user: Dict = Depends(get_current_user)):
        # Extract user roles
        user_roles = current_user.get("roles", [])
        
        # Check if any role of the user has the required permission
        permissions_granted = []
        for role in user_roles:
            role_permissions = ROLES_CONFIG.get(role, {}).get("permissions", [])
            common_permission = [item for item in permissions if item in role_permissions]
            if common_permission:
                permissions_granted.extend(common_permission)
            
        # If no role matches, raise an exception
        if len(permissions_granted) == 0:
            raise HTTPException(status_code=403, detail="Permission Denied")
        
        return {
                "current_user":current_user,
                "permissions_granted": permissions_granted
            }
    
    return wrapper