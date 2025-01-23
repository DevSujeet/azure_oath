from typing import Dict
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, Header, Security
from jwt import PyJWKClient
import requests
from auth.token_validator_jwt import inspect_token
from config import CLIENT_ID, JWKS_URL, AUDIENCE, ISSUER, TENANT_ID
from auth.azure_auth import msal_client, SCOPES

async def fetch_public_keys():
    """Fetch public keys from Azure's JWKS endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.get(JWKS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch JWKS keys")
        return response.json()["keys"]

async def verify_access_token(token: str) -> dict:
    """Verify the Access Token using Azure's JWKS."""
    try:
        # Decode the token header to get the key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # Fetch JWKS and find the matching key
        keys = await fetch_public_keys()
        key = next((k for k in keys if k["kid"] == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Key not found in JWKS")

        # Decode and verify the token
        payload = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
        return payload

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
##############################################
token_auth_scheme = HTTPBearer()

def get_public_keys():
    keys_url = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys?appid={CLIENT_ID}"
    response = requests.get(keys_url)
    response.raise_for_status()
    return response.json().get("keys", [])

def get_key_by_kid(kid, keys):
    for key in keys:
        if key["kid"] == kid:
            return key
    raise ValueError("Key not found")



def validate_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    """
    wroked
    """
    try:
        token = credentials.credentials
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Invalid token header, kid missing")

        # Retrieve public keys
        keys = get_public_keys()
        key = get_key_by_kid(kid, keys)

        # Verify token signature and payload
        decoded_token = jwt.decode(
            token,
            key,
            algorithms=key.get("alg"),
            audience=CLIENT_ID,
            issuer=ISSUER
        )

        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


#utitlit function to check if the user has the required role
def check_roles(required_role: str):
    def role_checker(decoded_token: dict = Depends(validate_token)):
        roles = decoded_token.get("roles", [])
        if required_role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role permissions")
        return decoded_token
    return role_checker

# security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(token_auth_scheme)):
    """Dependency to verify the Access Token and extract user details."""
    token = credentials.credentials
    payload = await verify_access_token(token) #decode(token) #
    return payload


async def decode(token: str):
    '''
        works
    '''
    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    data = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        options={"verify_exp": False},)
    return data

    
############################

# def get_user_info_no_validation(x_access_token: str = Header(...), x_id_token: str = Header(...)):
#     """Dependency to extract and validate tokens from headers."""
#     access_token = x_access_token#authorization.split(" ")[1]  # Extract Bearer token
#     token_info = {
#         "access_token": access_token,
#         "id_token": x_id_token
#     }

#     payload = _get_user_info(token_info)
#     return payload

# def _get_user_info(tokens: Dict):
#     """Verify the JWT token and return the payload."""
#     credentials_exception = HTTPException(
#         status_code=401,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )

#     expired_token_exception = HTTPException(
#         status_code=401,
#         detail="Token has expired",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         id_token = tokens.get("id_token")
#         access_token = tokens.get("access_token")

#         # Decode ID Token without validation
#         id_token_decoded = jwt.decode(id_token, "", options={"verify_signature": False})

#         # Decode Access Token without validation
#         access_token_decoded = jwt.decode(access_token, "", options={"verify_signature": False})

#         return {
#             "username": id_token_decoded.get("name"),
#             "email": id_token_decoded.get("preferred_username"),
#             "roles": id_token_decoded.get("roles", []),
#             "access_token_claims": access_token_decoded  # Contains access token claims
#         }
#     except jwt.ExpiredSignatureError:
#         # Handle expired token: Decode without verifying expiration to log user details
#         try:
#             payload = jwt.decode(access_token, "", options={"verify_signature": False,"verify_exp": False})
#             username = payload.get("username")
#             email = payload.get("email")
#             roles = payload.get("roles")
#             # Log details about the expired token
#             if username and email:
#                 print(f"Expired token for user: {username} ({email}), roles: {roles}")
#         except JWTError:
#             raise credentials_exception  # Raise if decoding fails entirely
#         # Token is expired but decoded successfully
#         raise expired_token_exception
    
#     except JWTError:
#         # Generic error for any other JWT issues
#         raise credentials_exception
