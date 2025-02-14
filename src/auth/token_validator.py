from typing import Dict
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, Header, Security
from jwt import PyJWKClient
import requests
from src.auth.token_validator_jwt import inspect_token
from src.config.config import CLIENT_ID, JWKS_URL, AUDIENCE, ISSUER, TENANT_ID
from src.auth.azure_auth import fetch_user_detail_from_MS, msal_client, SCOPES

############################ Method 1 to validate and decode token ############################################
async def fetch_public_keys():
    """Fetch public keys from Azure's JWKS endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.get(JWKS_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch JWKS keys")
        return response.json()["keys"]

async def verify_access_token(token: str) -> dict:
    """works Verify the Access Token using Azure's JWKS."""
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
############################ Method 2 to validate and decode token ############################################

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

async def validate_token(token:str):
    """
    wroked
    """
    try:
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

############################ Method 3 to validate and decode token ############################################
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


token_auth_scheme = HTTPBearer()
async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(token_auth_scheme)):
    """Dependency to verify the Access Token and extract user details."""
    token = credentials.credentials
    decoded_token = await validate_token(token=token)#verify_access_token(token) #decode(token) #

    # Extract details
    user_info_from_token = {
        "name": decoded_token.get("name"),
        "email": decoded_token.get("preferred_username"),  # Azure AD uses `preferred_username` for email
        "roles": decoded_token.get("roles", []),  # Roles might be a list
    }
    
    return user_info_from_token


#utitlit function to check if the user has the required role
def check_roles(required_role: str):
    def role_checker(decoded_token: dict = Depends(validate_token)):
        roles = decoded_token.get("roles", [])
        if required_role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role permissions")
        return decoded_token
    return role_checker
