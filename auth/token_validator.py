from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, Security
import requests
from config import CLIENT_ID, JWKS_URL, AUDIENCE, ISSUER, TENANT_ID

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

    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired access token: {str(e)}")
##############################################


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


token_auth_scheme = HTTPBearer()
def validate_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    try:
        token = credentials.credentials
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Invalid token header")

        # Retrieve public keys
        keys = get_public_keys()
        key = get_key_by_kid(kid, keys)

        # Verify token signature and payload
        decoded_token = jwt.decode(
            token,
            key,
            algorithms=key.get("alg"),
            audience=CLIENT_ID,
            issuer=f"https://sts.windows.net/{TENANT_ID}/"
        )

        return decoded_token
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    

# def validate_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
#     try:
#         token = credentials.credentials
#         decoded_token = jwt.decode(token, options={"verify_signature": False})
#         if not decoded_token:
#             raise HTTPException(status_code=401, detail="Invalid token")

#         # Optional: Verify issuer and audience (for production environments)
#         issuer = decoded_token.get("iss")
#         audience = decoded_token.get("aud")
#         if issuer != f"https://login.microsoftonline.com/{TENANT_ID}/v2.0" or audience != CLIENT_ID:
#             raise HTTPException(status_code=401, detail="Token validation failed")

#         return decoded_token
#     except jwt.ExpiredSignatureError:
#         raise HTTPException(status_code=401, detail="Token expired")
#     except jwt.InvalidTokenError:
#         raise HTTPException(status_code=401, detail="Invalid token")


#utitlit function to check if the user has the required role
def check_roles(required_role: str):
    def role_checker(decoded_token: dict = Depends(validate_token)):
        roles = decoded_token.get("roles", [])
        if required_role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role permissions")
        return decoded_token
    return role_checker

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Dependency to verify the Access Token and extract user details."""
    token = credentials.credentials
    payload = await verify_access_token(token)
    return payload