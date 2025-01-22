import httpx
from jose import jwt, JWTError
from fastapi import HTTPException
from config import JWKS_URL, AUDIENCE, ISSUER

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
