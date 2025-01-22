from msal import ConfidentialClientApplication
from fastapi import HTTPException
from config import CLIENT_ID, CLIENT_SECRET, AUTHORITY, SCOPES, REDIRECT_URI

# Initialize MSAL Confidential Client Application
msal_app = ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY,
)

def exchange_code_for_token(auth_code: str) -> dict:
    """Exchange the authorization code for an Access Token."""
    result = msal_app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )
    if "error" in result:
        raise HTTPException(
            status_code=400,
            detail=f"Error acquiring token: {result.get('error_description', 'Unknown error')}",
        )
    return result
