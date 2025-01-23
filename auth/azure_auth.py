from fastapi.responses import JSONResponse
from msal import ConfidentialClientApplication
from fastapi import HTTPException
import requests
from config import CLIENT_ID, CLIENT_SECRET, AUTHORITY, MS_USER_URL, SCOPES, REDIRECT_URI

# Initialize MSAL Confidential Client Application
# msal_client = ConfidentialClientApplication(
#     client_id=CLIENT_ID,
#     client_credential=CLIENT_SECRET,
#     authority=AUTHORITY,
# )

def get_msal_client():
    return ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY
    )
msal_client = get_msal_client()

def exchange_code_for_token(auth_code: str) -> dict:
    """Exchange the authorization code for an Access Token."""
    # result = msal_app.acquire_token_by_authorization_code(
    #     code=auth_code,
    #     scopes=SCOPES,
    #     redirect_uri=REDIRECT_URI,
    # )
    # if "error" in result:
    #     raise HTTPException(
    #         status_code=400,
    #         detail=f"Error acquiring token: {result.get('error_description', 'Unknown error')}",
    #     )
    # return result

    '''
     Added offline_access scope for refresh token
    '''
    token_response = msal_client.acquire_token_by_authorization_code(
        auth_code,
        scopes=[SCOPES],#["User.Read"],
        redirect_uri=REDIRECT_URI
    )

    if "error" in token_response:
        raise HTTPException(status_code=400, detail=token_response["error_description"])

    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")
    id_token = token_response.get("id_token")
    expires_in = token_response.get("expires_in")
    refresh_token_expires_in = token_response.get("ext_expires_in")  # Added field for refresh token expiration
    user_info = token_response.get("id_token_claims", {})

    response_data = {
        "username": user_info.get("name"),
        "email": user_info.get("preferred_username"),
        "roles": user_info.get("roles", []),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token,
        "expires_in": expires_in,
        "refresh_token_expires_in": refresh_token_expires_in
    }

    return JSONResponse(content=response_data)

def get_access_token_using_refresh_token(refresh_token: str):
    token_response = msal_client.acquire_token_by_refresh_token(
        refresh_token=refresh_token,
        scopes=[SCOPES],#["User.Read"]
    )

    if "error" in token_response:
        raise HTTPException(status_code=400, detail=token_response["error_description"])

    new_access_token = token_response.get("access_token")
    new_refresh_token = token_response.get("refresh_token")
    new_expires_in = token_response.get("expires_in")
    refresh_token_expires_in = token_response.get("ext_expires_in")
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "expires_in": new_expires_in,
        "refresh_token_expires_in": refresh_token_expires_in
    }

async def fetch_user_detail_from_MS(access_token:str):
    try:
        headers = {
            "Authorization":f"Bearer {access_token}",
            "Content_type":"application/json"
        }
        response = requests.get(MS_USER_URL, headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            return user_data
    except Exception as e:
        raise HTTPException(status_code=400, detail="Unable to fetch user details")

