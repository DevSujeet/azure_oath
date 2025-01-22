

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse
from auth.azure_auth import msal_client, exchange_code_for_token, get_access_token_using_refresh_token
from config import REDIRECT_URI

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={404: {"description": "x_user_id field is required in header"}}
)

@router.get("/login", responses={
    302: {"description": "Redirects to Azure login page, call this from a browser"}
})
async def login():
    '''
    Redirects to Azure login page, call this from a browser
    http://localhost:8000/auth/login
    '''
    auth_url = msal_client.get_authorization_request_url(
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )
    return RedirectResponse(auth_url)

@router.get("/callback", tags=["Authentication"])
async def auth_redirect(code: str):
    reseult = exchange_code_for_token(auth_code=code)
    return reseult

@router.post("/refresh", tags=["Authentication"])
async def refresh_token_endpoint(refresh_token: str):
    result = get_access_token_using_refresh_token(refresh_token)
    return result