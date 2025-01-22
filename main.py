# from fastapi import FastAPI, HTTPException
# from auth.azure_auth import exchange_code_for_token
# from config import CLIENT_ID, REDIRECT_URI, SCOPES, TENANT_ID
# from routes.protected import router as protected_router

# app = FastAPI()

# @app.get("/auth/login")
# def login():
#     """Redirect the user to Azure AD for login."""
#     login_url = (
#         f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize?"
#         f"client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope={' '.join(SCOPES)}"
#     )
#     return {"login_url": login_url}

# @app.get("/auth/callback")
# def callback(auth_code: str):
#     """Handle the callback from Azure AD."""
#     token_response = exchange_code_for_token(auth_code)
#     return {
#         "access_token": token_response["access_token"],
#         "expires_in": token_response["expires_in"],
#         "id_token": token_response.get("id_token"),
#     }

# # Include protected routes
# app.include_router(protected_router, prefix="/api")
######################################################################
# from fastapi import FastAPI, HTTPException, Depends, Request
# from fastapi.security import OAuth2AuthorizationCodeBearer
# from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
# from fastapi.openapi.models import OAuthFlowAuthorizationCode
# from fastapi.responses import RedirectResponse
# from jose import jwt
# import requests

#insert missing with MSAL lib usage

# # Custom OAuth2 Scheme for Swagger
# oauth2_flows = OAuthFlowsModel(
#     authorizationCode=OAuthFlowAuthorizationCode(
#         authorizationUrl=AUTHORIZATION_URL,
#         tokenUrl=TOKEN_URL,
#         scopes={"openid": "OpenID Connect scope"},
#     )
# )
# oauth2_scheme = OAuth2AuthorizationCodeBearer(
#     tokenUrl=TOKEN_URL, authorizationUrl=AUTHORIZATION_URL, auto_error=False
# )

# # In-memory store for tokens (for simplicity; use a proper database in production)
# users = {}

# @app.get("/")
# async def home():
#     """Public endpoint."""
#     return {"message": "Welcome to the app. Use /docs to test the OAuth flow."}

# @app.get("/auth/callback")
# async def auth_callback(request: Request):
#     """Handle the OAuth callback and exchange the code for tokens."""
#     code = request.query_params.get("code")
#     if not code:
#         raise HTTPException(status_code=400, detail="Authorization code not provided")

#     # Exchange the authorization code for tokens
#     token_data = {
#         "client_id": CLIENT_ID,
#         "client_secret": CLIENT_SECRET,
#         "grant_type": "authorization_code",
#         "code": code,
#         "redirect_uri": REDIRECT_URI,
#     }
#     response = requests.post(TOKEN_URL, data=token_data)
#     if response.status_code != 200:
#         raise HTTPException(status_code=400, detail="Failed to fetch tokens")

#     tokens = response.json()
#     id_token = tokens.get("id_token")
#     access_token = tokens.get("access_token")

#     # Validate the ID token
#     user_info = validate_token(id_token)

#     # Store user info and tokens (for demonstration purposes)
#     users[user_info["sub"]] = {
#         "user_info": user_info,
#         "access_token": access_token,
#         "id_token": id_token,
#     }

#     return {"message": "Authentication successful", "user": user_info}

# @app.get("/protected", dependencies=[Depends(oauth2_scheme)])
# async def protected_route(token: str = Depends(oauth2_scheme)):
#     """A protected route that requires a valid token."""
#     payload = validate_token(token)
#     return {"message": "Access granted", "user": payload}


# def validate_token(token: str):
#     """Validate and decode the ID token."""
#     response = requests.get(JWKS_URL)
#     jwks = response.json()
#     header = jwt.get_unverified_header(token)
#     key = next((key for key in jwks["keys"] if key["kid"] == header["kid"]), None)

#     if not key:
#         raise HTTPException(status_code=401, detail="Invalid token")

#     public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
#     payload = jwt.decode(token, public_key, algorithms=[ALGORITHM], audience=CLIENT_ID)

#     return payload


# # Add OAuth2 scheme to Swagger
# app.openapi_schema["components"]["securitySchemes"] = {
#     "OAuth2AuthorizationCode": {
#         "type": "oauth2",
#         "flows": {
#             "authorizationCode": {
#                 "authorizationUrl": AUTHORIZATION_URL,
#                 "tokenUrl": TOKEN_URL,
#                 "scopes": {"openid": "OpenID Connect scope"},
#             }
#         },
#     }
# }
# app.openapi_schema["security"] = [{"OAuth2AuthorizationCode": []}]

# if __name__ == "__main__":
#     import uvicorn

#     uvicorn.run(app, host="localhost", port=8000)

######################################################################

# from fastapi import FastAPI, Depends, HTTPException
# from fastapi.responses import RedirectResponse, JSONResponse
# from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
# from msal import ConfidentialClientApplication
# from dotenv import load_dotenv
# import os

# load_dotenv()

# app = FastAPI()

# insert the missing variable here

# authority = f"https://login.microsoftonline.com/{TENANT_ID}"
# scopes = ["User.Read"]

# msal_client = ConfidentialClientApplication(
#     client_id=CLIENT_ID,
#     client_credential=CLIENT_SECRET,
#     authority=authority
# )

# @app.get("/auth/login", tags=["Authentication"])
# async def login():
#     auth_url = msal_client.get_authorization_request_url(
#         scopes,
#         redirect_uri=REDIRECT_URI
#     )
#     return RedirectResponse(auth_url)

# @app.get("/auth/callback", tags=["Authentication"])
# async def auth_redirect(code: str):
#     token_response = msal_client.acquire_token_by_authorization_code(
#         code,
#         scopes=scopes,
#         redirect_uri=REDIRECT_URI
#     )

#     if "error" in token_response:
#         raise HTTPException(status_code=400, detail=token_response["error_description"])

#     user_info = token_response.get("id_token_claims", {})
#     return JSONResponse({
#         "username": user_info.get("name"),
#         "email": user_info.get("preferred_username"),
#         "roles": user_info.get("roles", [])
#     })

# # Swagger documentation adjustments
# @app.get("/auth/userinfo", tags=["Authentication"])
# async def user_info():
#     return {"message": "User info endpoint"}

#######################above worked#############################
from fastapi import FastAPI, HTTPException, Depends
import requests
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from msal import ConfidentialClientApplication
from jose import jwt



CLIENT_ID = "b564554a-b011-4583-bdaa-3b70da304682"
CLIENT_SECRET = "87w8Q~_cI1ZEDdpbqd-KRjzkSnjUmNdSstqoNdrA"
TENANT_ID = "1452a59b-1e9c-4484-b770-fb10b4153b92"
REDIRECT_URI = "http://localhost:8000/auth/callback"

token_auth_scheme = HTTPBearer()

def get_msal_client():
    return ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}"
    )
msal_client = get_msal_client()

# def validate_token(credentials: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
#     try:
#         token = credentials.credentials
#         decoded_token = msal_client.acquire_token_silent(
#             scopes=["User.Read"], account=None
#         )
#         if not decoded_token:
#             raise HTTPException(status_code=401, detail="Token validation failed")
#         return decoded_token
#     except Exception as e:
#         raise HTTPException(status_code=401, detail=str(e))

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

def check_roles(required_role: str):
    def role_checker(decoded_token: dict = Depends(validate_token)):
        roles = decoded_token.get("roles", [])
        if required_role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role permissions")
        return decoded_token
    return role_checker

app = FastAPI()

@app.get("/auth/login", tags=["Authentication"], responses={
    302: {"description": "Redirects to Azure login page"}
})
async def login():
    auth_url = msal_client.get_authorization_request_url(
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )
    return RedirectResponse(auth_url)

@app.get("/auth/callback", tags=["Authentication"])
async def auth_redirect(code: str):
    '''
     Added offline_access scope for refresh token
    '''
    token_response = msal_client.acquire_token_by_authorization_code(
        code,
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )

    if "error" in token_response:
        raise HTTPException(status_code=400, detail=token_response["error_description"])

    access_token = token_response.get("access_token")
    refresh_token = token_response.get("refresh_token")
    expires_in = token_response.get("expires_in")
    refresh_token_expires_in = token_response.get("ext_expires_in")  # Added field for refresh token expiration
    user_info = token_response.get("id_token_claims", {})

    response_data = {
        "username": user_info.get("name"),
        "email": user_info.get("preferred_username"),
        "roles": user_info.get("roles", []),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
        "refresh_token_expires_in": refresh_token_expires_in
    }

    return JSONResponse(content=response_data)

@app.post("/auth/refresh", tags=["Authentication"])
async def refresh_token_endpoint(refresh_token: str):
    token_response = msal_client.acquire_token_by_refresh_token(
        refresh_token=refresh_token,
        scopes=["User.Read"]
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

@app.get("/protected/resource", tags=["Protected"], dependencies=[Depends(validate_token)])
async def protected_resource():
    return {"message": "This is a protected resource"}

@app.get("/protected/admin", tags=["Protected"], dependencies=[Depends(validate_token)])
async def admin_resource(decoded_token: dict = Depends(validate_token)):
    roles = decoded_token.get("roles", [])
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Insufficient role permissions")
    return {"message": "Welcome, Admin"}

######################################################################