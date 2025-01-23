import os
from dotenv import load_dotenv
from typing import Dict, Any
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load environment variables from .env file
# load_dotenv('.env')

class OAUTH_Settings(BaseSettings):
    tenant_id: str
    client_id: str
    client_secret: str
    redirect_uri: str
    # secret_key:str
    # algorithm:str

    model_config = SettingsConfigDict(
        # env_prefix=CACHE_ENV_PREFIX,  # Match prefix with your .env file #development_
        env_file='.env',
        populate_by_name=True,  # Use field aliases
        extra='ignore',  # Ignore extra inputs from the .env file
        env_file_encoding='utf-8',
    )

settings = OAUTH_Settings()

# Azure AD Configuration
TENANT_ID = settings.tenant_id
CLIENT_ID = settings.client_id
CLIENT_SECRET = settings.client_secret
REDIRECT_URI = settings.redirect_uri
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = f"api://{CLIENT_ID}/access_as_user" #["User.Read", "openid", "profile", "email"]

# JWT Validation
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
AUDIENCE = CLIENT_ID #f"api://{CLIENT_ID}"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


