import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Azure AD Configuration
TENANT_ID = os.getenv("TENANT_ID", "")
CLIENT_ID = os.getenv("CLIENT_ID", "")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/auth/callback")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read", "openid", "profile", "email"]

# JWT Validation
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
AUDIENCE = CLIENT_ID
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

