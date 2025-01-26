from asyncio import Lock
import time
from fastapi import HTTPException
import requests
from pydantic import BaseModel, ValidationError, Field

# Define the Pydantic model
class AuthResponse(BaseModel):
    status: str
    token: str 
    expires_in: int
    message: str

# # Function to authenticate
# def authenticate(url: str, client_id: str, client_secret: str, certificate_path: str):
#     data = {
#         "client_id": client_id,
#         "client_secret": client_secret
#     }

#     try:
        
#         with open(certificate_path, "rb") as cert_file:
#             files = {"certificate": cert_file}
            
#             response = requests.post(url, files=files, data=data)
            
#             response.raise_for_status()
            
#             response_data = AuthResponse.model_validate(response.json())
            
#     except ValidationError as ve:
#         print(f"Validation Error: {ve}")
#     except requests.exceptions.RequestException as re:
#         print(f"Request Error: {re}")
#     except ValueError:
#         print("Failed to decode JSON response")


# Token Manager
class TokenManager:
    def __init__(self, auth_url: str,
                client_id: str,
                client_secret: str,
                max_retries: int = 2):
        self.auth_url = auth_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.expires_at = 0
        self.max_retries = max_retries
        self.lock = Lock()

    def fetch_token(self):
        """Fetch a new token from the authentication API."""
        with self.lock:
            try:
                response = requests.post(
                    self.auth_url,
                    data={"client_id": self.client_id,
                        "client_secret": self.client_secret},
                )
                response.raise_for_status()
                token_data = response.json()
                self.token = token_data["token"]
                self.expires_at = time.time() + token_data["expires_in"]
            except requests.exceptions.RequestException as e:
                raise HTTPException(status_code=500, detail=f"Failed to fetch token: {e}")

    def get_token(self):
        """Get a valid token, refreshing it if necessary."""
        if not self.token or time.time() >= self.expires_at:
            self.fetch_token()
        return self.token


token_manager = TokenManager(
    auth_url="https://api.example.com/auth",
    client_id="your_client_id",
    client_secret="your_client_secret",
)