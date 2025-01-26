
from fastapi import HTTPException
import requests
from decorators.address_sq_retry_decorator import retry_on_token_expiry
from api_caller.address_sq.address_sq_token_manager import token_manager

addresSQ_api_token_max_retries = 2
@retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
async def address_sq_search_by_text(text:str):
    pass

@retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
async def address_sq_search_by_id(adbor_id:str):
    pass

@retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
async def address_sq_search_by_id(adbor_id:str):
    pass


# Example API endpoint using the token
@retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
async def call_secured_api():
    token = token_manager.get_token()
    try:
        # create proper request as required
        response = requests.get(
            "some url for address sq",
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"API call failed: {e}")