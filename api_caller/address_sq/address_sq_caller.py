
from fastapi import HTTPException
import requests
from decorators.address_sq_retry_decorator import retry_on_token_expiry
from api_caller.address_sq.address_sq_token_manager import token_manager
from typing import Protocol
from utils.json_file_reader import read_json_raw

class response_provider(Protocol):
    async def search_by_text(self, text:str):
        pass

    async def search_by_id(self, adbor_id:str):
        pass

    async def search_by_lat_log(self, lat:str, long:str, radius:float):
        pass    

addresSQ_api_token_max_retries = 2
class concrete_rest_api_caller(response_provider):
    @retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
    async def search_by_text(self, text:str):
        pass

    @retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
    async def search_by_id(self, adbor_id:str):
        pass

    @retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
    async def search_by_lat_log(self, lat:str, long:str, radius:float):
        pass

class concrete_file_json_reader(response_provider):
    async def search_by_text(self, text:str):
        result = await read_json_raw("some file path")
        return result

    async def search_by_id(self, adbor_id:str):
        pass

    async def search_by_lat_log(self, lat:str, long:str, radius:float):
        pass

class response_provider_factory(response_provider): 
    def __init__(self, is_local:bool):
        self.is_local = is_local
        self.caller = None
        if is_local:
            self.caller = concrete_file_json_reader()
        else:
            self.caller = concrete_rest_api_caller()
    
    async def search_by_text(self, text:str):
        response = await self.caller.search_by_text(text=text)
        return response

    async def search_by_id(self, adbor_id:str):
        response = await self.caller.search_by_id(adbor_id=adbor_id)
        return response

    async def search_by_lat_log(self, lat:str, long:str, radius:float):
        response = await self.caller.search_by_lat_log(lat=lat, long=long, radius=radius)
        return response


# # Example API endpoint using the token
# @retry_on_token_expiry(max_retries=addresSQ_api_token_max_retries)
# async def call_secured_api():
#     token = token_manager.get_token()
#     try:
#         # create proper request as required
#         response = requests.get(
#             "some url for address sq",
#             headers={"Authorization": f"Bearer {token}"},
#         )
#         response.raise_for_status()
#         return response.json()
#     except requests.exceptions.RequestException as e:
#         raise HTTPException(status_code=500, detail=f"API call failed: {e}")