
from fastapi import HTTPException
from api_caller.address_sq_token_manager import token_manager

# Decorator for retry logic
def retry_on_token_expiry(max_retries):
    def decorator(func):
        def wrapper(*args, **kwargs):
            retries = 0
            while retries <= max_retries:
                try:
                    return func(*args, **kwargs)
                except HTTPException as e:
                    if "401" in str(e.detail) and retries < max_retries:
                        # Refresh the token and retry
                        token_manager.fetch_token()
                        retries += 1
                    else:
                        raise e
        return wrapper
    return decorator