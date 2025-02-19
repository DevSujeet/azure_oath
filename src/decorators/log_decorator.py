import time

from fastapi.responses import StreamingResponse
from src.auth.token_validator import getUserInfo_from_request
from src.config.log_config import logger_api
from fastapi import HTTPException, Request, Response, Depends
from functools import wraps
import json


# ✅ Fully Generic Logging Decorator (Independent of Schema & Dependencies)
def log_request_response(log_route=True,log_response=True):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not log_route:
                return await func(*args, **kwargs)  # Skip logging

            start_time = time.time()  # ✅ Start timing the request

            # ✅ Extract `Request` object from `args` or `kwargs`
            request: Request = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                request = Request(scope={})  # 🚨 Only as a last resort

            # ✅ Extract Authorization header & validate token
            user_info = "Unknown"
            permissions = "Unknown"

            user_info = await getUserInfo_from_request(request)

            # ✅ Capture Request Body (for all methods, when applicable)
            request_body = None
            try:
                request_body = await request.body()
                request_body = request_body.decode("utf-8") if request_body else None
            except Exception as e:
                logger_api.warning(f"Failed to read request body: {str(e)}")
                request_body = None  # Ensure no crash on read failure

            # ✅ Capture request details
            request_log = {
                "user": user_info.get("email", "Unknown"),
                "user_name": user_info.get("name", "Unknown"),
                "roles": user_info.get("roles", "Unknown"),
                "ip_address": request.client.host,
                "method": request.method,
                "path": request.url.path,
                "query_params": dict(request.query_params),  # Capture query params separately
                "request_body": request_body,
            }

            response = await func(*args, **kwargs)  # Call the actual function

            # ✅ Calculate Response Time
            response_time_ms = round((time.time() - start_time) * 1000, 2)  # Convert to milliseconds

            if log_response:
            # ✅ Handle Response Safely
                response_body = None
                status_code = 200  # Default if not found

                if isinstance(response, Response):  # FastAPI `Response` object
                    try:
                        response_body = response.body.decode("utf-8") if hasattr(response, "body") else None
                    except Exception:
                        response_body = "[Streaming Response]"
                    status_code = response.status_code
                elif isinstance(response, StreamingResponse):  # Handle streaming responses
                    response_body = "[Streaming Response]"
                    status_code = response.status_code
                elif isinstance(response, dict):  # If response is a dictionary (JSON)
                    response_body = json.dumps(response)
                    status_code = 200
                else:  # Other response types
                    response_body = str(response)
                    status_code = getattr(response, "status_code", 200)

                response_log = {
                    "status_code": status_code,
                    "response_body": response_body,
                    "response_time_ms": response_time_ms  # ✅ Log response time
                }
            else:
                response_log = {}

            # ✅ Log request and response
            log_data = {**request_log, **response_log}
            logger_api.info(f"Request Log: {json.dumps(log_data)}")

            return response  # Return the original response
        return wrapper
    return decorator
