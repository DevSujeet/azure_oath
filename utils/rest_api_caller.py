import httpx
import asyncio
from typing import Optional, Type, TypeVar, List, Dict, Any, Union
from pydantic import BaseModel, ValidationError

# Define a generic type T (must be a subclass of BaseModel)
T = TypeVar("T", bound=BaseModel)
async def make_request_single(
    method: str,
    url: str,
    model: Type[T],
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
) -> Optional[T]:
    """
    Generic async function to make API requests and parse a single object response.

    :param method: HTTP method (GET, POST, etc.)
    :param url: API endpoint URL
    :param model: Pydantic model class to parse response into a single object.
    :param params: Dictionary of query parameters.
    :param body: Dictionary of JSON body.
    :param headers: Dictionary of request headers.
    :param timeout: Request timeout in seconds.
    :return: Parsed API response as model T, or None if an error occurs.
    """
    headers = headers or {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=body,
                headers=headers,
            )
            response.raise_for_status()

            try:
                return model(**response.json())  # Validate response using Pydantic
            except ValidationError as e:
                print(f"Validation error: {e}")
                print(f"Raw Response: {response.json()}")
                return None

        except httpx.HTTPStatusError as http_err:
            print(f"HTTP error: {http_err}")
        except httpx.RequestError as req_err:
            print(f"Request error: {req_err}")
        except Exception as err:
            print(f"Unexpected error: {err}")

    return None


async def make_request_list(
    method: str,
    url: str,
    model: Type[T],
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
) -> Optional[List[T]]:
    """
    Generic async function to make API requests and parse a list of objects response.

    :param method: HTTP method (GET, POST, etc.)
    :param url: API endpoint URL
    :param model: Pydantic model class to parse response into a list of objects.
    :param params: Dictionary of query parameters.
    :param body: Dictionary of JSON body.
    :param headers: Dictionary of request headers.
    :param timeout: Request timeout in seconds.
    :return: List of parsed API responses as model T, or None if an error occurs.
    """
    headers = headers or {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=body,
                headers=headers,
            )
            response.raise_for_status()

            try:
                return [model(**item) for item in response.json()]  # Validate list response
            except ValidationError as e:
                print(f"Validation error: {e}")
                print(f"Raw Response: {response.json()}")
                return None

        except httpx.HTTPStatusError as http_err:
            print(f"HTTP error: {http_err}")
        except httpx.RequestError as req_err:
            print(f"Request error: {req_err}")
        except Exception as err:
            print(f"Unexpected error: {err}")

    return None


async def make_request_raw(
    method: str,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 10,
) -> Optional[Union[dict, list]]:
    """
    Generic async function to make API requests and return raw JSON response.

    :param method: HTTP method (GET, POST, etc.).
    :param url: API endpoint URL.
    :param params: Dictionary of query parameters.
    :param body: Dictionary of JSON body.
    :param headers: Dictionary of request headers.
    :param timeout: Request timeout in seconds.
    :return: Raw JSON response as dict or list, or None if an error occurs.
    """
    headers = headers or {"Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=body,
                headers=headers,
            )
            response.raise_for_status()
            return response.json()  # Return raw JSON response

        except httpx.HTTPStatusError as http_err:
            print(f"HTTP error: {http_err}")
        except httpx.RequestError as req_err:
            print(f"Request error: {req_err}")
        except Exception as err:
            print(f"Unexpected error: {err}")

    return None


# # Example Pydantic Model
# class User(BaseModel):
#     id: int
#     name: str
#     email: str


# # Example usage
# async def main():
#     BASE_URL = "https://jsonplaceholder.typicode.com/users"

#     # Fetch a single user
#     user = await make_request_single("GET", BASE_URL + "/1", User)
#     print("Single User:", user)

#     # Fetch a list of users
#     users = await make_request_list("GET", BASE_URL, User)
#     print("User List:", users)

#     # Fetch raw JSON data
#     raw_data = await make_request_raw("GET", BASE_URL)
#     print("Raw JSON Data:", raw_data)


# # Run async function
# asyncio.run(main())
