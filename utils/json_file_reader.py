import asyncio
import json
import aiofiles
from pathlib import Path
from typing import Type, TypeVar, List, Optional, Union
from pydantic import BaseModel, ValidationError


async def read_json_raw(file_path: str) -> Optional[Union[dict, list]]:
    """
    Reads a JSON file and returns its content as a raw dictionary or list.

    :param file_path: Path to the JSON file.
    :return: Dictionary (if JSON object) or List (if JSON array), or None if an error occurs.
    """
    file = Path(file_path)

    if not file.exists():
        print(f"Error: File {file_path} not found.")
        return None

    try:
        async with aiofiles.open(file, mode="r", encoding="utf-8") as f:
            data = await f.read()
            json_data = json.loads(data)  # Parse JSON into Python dict or list
            return json_data

    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file {file_path}: {e}")
    except Exception as err:
        print(f"Unexpected error reading file {file_path}: {err}")

    return None


# Define a generic type variable T (must be a subclass of BaseModel)
# This would be used to specify the type of the model to parse the JSON data
T = TypeVar("T", bound=BaseModel)


async def read_json_file(file_path: str, model: Type[T]) -> Optional[T]:
    """
    Reads a JSON file and parses it into a single instance of the given Pydantic model.

    :param file_path: Path to the JSON file.
    :param model: Pydantic model class to parse the JSON object.
    :return: A single instance of model T or None if error occurs.
    """
    file = Path(file_path)

    if not file.exists():
        print(f"Error: File {file_path} not found.")
        return None

    try:
        async with aiofiles.open(file, mode="r", encoding="utf-8") as f:
            data = await f.read()
            '''
                Takes a JSON string as input.
                Converts it into a Python dict (if JSON object) or a list (if JSON array).
            '''
            json_data = json.loads(data)  # Parse JSON
            return model(**json_data)  # Validate and return as model T

    except (json.JSONDecodeError, ValidationError) as e:
        print(f"Error parsing JSON file {file_path}: {e}")
    except Exception as err:
        print(f"Unexpected error reading file {file_path}: {err}")

    return None


async def read_json_list(file_path: str, model: Type[T]) -> Optional[List[T]]:
    """
    Reads a JSON file and parses it into a list of instances of the given Pydantic model.

    :param file_path: Path to the JSON file.
    :param model: Pydantic model class to parse the JSON list.
    :return: A list of model T instances or None if error occurs.
    """
    file = Path(file_path)

    if not file.exists():
        print(f"Error: File {file_path} not found.")
        return None

    try:
        async with aiofiles.open(file, mode="r", encoding="utf-8") as f:
            data = await f.read()
            json_data = json.loads(data)  # Parse JSON
            return [model(**item) for item in json_data]  # Validate each item as model T

    except (json.JSONDecodeError, ValidationError) as e:
        print(f"Error parsing JSON file {file_path}: {e}")
    except Exception as err:
        print(f"Unexpected error reading file {file_path}: {err}")

    return None


# Example Pydantic Model
class User(BaseModel):
    id: int
    name: str
    email: str


# # Example usage
# async def main():
#     # Read a single object
#     user = await read_json_file("user.json", User)
#     print("Single User:", user)

#     # Read a list of objects
#     users = await read_json_list("users.json", User)
#     print("User List:", users)


# # Run async function
# asyncio.run(main())
