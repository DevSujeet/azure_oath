import yaml
from typing import List, Dict

def load_roles_config(filepath: str) -> Dict[str, List[str]]:
    """Load roles and their permissions from a YAML file."""
    with open(filepath, "r") as file:
        config = yaml.safe_load(file)
    return config.get("roles", {})


ROLES_CONFIG = load_roles_config("config/roles.yaml")

# # Example: Accessing permissions for admin
# admin_permissions = ROLES_CONFIG["admin"]["permissions"]