import logging
import sys
import json
import httpx
from logging import StreamHandler


settings = {
    "LOG_LEVEL": "DEBUG",  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
    "JSON_LOGGING": False,
}

# Function to fetch log level from settings
def get_log_level(settings):
    return getattr(logging, settings.get("LOG_LEVEL", "DEBUG").upper(), logging.DEBUG)

# Function to determine log format
def get_formatter(json_logging=False):
    if json_logging:
        return logging.Formatter(
            json.dumps({
                "timestamp": "%(asctime)s",
                "logger": "%(name)s",
                "level": "%(levelname)s",
                "message": "%(message)s",
                "function": "%(funcName)s",
                "path": "%(pathname)s"
            }),
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        return logging.Formatter(
            "\n%(asctime)s | %(name)s | %(levelname)s | %(message)s\n[Function: %(funcName)s] [Path: %(pathname)s]",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    
# Function to configure logging
def configure_logging(settings):
    logger = logging.getLogger("FunctionApp-Internal")
    logger.setLevel(get_log_level(settings))

    # Clear existing handlers before adding new ones
    if logger.hasHandlers():
        logger.handlers.clear()

    # Console Handler
    stream_handler = StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(get_formatter(json_logging=settings.get("JSON_LOGGING", False)))
    logger.addHandler(stream_handler)

# Initialize logger AFTER declaring settings
logger = configure_logging(settings)