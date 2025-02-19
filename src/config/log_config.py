import logging
import sys
import json
import httpx
from logging import StreamHandler

# Example settings dictionary (Declared First)
# This can be moved to a separate settings file.
settings = {
    "LOG_LEVEL": "DEBUG",  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
    "JSON_LOGGING": False,  # Set to True for structured JSON logs (Splunk preferred)
    "SPLUNK_ENABLED": False ,  # Toggle Splunk logging
    "SPLUNK_URL": "http://your-splunk-server:8088",  # Replace with actual Splunk HEC URL
    "SPLUNK_TOKEN": "your-splunk-token",  # Replace with actual Splunk HEC token
    "SPLUNK_INDEX": "fastapi_logs"
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

# Custom Splunk HEC Handler supporting both JSON & Plain Text
class SplunkHECHandler(logging.Handler):
    def __init__(self, splunk_url, token, index="main", json_logging=True):
        super().__init__()
        self.splunk_url = f"{splunk_url}/services/collector"
        self.token = token
        self.index = index
        self.json_logging = json_logging  # Determines log format

    def emit(self, record):
        log_entry = self.format(record)
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json"
        }
        
        # Prepare data payload for Splunk
        data = {
            "event": log_entry if self.json_logging else {"message": log_entry},  # Sends as JSON if enabled
            "index": self.index,
            "sourcetype": "_json" if self.json_logging else "_raw"  # Different sourcetype for plain text
        }
        
        try:
            with httpx.Client(timeout=5.0) as client:  # Synchronous HTTP call
                response = client.post(self.splunk_url, headers=headers, json=data)
                if response.status_code not in [200, 201, 202]:
                    print(f"Failed to send log to Splunk: {response.text}")
        except httpx.RequestError as e:
            print(f"Splunk logging error: {e}")

# Function to configure logging
def configure_logging(settings):
    logger = logging.getLogger("fastapi_logger")
    logger.setLevel(get_log_level(settings))

    # Clear existing handlers before adding new ones
    if logger.hasHandlers():
        logger.handlers.clear()

    # Console Handler
    stream_handler = StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(get_formatter(json_logging=settings.get("JSON_LOGGING", False)))
    logger.addHandler(stream_handler)

    # Splunk HEC Handler (if enabled)
    if settings.get("SPLUNK_ENABLED", False):
        splunk_handler = SplunkHECHandler(
            splunk_url=settings.get("SPLUNK_URL"),
            token=settings.get("SPLUNK_TOKEN"),
            index=settings.get("SPLUNK_INDEX", "main"),
            json_logging=settings.get("JSON_LOGGING", False)  # Control JSON formatting
        )
        splunk_handler.setLevel(logging.INFO)
        # splunk_handler.setFormatter(get_formatter(json_logging=settings.get("JSON_LOGGING", False)))
        splunk_handler.setFormatter(get_formatter(json_logging=True))  # Always use JSON for Splunk
        logger.addHandler(splunk_handler)

    return logger

# Initialize logger AFTER declaring settings
# use this logger with logger dependency.
logger_api = configure_logging(settings)



# # Example usage in any file
# from src.config.log_config import logger
# ----------------------------------------------------------------------------------------------------------------
# logger.debug("Debugging mode enabled.")---lowest
# logger.info("Application started.")
# logger.warning("This is a warning.")
# logger.error("An error occurred.")
# logger.critical("Critical issue!") -- highest


#####################################################
# import logging
# from logging import StreamHandler
# from colorlog import ColoredFormatter
# import logging
# import sys

# # Configure logging
# logger = logging.getLogger("fastapi_logger")  # Create a logger
# logger.setLevel(logging.DEBUG)  # Set the base logger level (captures all levels)

# # Create a StreamHandler for logging to console
# stream_handler = StreamHandler(sys.stdout)
# stream_handler.setLevel(logging.INFO)  # Set log level for this handler

# # Add function name and file path to the log format (each variable on a new line)
# formatter = logging.Formatter(
#     "\n%(asctime)s\n%(name)s\n%(levelname)s\n%(message)s\n[Function: %(funcName)s]\n[Path: %(pathname)s]\n",
#     datefmt="%Y-%m-%d %H:%M:%S",
# )
# stream_handler.setFormatter(formatter)

# # Add the StreamHandler to the logger
# logger.addHandler(stream_handler)

################################################

# -----colored logs
# # Configure logging
# logger = logging.getLogger("fastapi_logger")
# logger.setLevel(logging.DEBUG)

# # Set up color formatter
# color_formatter = ColoredFormatter(
#     "\n%(asctime)s\n%(name)s\n%(levelname)s\n%(message)s\n[Function: %(funcName)s]\n[Path: %(pathname)s]\n",
#     datefmt="%Y-%m-%d %H:%M:%S",
#     log_colors={
#         "DEBUG": "cyan",
#         "INFO": "green",
#         "WARNING": "yellow",
#         "ERROR": "red",
#         "CRITICAL": "bold_red",
#     },
#     reset=True,  # Ensure ANSI reset codes are used
#     secondary_log_colors={},  # No additional colors for now
#     style="%",
# )

# # Create a console handler and attach the color formatter
# console_handler = logging.StreamHandler()
# console_handler.setLevel(logging.DEBUG)
# console_handler.setFormatter(color_formatter)
# logger.addHandler(console_handler)