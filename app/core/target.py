from enum import Enum
import ipaddress
from typing import Optional
from urllib.parse import urlparse


class TargetType(Enum):
    WEBSITE = "website"
    HOST = "host"
    UNKNOWN = "unknown"


class Target:
    def __init__(self, raw_input: str, normalized_value: str, target_type: TargetType):
        self.raw_input = raw_input
        self.normalized_value = normalized_value
        self.target_type = target_type

    def __repr__(self) -> str:
        return f"Target(type={self.target_type.value}, value='{self.normalized_value}')"


def parse_target(raw_input: str) -> Target:
    """
    Parses, validates, and normalizes a user-provided target string.
    Can be a website URL (e.g., https://example.com) or an IP address (e.g., 127.0.0.1).
    Rejects invalid formats and out-of-scope/malformed targets.
    """
    cleaned_input = raw_input.strip()
    if not cleaned_input:
        raise ValueError("Target input cannot be empty.")

    # 1. Check if the input is a valid IP address (IPv4 or IPv6)
    ip_target = _try_parse_ip(cleaned_input)
    if ip_target:
        return Target(
            raw_input=raw_input,
            normalized_value=ip_target,
            target_type=TargetType.HOST
        )

    # 2. If not an IP, treat/parse as a website URL using urllib.parse
    url_to_parse = cleaned_input
    if not url_to_parse.startswith(("http://", "https://")):
        url_to_parse = f"https://{url_to_parse}"

    parsed_url = urlparse(url_to_parse)

    # Validate netloc and host shape
    if not parsed_url.netloc or not parsed_url.hostname:
        raise ValueError(f"Invalid target format: '{raw_input}'. Expected a valid URL or IP address.")

    normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    if parsed_url.path and parsed_url.path != "/":
        normalized_url += parsed_url.path

    return Target(
        raw_input=raw_input,
        normalized_value=normalized_url,
        target_type=TargetType.WEBSITE
    )


def _try_parse_ip(value: str) -> Optional[str]:
    """Helper method to safely check and parse IP addresses."""
    host_part = value.split(":")[0] if ":" in value and not value.startswith("[") else value
    
    try:
        ip_obj = ipaddress.ip_address(host_part)
        return str(ip_obj)
    except ValueError:
        return None