"""Target models representing API endpoints and URLs to test."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class TargetType(Enum):
    API = "api"
    URL = "url"


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


@dataclass
class Target:
    """Base target for security testing."""

    url: str
    target_type: TargetType = TargetType.URL
    name: str = ""
    description: str = ""

    def __post_init__(self):
        if not self.name:
            self.name = self.url


@dataclass
class APITarget(Target):
    """Represents an API endpoint to test."""

    method: HTTPMethod = HTTPMethod.GET
    headers: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    body: Optional[dict] = None
    auth_token: Optional[str] = None
    content_type: str = "application/json"

    def __post_init__(self):
        self.target_type = TargetType.API
        super().__post_init__()

    def get_request_headers(self) -> dict:
        """Build complete request headers."""
        h = {"Content-Type": self.content_type, "User-Agent": "WhiteHats-Scanner/1.0"}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        h.update(self.headers)
        return h


@dataclass
class URLTarget(Target):
    """Represents a URL (web page) to test."""

    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    def __post_init__(self):
        self.target_type = TargetType.URL
        super().__post_init__()
