"""Test case model for auto-generated security tests."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TestCase:
    """Represents an auto-generated security test case."""

    test_id: str
    name: str
    module: str
    target_url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)
    body: Optional[dict] = None
    payload: str = ""
    expected_behavior: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "name": self.name,
            "module": self.module,
            "target_url": self.target_url,
            "method": self.method,
            "headers": self.headers,
            "params": self.params,
            "body": self.body,
            "payload": self.payload,
            "expected_behavior": self.expected_behavior,
            "description": self.description,
        }
