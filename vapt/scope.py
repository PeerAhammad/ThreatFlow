from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScanScope:
    name: str
    allowed_hosts: set[str]
    allowed_ports: set[int]
    excluded_paths: set[str] = field(default_factory=set)
    active_validation_allowed: bool = False


# Explicitly registered local development target.
LOCAL_LAB_SCOPE = ScanScope(
    name="ThreatFlow Local Training Lab",
    allowed_hosts={"127.0.0.1"},
    allowed_ports={8765},
    excluded_paths={"/admin/delete", "/shutdown"},
    active_validation_allowed=False,
)


def validate_target(target: str, scope: ScanScope = LOCAL_LAB_SCOPE) -> dict:
    """
    Validate a target URL against an explicitly registered scope.
    This validator does not perform network requests.
    """
    try:
        parsed = urlparse(target)

        if parsed.scheme not in {"http", "https"}:
            return {"allowed": False, "reason": "Unsupported URL scheme"}

        if not parsed.hostname:
            return {"allowed": False, "reason": "Missing hostname"}

        if parsed.username or parsed.password:
            return {"allowed": False, "reason": "Credentials in URLs are not allowed"}

        host = parsed.hostname.lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        if host not in scope.allowed_hosts:
            return {"allowed": False, "reason": f"Host '{host}' is outside registered scope"}

        if port not in scope.allowed_ports:
            return {"allowed": False, "reason": f"Port {port} is outside registered scope"}

        if path in scope.excluded_paths:
            return {"allowed": False, "reason": f"Path '{path}' is explicitly excluded"}

        return {
            "allowed": True,
            "reason": "Target is within registered scope",
            "scope": scope.name,
            "target": target,
        }

    except ValueError:
        return {"allowed": False, "reason": "Invalid URL or port"}
