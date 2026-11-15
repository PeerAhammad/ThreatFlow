
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScanScope:
    name: str
    allowed_hosts: set[str]
    allowed_ports: set[int]
    excluded_paths: set[str] = field(default_factory=set)
    active_validation_allowed: bool = False


LOCAL_LAB_SCOPE = ScanScope(
    name="ThreatFlow Local Training Lab",
    allowed_hosts={"127.0.0.1"},
    allowed_ports={8765},
    excluded_paths={"/admin/delete", "/shutdown"},
    active_validation_allowed=False,
)

HOSTED_LAB_SCOPE = ScanScope(
    name="ThreatFlow Hosted Training Lab",
    allowed_hosts={"threatflow-lab.onrender.com"},
    allowed_ports={443},
    excluded_paths={"/admin/delete", "/shutdown"},
    active_validation_allowed=False,
)


def get_registered_scope(target: str):
    try:
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()

        if host == "127.0.0.1":
            return LOCAL_LAB_SCOPE

        if host == "threatflow-lab.onrender.com":
            return HOSTED_LAB_SCOPE

        return None

    except ValueError:
        return None


def validate_target(target: str, scope=None) -> dict:
    try:
        parsed = urlparse(target)

        if parsed.scheme not in {"http", "https"}:
            return {"allowed": False, "reason": "Unsupported URL scheme"}

        if not parsed.hostname:
            return {"allowed": False, "reason": "Missing hostname"}

        if parsed.username or parsed.password:
            return {"allowed": False, "reason": "Credentials in URLs are not allowed"}

        if scope is None:
            scope = get_registered_scope(target)

        if scope is None:
            return {"allowed": False, "reason": "Host is not registered in any authorized scope"}

        host = parsed.hostname.lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"

        if host not in scope.allowed_hosts:
            return {"allowed": False, "reason": f"Host '{host}' is outside registered scope"}

        if port not in scope.allowed_ports:
            return {"allowed": False, "reason": f"Port {port} is outside registered scope"}

        if path in scope.excluded_paths:
            return {"allowed": False, "reason": f"Path '{path}' is explicitly excluded"}

        if host == "threatflow-lab.onrender.com" and parsed.scheme != "https":
            return {"allowed": False, "reason": "Hosted lab requires HTTPS"}

        return {
            "allowed": True,
            "reason": "Target is within registered scope",
            "scope": scope.name,
            "target": target,
        }

    except ValueError:
        return {"allowed": False, "reason": "Invalid URL or port"}
