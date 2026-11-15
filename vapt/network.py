import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from vapt.scope import get_registered_scope, validate_target


def scan_network(target: str) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()

    scope = get_registered_scope(target)

    if scope is None:
        return {
            "success": False,
            "execution_status": "rejected",
            "scope_validation": {
                "allowed": False,
                "reason": "Target is not registered in an authorized scope",
            },
            "findings": [],
        }

    validation = validate_target(target, scope)

    if not validation["allowed"]:
        return {
            "success": False,
            "execution_status": "rejected",
            "scope_validation": validation,
            "findings": [],
        }

    host = urlparse(target).hostname
    results = []

    for port in sorted(scope.allowed_ports):
        try:
            with socket.create_connection((host, port), timeout=2):
                results.append({
                    "host": host,
                    "port": port,
                    "status": "open",
                    "evidence": f"TCP connection succeeded on {host}:{port}",
                })

        except socket.timeout:
            results.append({
                "host": host,
                "port": port,
                "status": "filtered_or_timeout",
                "evidence": "Connection attempt timed out",
            })

        except OSError as exc:
            results.append({
                "host": host,
                "port": port,
                "status": "closed_or_unreachable",
                "evidence": str(exc),
            })

    return {
        "success": True,
        "scanner": "Python TCP Socket Scanner",
        "target": target,
        "scope": scope.name,
        "execution_status": "completed",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "ports_checked": len(results),
        "results": results,
    }