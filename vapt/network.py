import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

from vapt.scope import LOCAL_LAB_SCOPE, validate_target


def scan_network(target: str) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()

    # Enforce registered scope before connecting.
    validation = validate_target(target)

    if not validation["allowed"]:
        return {
            "success": False,
            "execution_status": "rejected",
            "scope_validation": validation,
            "findings": [],
        }

    parsed = urlparse(target)
    host = parsed.hostname

    results = []

    # Only scan explicitly registered ports.
    for port in sorted(LOCAL_LAB_SCOPE.allowed_ports):
        try:
            with socket.create_connection(
                (host, port), timeout=2
            ):
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
        "execution_status": "completed",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "ports_checked": len(results),
        "results": results,
    }