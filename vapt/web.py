import urllib.request
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse

from vapt.scope import get_registered_scope, validate_target


def scan_web(target: str) -> dict:
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
            "results": [],
        }

    validation = validate_target(target, scope)

    if not validation["allowed"]:
        return {
            "success": False,
            "execution_status": "rejected",
            "scope_validation": validation,
            "results": [],
        }

    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    paths = ["/", "/docs", "/robots.txt", "/admin"]
    results = []

    for path in paths:
        url = base_url + path

        # Validate every requested path against the same registered scope.
        path_validation = validate_target(url, scope)

        if not path_validation["allowed"]:
            results.append({
                "path": path,
                "status_code": None,
                "evidence": "Path rejected by scope enforcement",
            })
            continue

        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ThreatFlow-VAPT/1.0"},
                method="GET",
            )

            opener = urllib.request.build_opener(
                urllib.request.HTTPHandler()
            )

            with opener.open(request, timeout=5) as response:
                headers = response.headers

                results.append({
                    "path": path,
                    "status_code": response.status,
                    "server": headers.get("Server"),
                    "content_type": headers.get("Content-Type"),
                    "security_headers": {
                        name: headers.get(name)
                        for name in [
                            "Content-Security-Policy",
                            "X-Frame-Options",
                            "X-Content-Type-Options",
                            "Referrer-Policy",
                        ]
                    },
                    "evidence": "HTTP GET request completed successfully",
                })

        except urllib.error.HTTPError as exc:
            results.append({
                "path": path,
                "status_code": exc.code,
                "evidence": f"HTTP error response: {exc.code}",
            })

        except Exception as exc:
            results.append({
                "path": path,
                "status_code": None,
                "evidence": f"Request failed: {str(exc)}",
            })

    return {
        "success": True,
        "scanner": "ThreatFlow Python HTTP Scanner",
        "target": target,
        "scope": scope.name,
        "execution_status": "completed",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "paths_checked": len(results),
        "results": results,
    }