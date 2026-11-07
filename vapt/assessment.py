from datetime import datetime, timezone

from vapt.network import scan_network
from vapt.web import scan_web


def run_assessment(target: str) -> dict:
    started_at = datetime.now(timezone.utc).isoformat()

    # Execute both existing scanners.
    network_result = scan_network(target)
    web_result = scan_web(target)

    if not network_result.get("success") or not web_result.get("success"):
        return {
            "success": False,
            "execution_status": "failed",
            "network": network_result,
            "web": web_result,
            "findings": [],
        }

    findings = []
    fingerprints = {}

    def add_finding(
        title,
        asset,
        category,
        severity,
        confidence,
        validation_status,
        description,
        evidence,
        remediation,
        source,
    ):
        # Merge duplicate findings without discarding evidence.
        fingerprint = (title, asset)

        if fingerprint in fingerprints:
            existing = findings[fingerprints[fingerprint]]
            existing["evidence"].append(evidence)
            return

        finding = {
            "id": f"TF-{len(findings) + 1:04d}",
            "title": title,
            "asset": asset,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "validation_status": validation_status,
            "description": description,
            "evidence": [evidence],
            "remediation": remediation,
            "source": source,
            "cvss": None,
        }

        fingerprints[fingerprint] = len(findings)
        findings.append(finding)

    # Network observations.
    for result in network_result.get("results", []):
        if result["status"] == "open":
            add_finding(
                title=f"Open TCP port {result['port']}",
                asset=f"{result['host']}:{result['port']}",
                category="network_exposure",
                severity="informational",
                confidence="high",
                validation_status="observed",
                description="A TCP connection to this port succeeded. "
                            "An open port is an exposure observation, "
                            "not automatically a vulnerability.",
                evidence=result["evidence"],
                remediation="Verify that the service is required and "
                            "appropriately secured.",
                source=network_result["scanner"],
            )

    # Web observations.
    for result in web_result.get("results", []):
        path = result["path"]
        asset = target.rstrip("/") + path

        headers = result.get("security_headers", {})

        missing = [
            name for name, value in headers.items()
            if value is None
        ]

        for header in missing:
            add_finding(
                title=f"Missing HTTP security header: {header}",
                asset=asset,
                category="security_configuration",
                severity="low",
                confidence="high",
                validation_status="unconfirmed",
                description=f"The response did not include {header}. "
                            "Whether this represents a vulnerability "
                            "depends on application context.",
                evidence=f"{path}: {header} header absent",
                remediation=f"Evaluate whether {header} should be "
                            "configured for this application.",
                source=web_result["scanner"],
            )

        # Record accessible API documentation as an observation.
        if path == "/docs" and result.get("status_code") == 200:
            add_finding(
                title="API documentation publicly reachable",
                asset=asset,
                category="information_exposure",
                severity="informational",
                confidence="high",
                validation_status="observed",
                description="The API documentation endpoint returned HTTP 200. "
                            "This does not by itself establish a vulnerability.",
                evidence="GET /docs returned HTTP 200",
                remediation="Review whether API documentation should be "
                            "accessible in the deployed environment.",
                source=web_result["scanner"],
            )

        # Do not claim authentication bypass from HTTP status alone.
        if path == "/admin" and result.get("status_code") == 200:
            add_finding(
                title="Admin route accessible",
                asset=asset,
                category="access_control",
                severity="informational",
                confidence="medium",
                validation_status="suspected",
                description="The admin route returned HTTP 200 to the "
                            "scanner. Authentication and authorization "
                            "controls have not been validated.",
                evidence="Unauthenticated GET /admin returned HTTP 200",
                remediation="Verify authentication and authorization "
                            "requirements for administrative routes.",
                source=web_result["scanner"],
            )

    # Prioritize findings without inventing CVSS scores.
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }

    findings.sort(
        key=lambda item: severity_order.get(item["severity"], 5)
    )

    return {
        "success": True,
        "project": "ThreatFlow AI - Unified VAPT Agent",
        "target": target,
        "execution_status": "completed",
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),

        "scanner_summary": {
            "network": network_result["scanner"],
            "web": web_result["scanner"],
            "network_ports_checked": network_result["ports_checked"],
            "web_paths_checked": web_result["paths_checked"],
        },

        "summary": {
            "total_findings": len(findings),
            "critical": sum(f["severity"] == "critical" for f in findings),
            "high": sum(f["severity"] == "high" for f in findings),
            "medium": sum(f["severity"] == "medium" for f in findings),
            "low": sum(f["severity"] == "low" for f in findings),
            "informational": sum(
                f["severity"] == "informational" for f in findings
            ),
        },

        "findings": findings,

        "raw_evidence": {
            "network": network_result,
            "web": web_result,
        },

        "approval_required_for_active_validation": True,
        "active_validation_executed": False,
    }