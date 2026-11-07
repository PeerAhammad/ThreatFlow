from dataclasses import dataclass, asdict
from urllib.parse import urlparse

from vapt.scope import validate_target


@dataclass
class ScanStep:
    step_id: int
    name: str
    adapter: str
    category: str
    rationale: str
    status: str = "planned"


def create_plan(request: str, target: str) -> dict:
    """
    Convert a natural-language security request into
    a scope-validated, auditable scan plan.

    Planning only. No scans are executed here.
    """

    scope_check = validate_target(target)

    if not scope_check["allowed"]:
        return {
            "success": False,
            "message": "Target rejected by scope enforcement.",
            "scope_validation": scope_check,
            "plan": [],
        }

    parsed = urlparse(target)
    steps = []

    def add_step(name, adapter, category, rationale):
        steps.append(
            ScanStep(
                step_id=len(steps) + 1,
                name=name,
                adapter=adapter,
                category=category,
                rationale=rationale,
            )
        )

    # Network assessment
    if any(word in request.lower() for word in
           ["network", "port", "host", "service", "full", "vapt"]):
        add_step(
            "Service and Port Discovery",
            "Nmap",
            "network",
            "Identify reachable services and exposed ports "
            "within the registered target scope."
        )

    # Web application assessment
    if parsed.scheme in {"http", "https"}:
        add_step(
            "Web Application Baseline",
            "OWASP ZAP",
            "web",
            "Inspect the in-scope web application for "
            "common security misconfigurations."
        )

        add_step(
            "HTTP Security Configuration Review",
            "Built-in HTTP Checks",
            "web",
            "Review HTTP response headers and identify "
            "missing or weak security controls."
        )

    # TLS assessment
    if parsed.scheme == "https":
        add_step(
            "TLS Configuration Assessment",
            "SSLyze",
            "tls",
            "Assess the TLS configuration and supported "
            "protocols of the HTTPS service."
        )

    if not steps:
        add_step(
            "Basic Target Assessment",
            "Built-in Checks",
            "baseline",
            "Perform basic checks appropriate to the supplied request."
        )

    return {
        "success": True,
        "message": "Plan generated successfully. No scans have been executed.",
        "request": request,
        "target": target,
        "scope_validation": scope_check,
        "plan": [asdict(step) for step in steps],
        "execution_status": "not_started",
    }