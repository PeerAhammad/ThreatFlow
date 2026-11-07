import json
import socket
import ssl
import uuid

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import (
    Request,
    build_opener,
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
)

from vapt.scope import LOCAL_LAB_SCOPE, validate_target


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
ASSESSMENT_DIR = DATA_DIR / "assessments"

DATA_DIR.mkdir(exist_ok=True)
ASSESSMENT_DIR.mkdir(exist_ok=True)

AUDIT_FILE = DATA_DIR / "audit.jsonl"
APPROVAL_FILE = DATA_DIR / "approvals.json"


def now():
    return datetime.now(timezone.utc).isoformat()


def audit(event, details):
    record = {
        "timestamp": now(),
        "event": event,
        "details": details,
    }

    with AUDIT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def save_assessment(data):
    path = ASSESSMENT_DIR / f"{data['assessment_id']}.json"

    path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def load_assessment(assessment_id):
    path = ASSESSMENT_DIR / f"{assessment_id}.json"

    if not path.exists():
        return None

    return json.loads(path.read_text(encoding="utf-8"))


def load_approvals():
    if not APPROVAL_FILE.exists():
        return []

    return json.loads(APPROVAL_FILE.read_text(encoding="utf-8"))


def save_approvals(records):
    APPROVAL_FILE.write_text(
        json.dumps(records, indent=2),
        encoding="utf-8",
    )


# --------------------------------------------------
# FINDING NORMALIZATION
# --------------------------------------------------

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}


def normalize_findings(raw_findings):
    grouped = {}

    for original in raw_findings:
        item = dict(original)
        title = item["title"]
        asset = item["asset"]

        # Group missing-header observations by website origin.
        if (
            item["category"] == "security_configuration"
            and title.startswith("Missing HTTP security header:")
        ):
            parsed = urlparse(asset)
            group_asset = f"{parsed.scheme}://{parsed.netloc}"
        else:
            group_asset = asset.lower()

        key = (title.casefold(), group_asset.casefold())

        item["affected_assets"] = [asset]
        item["evidence"] = list(dict.fromkeys(item["evidence"]))

        if key not in grouped:
            item["asset"] = group_asset
            grouped[key] = item
        else:
            existing = grouped[key]

            existing["evidence"] = list(dict.fromkeys(
                existing["evidence"] + item["evidence"]
            ))

            existing["affected_assets"] = list(dict.fromkeys(
                existing["affected_assets"] + item["affected_assets"]
            ))

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "informational": 4,
    }

    findings = list(grouped.values())

    findings.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 5),
            item["title"].lower(),
        )
    )

    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"TF-{index:04d}"

    return findings


# --------------------------------------------------
# NETWORK SCANNER
# --------------------------------------------------

def network_scan(target):
    parsed = urlparse(target)
    host = parsed.hostname

    results = []

    for port in sorted(LOCAL_LAB_SCOPE.allowed_ports):
        try:
            with socket.create_connection(
                (host, port),
                timeout=2,
            ):
                results.append({
                    "host": host,
                    "port": port,
                    "status": "open",
                    "evidence": f"TCP connection succeeded: {host}:{port}",
                })

        except socket.timeout:
            results.append({
                "host": host,
                "port": port,
                "status": "filtered_or_timeout",
                "evidence": "Connection timed out",
            })

        except OSError as exc:
            results.append({
                "host": host,
                "port": port,
                "status": "closed_or_unreachable",
                "evidence": str(exc),
            })

    return {
        "scanner": "Python TCP Socket Scanner",
        "ports_checked": len(results),
        "results": results,
    }


# --------------------------------------------------
# HTTP SCANNER
# --------------------------------------------------
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def web_scan(target):
    parsed = urlparse(target)

    base_url = f"{parsed.scheme}://{parsed.netloc}"

    paths = [
        "/",
        "/docs",
        "/robots.txt",
        "/admin",
    ]

    results = []

    opener = build_opener(
    NoRedirect(),
    HTTPHandler(),
    HTTPSHandler(),
)

    for path in paths:
        url = base_url + path

        # Validate each requested path independently.
        validation = validate_target(url)

        if not validation["allowed"]:
            results.append({
                "path": path,
                "status_code": None,
                "evidence": "Skipped: path outside registered scope",
            })
            continue

        request = Request(
            url,
            headers={
                "User-Agent": "ThreatFlow-VAPT/1.0"
            },
            method="GET",
        )

        try:
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
                    "evidence": f"GET {path} returned HTTP {response.status}",
                })

        except Exception as exc:
            status = getattr(exc, "code", None)

            headers = getattr(exc, "headers", None)

            results.append({
                "path": path,
                "status_code": status,
                "server": headers.get("Server") if headers else None,
                "content_type": headers.get("Content-Type") if headers else None,
                "security_headers": {},
                "evidence": str(exc),
            })

    return {
        "scanner": "ThreatFlow Python HTTP Scanner",
        "paths_checked": len(results),
        "results": results,
    }


# --------------------------------------------------
# TLS ASSESSMENT
# --------------------------------------------------

def tls_scan(target):
    parsed = urlparse(target)

    if parsed.scheme != "https":
        return {
            "status": "skipped",
            "reason": "Target uses HTTP. TLS assessment is not applicable.",
        }

    host = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=5,
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=host,
            ) as secure_socket:

                return {
                    "status": "completed",
                    "protocol": secure_socket.version(),
                    "cipher": secure_socket.cipher(),
                    "certificate": secure_socket.getpeercert(),
                }

    except Exception as exc:
        return {
            "status": "failed",
            "error": str(exc),
        }


# --------------------------------------------------
# UNIFIED ASSESSMENT
# --------------------------------------------------

def run_assessment(target, request):
    started_at = now()

    validation = validate_target(target)

    if not validation["allowed"]:
        audit("scope_rejected", {
            "target": target,
            "reason": validation["reason"],
        })

        return {
            "success": False,
            "execution_status": "rejected",
            "scope_validation": validation,
            "findings": [],
        }

    assessment_id = str(uuid.uuid4())

    audit("assessment_started", {
        "assessment_id": assessment_id,
        "target": target,
    })

    network = network_scan(target)
    web = web_scan(target)
    tls = tls_scan(target)

    raw_findings = []

    # Network observations.
    for result in network["results"]:
        if result["status"] == "open":
            raw_findings.append({
                "title": f"Open TCP port {result['port']}",
                "asset": f"{result['host']}:{result['port']}",
                "category": "network_exposure",
                "severity": "informational",
                "confidence": "high",
                "validation_status": "observed",
                "description": (
                    "TCP connectivity was successful. "
                    "An open port is not automatically a vulnerability."
                ),
                "evidence": [result["evidence"]],
                "remediation": (
                    "Verify that the exposed service is required "
                    "and appropriately secured."
                ),
                "source": network["scanner"],
                "cvss": None,
            })

    # HTTP observations.
    for result in web["results"]:
        path = result["path"]
        status = result.get("status_code")

        asset = target.rstrip("/") + path

        headers = result.get("security_headers", {})

        for header, value in headers.items():
            if value is None and status is not None and 200 <= status < 400:
                raw_findings.append({
                    "title": f"Missing HTTP security header: {header}",
                    "asset": asset,
                    "category": "security_configuration",
                    "severity": "low",
                    "confidence": "high",
                    "validation_status": "unconfirmed",
                    "description": (
                        f"The HTTP response did not contain {header}. "
                        "Application-specific impact has not been established."
                    ),
                    "evidence": [f"{path}: {header} absent"],
                    "remediation": (
                        f"Evaluate and configure {header} where appropriate."
                    ),
                    "source": web["scanner"],
                    "cvss": None,
                })
                for result in web["results"]:
                    path = result["path"]
                    status = result.get("status_code")

    asset = target.rstrip("/") + path

    headers = result.get("security_headers", {})
    content_type = result.get("content_type") or ""

    # Only assess HTML pages, not robots.txt or other resources.
    is_html_page = (
        content_type.lower().startswith("text/html")
        and path != "/robots.txt"
    )

    if (
        is_html_page
        and status is not None
        and 200 <= status < 300
    ):
        for header, value in headers.items():
            if value is None:
                raw_findings.append({
                    "title": f"Missing HTTP security header: {header}",
                    "asset": asset,
                    "category": "security_configuration",
                    "severity": "low",
                    "confidence": "high",
                    "validation_status": "unconfirmed",
                    "description": (
                        f"The HTML response did not contain {header}. "
                        "Application-specific impact has not been established."
                    ),
                    "evidence": [
                        f"GET {path} returned HTTP {status}",
                        f"Response header {header} was absent.",
                    ],
                    "remediation": (
                        f"Evaluate and configure {header} where appropriate."
                    ),
                    "source": web["scanner"],
                    "cvss": None,
                })

    if path == "/docs" and status == 200:
        raw_findings.append({
            "title": "API documentation publicly reachable",
            "asset": asset,
            "category": "information_exposure",
            "severity": "informational",
            "confidence": "high",
            "validation_status": "observed",
            "description": (
                "The API documentation endpoint returned HTTP 200. "
                "This alone does not establish a vulnerability."
            ),
            "evidence": ["GET /docs returned HTTP 200"],
            "remediation": (
                "Review whether API documentation should be available "
                "in the deployment environment."
            ),
            "source": web["scanner"],
            "cvss": None,
        })

    if path == "/admin" and status == 200:
        raw_findings.append({
            "title": "Admin route accessible",
            "asset": asset,
            "category": "access_control",
            "severity": "informational",
            "confidence": "medium",
            "validation_status": "suspected",
            "description": (
                "The admin route returned HTTP 200. Authentication and "
                "authorization have not been tested."
            ),
            "evidence": [
                "Unauthenticated GET /admin returned HTTP 200"
            ],
            "remediation": "Verify authentication and authorization controls.",
            "source": web["scanner"],
            "cvss": None,
        })

        if path == "/admin" and status == 200:
            raw_findings.append({
                "title": "Admin route accessible",
                "asset": asset,
                "category": "access_control",
                "severity": "informational",
                "confidence": "medium",
                "validation_status": "suspected",
                "description": (
                    "The admin route returned HTTP 200. "
                    "Authentication and authorization have not been tested."
                ),
                "evidence": ["Unauthenticated GET /admin returned HTTP 200"],
                "remediation": (
                    "Verify authentication and authorization controls."
                ),
                "source": web["scanner"],
                "cvss": None,
            })

    findings = normalize_findings(raw_findings)

    summary = {
        severity: sum(
            item["severity"] == severity
            for item in findings
        )
        for severity in SEVERITY_ORDER
    }

    completed_at = now()

    assessment = {
        "success": True,
        "assessment_id": assessment_id,
        "project": "ThreatFlow AI - Unified VAPT Agent",
        "request": request,
        "target": target,
        "scope_validation": validation,
        "execution_status": "completed",
        "started_at": started_at,
        "completed_at": completed_at,

        "scanner_summary": {
            "network": network["scanner"],
            "web": web["scanner"],
            "tls": tls["status"],
            "ports_checked": network["ports_checked"],
            "paths_checked": web["paths_checked"],
        },

        "summary": {
            "total": len(findings),
            **summary,
        },

        "findings": findings,

        "raw_evidence": {
            "network": network,
            "web": web,
            "tls": tls,
        },

        "active_validation_executed": False,
        "approval_required_for_active_validation": True,

        "limitations": [
            "TCP scanner checks registered ports only.",
            "HTTP scanner performs non-destructive GET requests.",
            "TLS assessment uses certificate verification.",
            "No exploit or intrusive validation was performed.",
            "CVSS scores are not assigned without sufficient evidence.",
        ],
    }

    save_assessment(assessment)

    audit("assessment_completed", {
        "assessment_id": assessment_id,
        "findings": len(findings),
    })

    return assessment


# --------------------------------------------------
# HUMAN APPROVAL
# --------------------------------------------------

def request_approval(assessment_id, action, rationale):
    assessment = load_assessment(assessment_id)

    if not assessment:
        return None

    approval = {
        "approval_id": str(uuid.uuid4()),
        "assessment_id": assessment_id,
        "action": action,
        "rationale": rationale,
        "status": "pending",
        "requested_at": now(),
        "decision_at": None,
        "reviewer": None,
        "decision_reason": None,
    }

    records = load_approvals()
    records.append(approval)
    save_approvals(records)

    audit("approval_requested", approval)

    return approval


def decide_approval(approval_id, approved, reviewer, reason):
    records = load_approvals()

    for record in records:
        if record["approval_id"] == approval_id:

            if record["status"] != "pending":
                return {
                    "success": False,
                    "message": "Approval already decided.",
                }

            record["status"] = (
                "approved" if approved else "rejected"
            )

            record["reviewer"] = reviewer
            record["decision_reason"] = reason
            record["decision_at"] = now()

            save_approvals(records)

            audit("approval_decided", record)

            return {
                "success": True,
                "approval": record,
                "execution_note": (
                    "Approval recorded only. No active validation executed."
                ),
            }

    return None


# --------------------------------------------------
# PDF REPORT
# --------------------------------------------------

def generate_pdf(assessment_id):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        PageBreak,
    )
    from xml.sax.saxutils import escape

    assessment = load_assessment(assessment_id)

    if not assessment:
        return None

    output = DATA_DIR / f"ThreatFlow_{assessment_id[:8]}.pdf"

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    story = []

    def para(text, style="BodyText"):
        story.append(
            Paragraph(escape(str(text)), styles[style])
        )
        story.append(Spacer(1, 6))

    para("THREATFLOW AI", "Title")
    para("Unified Vulnerability Assessment Report", "Heading2")

    para(f"Assessment ID: {assessment_id}")
    para(f"Target: {assessment['target']}")
    para(f"Started: {assessment['started_at']}")
    para(f"Completed: {assessment['completed_at']}")

    story.append(Spacer(1, 12))
    para("1. Executive Summary", "Heading2")

    summary = assessment["summary"]

    para(f"Total observations: {summary['total']}")

    table_data = [
        ["Severity", "Count"],
        ["Critical", summary["critical"]],
        ["High", summary["high"]],
        ["Medium", summary["medium"]],
        ["Low", summary["low"]],
        ["Informational", summary["informational"]],
    ]

    table = Table(table_data, colWidths=[100 * mm, 35 * mm])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#174A70")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(table)

    para("2. Scope and Methodology", "Heading2")
    para("Authorized target: " + assessment["target"])
    para("Scope: " + assessment["scope_validation"]["scope"])

    para("Network: Python TCP Socket Scanner")
    para("Web: ThreatFlow Python HTTP Scanner")
    para("TLS: Python SSL module")

    para("3. Detailed Findings", "Heading2")

    for finding in assessment["findings"]:
        para(
            f"{finding['id']} - {finding['title']}",
            "Heading3",
        )

        para(f"Asset: {finding['asset']}")
        for affected_asset in finding.get("affected_assets", []):
            para(f"Affected asset: {affected_asset}")
        para(f"Severity: {finding['severity']}")
        para(f"Confidence: {finding['confidence']}")
        para(f"Validation: {finding['validation_status']}")
        para(f"Category: {finding['category']}")
        para(f"CVSS: {finding['cvss']}")
        para(f"Description: {finding['description']}")

        para("Evidence:")
        for evidence in finding["evidence"]:
            para("- " + evidence)

        para("Remediation: " + finding["remediation"])
        para("Source: " + finding["source"])

    para("4. Human Approval and Safety", "Heading2")

    approvals = [
        item for item in load_approvals()
        if item["assessment_id"] == assessment_id
    ]

    if approvals:
        for item in approvals:
            para(
                f"Action: {item['action']} | "
                f"Status: {item['status']} | "
                f"Reviewer: {item['reviewer']}"
            )
    else:
        para("No active validation approvals were requested.")

    para(
        "No active exploitation or intrusive validation was executed."
    )

    para("5. Limitations", "Heading2")

    for limitation in assessment["limitations"]:
        para("- " + limitation)

    para("6. Audit Information", "Heading2")
    para("Assessment ID: " + assessment_id)
    para("Execution status: " + assessment["execution_status"])

    doc.build(story)

    audit("pdf_report_generated", {
        "assessment_id": assessment_id,
        "path": str(output),
    })

    return output