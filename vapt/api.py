from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from vapt.scope import validate_target
from vapt.engine import (
    run_assessment,
    load_assessment,
    request_approval,
    decide_approval,
    generate_pdf,
)

router = APIRouter(prefix="/api/vapt", tags=["VAPT Agent"])


class PlanRequest(BaseModel):
    request: str = Field(min_length=5, max_length=1000)
    target: str = Field(min_length=1, max_length=500)


class ApprovalRequest(BaseModel):
    assessment_id: str
    action: str
    rationale: str


class ApprovalDecision(BaseModel):
    approved: bool
    reviewer: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=3, max_length=1000)


@router.get("/health")
def health():
    return {
        "status": "operational",
        "component": "ThreatFlow Unified VAPT Agent",
    }


@router.post("/plan")
def plan(payload: PlanRequest):
    validation = validate_target(payload.target)

    if not validation["allowed"]:
        return {
            "success": False,
            "scope_validation": validation,
            "plan": [],
        }

    return {
        "success": True,
        "target": payload.target,
        "scope_validation": validation,
        "plan": [
            {
                "step": 1,
                "tool": "Python TCP Socket Scanner",
                "purpose": "Registered TCP port discovery",
            },
            {
                "step": 2,
                "tool": "ThreatFlow Python HTTP Scanner",
                "purpose": "HTTP security configuration assessment",
            },
            {
                "step": 3,
                "tool": "Python SSL",
                "purpose": "TLS assessment where applicable",
            },
        ],
        "execution_status": "not_started",
    }


@router.post("/assessment")
def assessment(payload: PlanRequest):
    return run_assessment(
        payload.target,
        payload.request,
    )


@router.get("/assessment/{assessment_id}")
def get_assessment(assessment_id: str):
    result = load_assessment(assessment_id)

    if not result:
        raise HTTPException(404, "Assessment not found")

    return result


@router.post("/approval/request")
def approval_request(payload: ApprovalRequest):
    result = request_approval(
        payload.assessment_id,
        payload.action,
        payload.rationale,
    )

    if not result:
        raise HTTPException(404, "Assessment not found")

    return result


@router.post("/approval/{approval_id}/decision")
def approval_decision(
    approval_id: str,
    payload: ApprovalDecision,
):
    result = decide_approval(
        approval_id,
        payload.approved,
        payload.reviewer,
        payload.reason,
    )

    if not result:
        raise HTTPException(404, "Approval not found")

    return result


@router.get("/report/{assessment_id}")
def report(assessment_id: str):
    path = generate_pdf(assessment_id)

    if not path:
        raise HTTPException(404, "Assessment not found")

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=path.name,
    )