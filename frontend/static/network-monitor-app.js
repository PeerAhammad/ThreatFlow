(() => {
    "use strict";

    const API = "/api/vapt";

    const HISTORY_KEY = "threatflow_vapt_assessment_ids";
    const APPROVAL_KEY = "threatflow_vapt_approvals";

    let assessments = [];
    let selected = null;

    let approvals = JSON.parse(
        localStorage.getItem(APPROVAL_KEY) || "[]"
    );


    const $ = (id) => document.getElementById(id);


    function esc(value) {
        return String(value ?? "").replace(/[&<>"']/g, c => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        })[c]);
    }


    function fmt(value) {
        return value
            ? new Date(value).toLocaleString()
            : "—";
    }


    function toast(message) {
        const el = $("toast");

        el.textContent = message;
        el.classList.add("show");

        setTimeout(() => {
            el.classList.remove("show");
        }, 2800);
    }


    function ids() {
        return JSON.parse(
            localStorage.getItem(HISTORY_KEY) || "[]"
        );
    }


    function saveIds(list) {
        localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify([...new Set(list)].slice(0, 40))
        );
    }


    async function api(path, options = {}) {

        const response = await fetch(API + path, {
            ...options,

            headers: {
                "Content-Type": "application/json",
                ...(options.headers || {})
            }
        });


        const contentType =
            response.headers.get("content-type") || "";


        if (!response.ok) {

            let message = `Request failed (${response.status})`;

            try {

                const body = contentType.includes("json")
                    ? await response.json()
                    : await response.text();

                message =
                    body.detail ||
                    body.message ||
                    message;

            } catch { }

            throw new Error(message);
        }


        if (contentType.includes("application/pdf")) {
            return response.blob();
        }

        return response.json();
    }


    // --------------------------------------------------
    // NAVIGATION
    // --------------------------------------------------

    function showPage(name) {

        document.querySelectorAll(".page").forEach(page => {

            page.classList.toggle(
                "active",
                page.id === `page-${name}`
            );

        });


        document.querySelectorAll(".nav-item").forEach(button => {

            button.classList.toggle(
                "active",
                button.dataset.page === name
            );

        });


        const labels = {
            overview: "Overview",
            assessments: "Assessments",
            activity: "Scan activity",
            findings: "Findings",
            approvals: "Approvals",
            reports: "Reports",
            network: "Network monitor"
        };

        $("crumb").textContent = labels[name] || name;


        if (name === "approvals") renderApprovals();
        if (name === "reports") renderReports();
        if (name === "activity") renderActivity();
        if (name === "findings") renderFindings();

    }


    // --------------------------------------------------
    // API HEALTH
    // --------------------------------------------------

    async function checkHealth() {

        try {

            await api("/health");

            $("apiDot").parentElement.classList.add("online");

            $("apiLabel").textContent = "VAPT API operational";

            $("metricApi").textContent = "Online";

        } catch {

            $("apiDot").parentElement.classList.remove("online");

            $("apiLabel").textContent = "API unavailable";

            $("metricApi").textContent = "Offline";

        }

    }


    // --------------------------------------------------
    // HISTORY
    // --------------------------------------------------

    async function loadHistory() {

        const savedIds = ids();

        assessments = [];


        for (const id of savedIds) {

            try {

                const assessment = await api(
                    `/assessment/${encodeURIComponent(id)}`
                );

                if (assessment.success) {
                    assessments.push(assessment);
                }

            } catch {
                // Continue loading other saved assessments.
            }

        }


        if (!selected && assessments.length) {
            selected = assessments[0];
        }


        renderOverview();
        renderAssessmentList();
        renderFindings();
        renderActivity();
        renderApprovals();
        renderReports();

    }


    // --------------------------------------------------
    // OVERVIEW
    // --------------------------------------------------

    function renderOverview() {

        $("metricAssessments").textContent =
            assessments.length;

        $("metricFindings").textContent =
            selected?.summary?.total ?? "—";

        $("metricApprovals").textContent =
            approvals.filter(a => a.status === "pending").length;

        $("approvalCount").textContent =
            approvals.filter(a => a.status === "pending").length;


        const host = $("recentAssessments");


        if (!assessments.length) {

            host.className = "empty-state";

            host.innerHTML = `
                <span class="empty-icon">◎</span>
                <b>No assessments yet</b>
                <p>
                    Create an assessment against the registered
                    local lab to see results here.
                </p>
                <button class="btn btn-secondary"
                    data-action="new-assessment">
                    Create assessment
                </button>
            `;

            return;
        }


        host.className = "table-wrap";


        host.innerHTML = `
            <table>

                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Findings</th>
                        <th>Completed</th>
                        <th></th>
                    </tr>
                </thead>

                <tbody>

                    ${assessments.slice(0, 5).map(a => `

                        <tr>

                            <td>
                                <b>${esc(a.target)}</b>
                                <br>
                                <small>${esc(a.assessment_id.slice(0, 8))}</small>
                            </td>

                            <td>
                                <span class="tag tag-live">
                                    ${esc(a.execution_status)}
                                </span>
                            </td>

                            <td>${a.summary?.total ?? 0}</td>

                            <td>${esc(fmt(a.completed_at))}</td>

                            <td>
                                <button class="link-btn"
                                    data-open="${esc(a.assessment_id)}">
                                    Open
                                </button>
                            </td>

                        </tr>

                    `).join("")}

                </tbody>

            </table>
        `;

    }


    // --------------------------------------------------
    // ASSESSMENT LIST
    // --------------------------------------------------

    function renderAssessmentList() {

        const el = $("assessmentList");


        if (!assessments.length) {

            el.innerHTML = `
                <div class="empty-state">
                    <b>No saved assessments</b>
                    <p>
                        Run an assessment to populate this list.
                        Assessment IDs are saved locally in this browser.
                    </p>
                </div>
            `;

            return;
        }


        el.innerHTML = `

            <table>

                <thead>
                    <tr>
                        <th>Assessment</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Findings</th>
                        <th>Started</th>
                        <th>Actions</th>
                    </tr>
                </thead>

                <tbody>

                    ${assessments.map(a => `

                        <tr>

                            <td>
                                <b>${esc(a.assessment_id.slice(0, 13))}…</b>
                            </td>

                            <td>${esc(a.target)}</td>

                            <td>${esc(a.execution_status)}</td>

                            <td>${a.summary?.total ?? 0}</td>

                            <td>${esc(fmt(a.started_at))}</td>

                            <td>
                                <button class="link-btn"
                                    data-open="${esc(a.assessment_id)}">
                                    View details
                                </button>
                            </td>

                        </tr>

                    `).join("")}

                </tbody>

            </table>

        `;

    }


    function openAssessment(id) {

        selected = assessments.find(
            a => a.assessment_id === id
        ) || null;


        if (!selected) return;


        renderOverview();
        renderFindings();
        renderActivity();
        renderReports();

        showPage("findings");

        toast("Assessment loaded");

    }


    // --------------------------------------------------
    // FINDINGS
    // --------------------------------------------------

    function renderFindings() {

        const el = $("findingsContent");

        if (!el) return;


        if (!selected) {

            el.innerHTML = `
                <div class="empty-state">
                    <b>No findings loaded</b>
                    <p>Run an assessment to populate the findings explorer.</p>
                </div>
            `;

            return;
        }


        const filter =
            $("severityFilter")?.value || "all";


        const findings = (selected.findings || []).filter(f => {

            return filter === "all" ||
                f.severity === filter;

        });


        if (!findings.length) {

            el.innerHTML = `
                <div class="empty-state">
                    <b>No matching observations</b>
                    <p>Try another severity filter.</p>
                </div>
            `;

            return;
        }


        el.innerHTML = `

            <div class="panel-heading">

                <div>
                    <h2>
                        ${findings.length} observations ·
                        ${esc(selected.assessment_id.slice(0, 8))}
                    </h2>

                    <p>
                        ${esc(selected.target)}
                        · Observations are not necessarily confirmed vulnerabilities.
                    </p>
                </div>

                <span class="tag tag-live">
                    ${esc(selected.execution_status)}
                </span>

            </div>


            ${findings.map(f => `

                <article class="finding-card">

                    <div class="finding-main">

                        <span class="severity-dot severity-${esc(f.severity)}"></span>

                        <div class="finding-copy">

                            <b>${esc(f.title)}</b>

                            <p>${esc(f.description)}</p>

                            <div class="finding-meta">

                                <span>${esc(f.id)}</span>

                                <span>${esc(f.category)}</span>

                                <span>
                                    Confidence: ${esc(f.confidence)}
                                </span>

                                <span>
                                    Validation: ${esc(f.validation_status)}
                                </span>

                            </div>


                            <div class="finding-meta">

                                <span>
                                    Asset: ${esc(f.asset)}
                                </span>

                                ${(f.affected_assets || []).length
                                    ? `<span>${f.affected_assets.length} affected asset(s)</span>`
                                    : ""}

                                <span>
                                    Source: ${esc(f.source)}
                                </span>

                            </div>

                        </div>


                        <span class="severity-label sev-${esc(f.severity)}">
                            ${esc(f.severity)}
                        </span>

                    </div>


                    <div class="evidence-box">

                        <b>Evidence</b>

                        <code>${(f.evidence || []).map(esc).join("\n") || "No evidence supplied"}

CVSS: ${f.cvss ?? "Not assigned"}
CVE: ${f.cve ?? "Not assigned"}
CWE: ${f.cwe ?? "Not assigned"}</code>

                        <br>

                        <b>Remediation</b>

                        <br>

                        ${esc(f.remediation || "No remediation guidance supplied.")}

                    </div>

                </article>

            `).join("")}

        `;

    }


    // --------------------------------------------------
    // SCAN ACTIVITY
    // --------------------------------------------------

    function renderActivity() {

        const el = $("activityContent");


        if (!selected) {

            el.innerHTML = `
                <div class="empty-state">
                    <b>No execution selected</b>
                    <p>Run or open an assessment to inspect its execution trace.</p>
                </div>
            `;

            return;
        }


        const summary = selected.scanner_summary || {};

        const raw = selected.raw_evidence || {};


        const rows = [

            [
                "Network",
                summary.network || "Not reported",
                `${summary.ports_checked ?? 0} registered port(s) checked`,
                raw.network?.results
            ],

            [
                "Web",
                summary.web || "Not reported",
                `${summary.paths_checked ?? 0} path(s) checked`,
                raw.web?.results
            ],

            [
                "TLS",
                summary.tls || "Not reported",
                raw.tls?.reason ||
                raw.tls?.error ||
                raw.tls?.protocol ||
                "No additional TLS detail"
            ]

        ];


        el.innerHTML = `

            <div class="panel-heading">

                <div>
                    <h2>Execution summary</h2>

                    <p>
                        ${esc(selected.assessment_id)}
                        · ${esc(selected.target)}
                    </p>
                </div>


                <div style="display:flex;gap:8px;align-items:center">

                    <button
                        class="btn btn-secondary"
                        data-request-approval="${esc(selected.assessment_id)}">

                        ＋ Request approval

                    </button>

                    <span class="tag tag-live">
                        ${esc(selected.execution_status)}
                    </span>

                </div>

            </div>


            <div class="table-wrap">

                <table>

                    <thead>
                        <tr>
                            <th>Check</th>
                            <th>Adapter</th>
                            <th>Coverage</th>
                            <th>Result</th>
                        </tr>
                    </thead>

                    <tbody>

                        ${rows.map(row => `

                            <tr>

                                <td><b>${row[0]}</b></td>

                                <td>${esc(row[1])}</td>

                                <td>${esc(row[2])}</td>

                                <td>
                                    ${
                                        Array.isArray(row[3])
                                            ? row[3].map(x => esc(JSON.stringify(x))).join("<br>")
                                            : esc(row[3] || "—")
                                    }
                                </td>

                            </tr>

                        `).join("")}

                    </tbody>

                </table>

            </div>


            <div class="evidence-box">

                <b>Execution boundaries</b>

                <br>

                Active validation executed:
                ${selected.active_validation_executed ? "Yes" : "No"}

                <br>

                Approval required for active validation:
                ${selected.approval_required_for_active_validation ? "Yes" : "No"}

                <br>

                Started: ${esc(fmt(selected.started_at))}

                <br>

                Completed: ${esc(fmt(selected.completed_at))}

                <br><br>

                <b>Limitations</b>

                <br>

                ${(selected.limitations || [])
                    .map(x => "• " + esc(x))
                    .join("<br>")}

            </div>

        `;

    }


    // --------------------------------------------------
    // APPROVALS
    // --------------------------------------------------

    function renderApprovals() {

        const el = $("approvalsContent");

        if (!el) return;


        if (!approvals.length) {

            el.innerHTML = `
                <div class="empty-state">

                    <span class="empty-icon">✓</span>

                    <b>No approval requests</b>

                    <p>
                        Open an assessment's Scan Activity page to
                        create an approval request.
                    </p>

                </div>
            `;

            return;
        }


        el.innerHTML = approvals.slice().reverse().map(a => `

            <div class="approval-card">

                <span class="metric-icon amber">✓</span>

                <div>

                    <b>${esc(a.action)}</b>

                    <p>
                        ${esc(a.rationale)}
                        · Assessment ${esc((a.assessment_id || "").slice(0, 8))}
                        · ${esc(fmt(a.requested_at))}
                    </p>

                    <span class="tag ${
                        a.status === "pending"
                            ? "tag-warning"
                            : "tag-live"
                    }">
                        ${esc(a.status)}
                    </span>

                    ${a.reviewer
                        ? `<small> · ${esc(a.reviewer)}: ${esc(a.decision_reason)}</small>`
                        : ""}

                </div>


                ${
                    a.status === "pending"
                        ? `<button class="btn btn-secondary" data-review="${esc(a.approval_id)}">Review</button>`
                        : ""
                }

            </div>

        `).join("");

    }


    async function requestApproval(assessmentId) {

        const action = prompt(
            "Proposed action (describe the exact validation action):",
            "Request controlled active validation"
        );

        if (!action) return;


        const rationale = prompt(
            "Why is this action needed?",
            "Analyst review requested; no active test will run from this approval."
        );

        if (!rationale) return;


        try {

            const approval = await api("/approval/request", {

                method: "POST",

                body: JSON.stringify({
                    assessment_id: assessmentId,
                    action,
                    rationale
                })

            });


            approvals.push(approval);

            localStorage.setItem(
                APPROVAL_KEY,
                JSON.stringify(approvals)
            );


            renderApprovals();
            renderOverview();

            toast("Approval request recorded");

        } catch (error) {

            toast(error.message);

        }

    }


    async function decideApproval(approved) {

        const id = $("approvalId").value;


        try {

            const result = await api(
                `/approval/${encodeURIComponent(id)}/decision`,
                {

                    method: "POST",

                    body: JSON.stringify({

                        approved,

                        reviewer: $("reviewerInput").value.trim(),

                        reason: $("decisionReason").value.trim()

                    })

                }
            );


            if (!result.success) {
                throw new Error(
                    result.message || "Decision was not recorded"
                );
            }


            approvals = approvals.map(a =>
                a.approval_id === id
                    ? result.approval
                    : a
            );


            localStorage.setItem(
                APPROVAL_KEY,
                JSON.stringify(approvals)
            );


            $("approvalDialog").close();

            renderApprovals();
            renderOverview();

            toast(
                `Decision recorded: ${approved ? "approved" : "rejected"}`
            );


            if (result.execution_note) {
                console.info(result.execution_note);
            }

        } catch (error) {

            toast(error.message);

        }

    }


    // --------------------------------------------------
    // REPORTS
    // --------------------------------------------------

    function renderReports() {

        const el = $("reportsContent");

        if (!el) return;


        if (!assessments.length) {

            el.innerHTML = `
                <div class="empty-state">

                    <span class="empty-icon">▤</span>

                    <b>No reports available</b>

                    <p>
                        Complete an assessment to generate its PDF report.
                    </p>

                </div>
            `;

            return;
        }


        el.innerHTML = `

            <div class="table-wrap">

                <table>

                    <thead>
                        <tr>
                            <th>Assessment</th>
                            <th>Target</th>
                            <th>Findings</th>
                            <th>Completed</th>
                            <th>Download</th>
                        </tr>
                    </thead>

                    <tbody>

                        ${assessments.map(a => `

                            <tr>

                                <td>
                                    <b>${esc(a.assessment_id.slice(0, 13))}…</b>
                                </td>

                                <td>${esc(a.target)}</td>

                                <td>${a.summary?.total ?? 0}</td>

                                <td>${esc(fmt(a.completed_at))}</td>

                                <td>
                                    <button
                                        class="btn btn-secondary"
                                        data-report="${esc(a.assessment_id)}">

                                        ↓ PDF report

                                    </button>
                                </td>

                            </tr>

                        `).join("")}

                    </tbody>

                </table>

            </div>


            <div class="panel-footnote">

                PDF reports are generated by the backend on request.
                The current report generator includes scope, summary,
                detailed findings, approvals and limitations.

            </div>

        `;

    }


    async function downloadReport(id) {

        try {

            const blob = await api(
                `/report/${encodeURIComponent(id)}`
            );


            const url = URL.createObjectURL(blob);

            const anchor = document.createElement("a");

            anchor.href = url;

            anchor.download =
                `ThreatFlow_${id.slice(0, 8)}.pdf`;

            document.body.appendChild(anchor);

            anchor.click();

            anchor.remove();

            URL.revokeObjectURL(url);

            toast("PDF report downloaded");

        } catch (error) {

            toast(error.message);

        }

    }


    // --------------------------------------------------
    // NEW ASSESSMENT
    // --------------------------------------------------

    async function startAssessment(event) {

        event.preventDefault();


        const button = $("runAssessmentBtn");

        const errorBox = $("dialogError");


        errorBox.textContent = "";

        button.disabled = true;

        button.textContent = "Validating scope…";


        const payload = {

            request: $("requestInput").value.trim(),

            target: $("targetInput").value.trim()

        };


        try {

            // Step 1: Validate and obtain the plan.

            const plan = await api("/plan", {

                method: "POST",

                body: JSON.stringify(payload)

            });


            if (!plan.success) {

                throw new Error(
                    plan.scope_validation?.reason ||
                    "Target rejected by scope policy"
                );

            }


            // Step 2: Execute the assessment.

            button.textContent = "Running passive checks…";


            const result = await api("/assessment", {

                method: "POST",

                body: JSON.stringify(payload)

            });


            if (!result.success) {

                throw new Error(
                    result.scope_validation?.reason ||
                    "Assessment did not complete"
                );

            }


            // Step 3: Save assessment locally.

            saveIds([
                result.assessment_id,
                ...ids()
            ]);


            assessments = [

                result,

                ...assessments.filter(
                    a => a.assessment_id !== result.assessment_id
                )

            ];


            selected = result;


            $("assessmentDialog").close();


            renderOverview();
            renderAssessmentList();
            renderFindings();
            renderActivity();
            renderReports();


            showPage("findings");


            toast(
                `Assessment completed · ${result.summary?.total ?? 0} observations`
            );


        } catch (error) {

            errorBox.textContent = error.message;

            toast("Assessment could not be completed");

        } finally {

            button.disabled = false;

            button.textContent = "Validate & run assessment";

        }

    }


    // --------------------------------------------------
    // EVENT HANDLERS
    // --------------------------------------------------

    document.addEventListener("click", event => {

        const page = event.target.closest("[data-page]");

        if (page) {

            event.preventDefault();

            showPage(page.dataset.page);

            return;

        }


        const newAssessment =
            event.target.closest("[data-action='new-assessment']");

        if (newAssessment) {

            $("dialogError").textContent = "";

            $("assessmentDialog").showModal();

            return;

        }


        const close = event.target.closest("[data-close]");

        if (close) {

            close.closest("dialog").close();

            return;

        }


        const open = event.target.closest("[data-open]");

        if (open) {

            openAssessment(open.dataset.open);

            return;

        }


        const approvalRequest =
            event.target.closest("[data-request-approval]");

        if (approvalRequest) {

            requestApproval(
                approvalRequest.dataset.requestApproval
            );

            return;

        }


        const report = event.target.closest("[data-report]");

        if (report) {

            downloadReport(report.dataset.report);

            return;

        }


        const review = event.target.closest("[data-review]");

        if (review) {

            const approval = approvals.find(
                a => a.approval_id === review.dataset.review
            );


            if (approval) {

                $("approvalId").value = approval.approval_id;

                $("approvalDialogTitle").textContent =
                    approval.action;

                $("approvalDialog").showModal();

            }

        }

    });


    // --------------------------------------------------
    // FORM EVENTS
    // --------------------------------------------------

    $("assessmentForm").addEventListener(
        "submit",
        startAssessment
    );


    $("approvalForm").addEventListener("submit", event => {

        event.preventDefault();

        decideApproval(true);

    });


    $("rejectApproval").addEventListener("click", () => {

        decideApproval(false);

    });


    $("severityFilter").addEventListener(
        "change",
        renderFindings
    );


    // --------------------------------------------------
    // INITIALIZATION
    // --------------------------------------------------

    checkHealth();

    loadHistory();


    setInterval(checkHealth, 30000);


})();