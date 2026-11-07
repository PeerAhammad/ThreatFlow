from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ThreatFlow Local VAPT Training Lab",
    description="Intentionally misconfigured local security testing application",
    version="1.0.0",
)

# Intentionally permissive CORS for security assessment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>ThreatFlow Training Lab</title></head>
    <body>
        <h1>ThreatFlow Local VAPT Training Lab</h1>
        <p>Intentionally misconfigured application for authorized testing.</p>
        <ul>
            <li><a href="/admin">Admin Page</a></li>
            <li><a href="/api/info">Application Information</a></li>
            <li><a href="/docs">API Documentation</a></li>
            <li><a href="/robots.txt">Robots File</a></li>
        </ul>
    </body>
    </html>
    """


@app.get("/admin", response_class=HTMLResponse)
def admin():
    return """
    <h2>Demo Admin Area</h2>
    <p>Training-only page. No authentication is implemented.</p>
    <p>No real credentials or sensitive information are stored here.</p>
    """


@app.get("/api/info")
def info():
    return JSONResponse({
        "application": "ThreatFlow Training Lab",
        "environment": "local-training",
        "debug": True,
        "contact": "training@example.invalid",
    })


@app.get("/robots.txt", response_class=HTMLResponse)
def robots():
    return "User-agent: *\nAllow: /\nDisallow: /admin\n"


@app.get("/health")
def health():
    return {"status": "ok"}