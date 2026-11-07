from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ThreatFlow Training Lab", description="Intentionally misconfigured local-only training app", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/", response_class=HTMLResponse)
def home():
    return '''<!doctype html><html><head><title>Training Lab</title></head><body>
    <h1>ThreatFlow Local VAPT Training Lab</h1><p>Intentionally misconfigured app for authorized local testing.</p>
    <ul><li><a href="/admin">Demo admin page</a></li><li><a href="/api/info">Application info</a></li><li><a href="/docs">API documentation</a></li><li><a href="/robots.txt">Robots file</a></li></ul></body></html>'''

@app.get("/admin", response_class=HTMLResponse)
def admin():
    return "<h2>Demo Admin Area</h2><p>Training-only page. No authentication is implemented.</p><p>No real credentials or sensitive data exist in this lab.</p>"

@app.get("/api/info")
def info():
    return JSONResponse({"application":"ThreatFlow Training Lab","environment":"local-training","debug":True,"contact":"training@example.invalid"})

@app.get("/robots.txt", response_class=HTMLResponse)
def robots():
    return "User-agent: *\nAllow: /\nDisallow: /admin\n"

@app.get("/health")
def health():
    return {"status":"ok"}
