"""
ThreatFlow API.

  GET /            dashboard
  GET /health      liveness
  GET /api/status  model/replay info + evaluation summary for the dashboard
  WS  /ws/replay   replays held-out CICIDS2017 flows through the streaming detector

WebSocket protocol
  client -> server: {"cmd": "start"} | {"cmd": "pause"} | {"cmd": "reset"} | {"cmd": "speed", "value": flows_per_sec}
  server -> client: {"type": "hello", ...} on connect, {"type": "batch", ...} while running,
                    {"type": "reset"} after a reset, {"type": "done"} at the end of the replay.
"""

import asyncio
import json
import time
from pathlib import Path

import joblib
import numpy as np
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from model.inference import StreamingDetector

ROOT = Path(__file__).resolve().parent.parent
ALERT_CFG = dict(window=10, on_rate=0.20, hold=30)  # frozen after tuning on the first half of the test split
FLAG_THR = 0.5
TICK = 0.05  # seconds between batches

_model, _sample = ROOT / "artifacts" / "pard_model.joblib", ROOT / "data" / "replay_sample.npz"
if not (_model.exists() and _sample.exists()):
    raise RuntimeError("Missing artifacts/pard_model.joblib or data/replay_sample.npz - run train.py first.")

ART = joblib.load(_model)
_s = np.load(_sample)
X, Y = _s["X"].astype(np.float64), _s["y"].astype(int)


def make_detector() -> StreamingDetector:
    return StreamingDetector(ART, **ALERT_CFG)


def load_eval() -> dict:
    p = ROOT / "artifacts" / "eval_summary.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def r4(a) -> list:
    return np.round(np.asarray(a, dtype=float), 4).tolist()


app = FastAPI(title="ThreatFlow")


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return {"status": "ok"}


@app.get("/api/status")
def status():
    return {
        "status": "ok",
        "replay_rows": int(len(X)),
        "flag_threshold": FLAG_THR,
        "alert": ALERT_CFG,
        "eval": load_eval(),
    }


@app.get("/")
def index():
    return FileResponse(ROOT / "frontend" / "index.html")


app.mount("/static", StaticFiles(directory=ROOT / "frontend" / "static"), name="static")


@app.websocket("/ws/replay")
async def ws_replay(ws: WebSocket):
    await ws.accept()
    st = {"run": False, "reset": False, "speed": 100}
    det, pos, silence = make_detector(), 0, 0

    await ws.send_json({
        "type": "hello",
        "total": int(len(X)),
        "flag_thr": FLAG_THR,
        "alert": {**ALERT_CFG, "on_count": det.alerter.on_count},
    })

    async def reader():
        while True:
            msg = await ws.receive_json()
            cmd = msg.get("cmd")
            if cmd == "start":
                st["run"] = True
            elif cmd == "pause":
                st["run"] = False
            elif cmd == "reset":
                st["run"], st["reset"] = False, True
            elif cmd == "speed":
                try:
                    st["speed"] = int(min(max(float(msg.get("value", 100)), 5), 2000))
                except (TypeError, ValueError):
                    pass

    task = asyncio.create_task(reader())
    try:
        while not task.done():
            t0 = time.perf_counter()

            if st["reset"] or (st["run"] and pos >= len(X)):  # explicit reset, or Start after the replay finished
                det, pos, silence, st["reset"] = make_detector(), 0, 0, False
                await ws.send_json({"type": "reset"})

            if st["run"]:
                k = max(1, int(st["speed"] * TICK))
                chunk = X[pos:pos + k]
                out = await asyncio.to_thread(det.process, chunk)  # keep the event loop free

                sil = np.empty(len(chunk), dtype=int)
                for i, flagged in enumerate(out["p_attack"] >= FLAG_THR):
                    silence = 0 if flagged else silence + 1
                    sil[i] = silence

                await ws.send_json({
                    "type": "batch",
                    "i0": pos,
                    "p": r4(out["p_attack"]),
                    "rate": r4(out["alert_rate"]),
                    "alert": out["alert"].tolist(),
                    "silence": sil.tolist(),
                    "regime": r4(out["regime_smooth"][:, 1]),
                    "y": Y[pos:pos + len(chunk)].tolist(),  # ground truth: replay/demo only
                })
                pos += len(chunk)
                if pos >= len(X):
                    st["run"] = False
                    await ws.send_json({"type": "done"})

            await asyncio.sleep(max(0.0, TICK - (time.perf_counter() - t0)))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        task.cancel()
        try:
            await task
        except BaseException:  # CancelledError or the disconnect that ended the reader
            pass
