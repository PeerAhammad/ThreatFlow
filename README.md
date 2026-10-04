# ThreatFlow

**Probabilistic Streaming Cyber Threat Regime Detection**

ThreatFlow is a hackathon prototype for detecting changes in cyber-traffic
behavior as a stream rather than treating every flow as an independent
classification problem.

## Core idea

CICIDS2017 traffic
→ shared preprocessing
→ chronological windows
→ Switching State-Space Model
→ regime probabilities
→ threat/transition events
→ FastAPI
→ live dashboard

The system is designed around the question:

> What behavioral regime is the network currently in, how confident are we,
> and when did that regime change?

## Project structure

```text
ThreatFlow-Hackathon/
├── model/
│   ├── switching_ssm.py
│   ├── inference.py
│   └── preprocessing.py
├── data/
│   └── CICIDS2017/
├── artifacts/
├── backend/
│   ├── main.py
│   ├── replay.py
│   └── schemas.py
├── frontend/
├── tests/
│   └── test_streaming.py
├── train.py
├── evaluate.py
├── requirements.txt
└── README.md
```

## Important implementation rule

Fit the scaler/PCA on the training split only. Save those fitted objects
and reuse them unchanged during chronological test/replay inference.

## Run the API

```bash
uvicorn backend.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000/docs
```

## Demo target

- Normal traffic
- Reconnaissance/scanning
- DoS or other attack behavior
- Regime posterior probabilities
- Transition/alert feed
- Processing latency
- Optional baseline comparison

## Status

This repository is the hackathon implementation scaffold. The existing
Switching SSM code is retained as the research/model core; the backend,
replay, preprocessing, evaluation, and dashboard integration are intentionally
kept modular.
