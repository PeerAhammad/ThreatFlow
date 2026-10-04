# ThreatFlow

**Streaming Cyber-Threat Detection and Incident-Level Alerting**

ThreatFlow is a hackathon prototype for turning noisy, flow-level network security detections into persistent, incident-level alerts.

Instead of treating every network flow as an isolated classification problem, ThreatFlow processes traffic chronologically, maintains temporal context, and identifies sustained changes in network behavior.

## Why ThreatFlow?

A flow-level classifier can identify suspicious traffic, but real network monitoring produces thousands of individual flow predictions.

The practical question is therefore not only:

> "Is this flow malicious?"

but also:

> "Are these detections part of a sustained behavioral change, and when should they become an incident?"

ThreatFlow addresses this second problem through streaming temporal context and an alerting layer.

## Architecture

```text
CICIDS2017 traffic
        |
        v
Chronological preprocessing
        |
        v
Random Forest flow-level detector
        |
        +----------------------+
        |                      |
        v                      v
 Flow-level flags       Switching State-Space Model
                               |
                               v
                     Regime probabilities
                               |
                               v
                    Temporal context/features
                               |
                               v
                  Streaming alert state machine
                               |
                               v
                     Incident-level alerts
                               |
                               v
                       FastAPI backend
                               |
                               v
                        Web dashboard
```

## Core design

ThreatFlow separates **detection** from **incident aggregation**.

### 1. Flow-level detection

A Random Forest classifier operates on network-flow features and produces flow-level threat predictions.

On the held-out evaluation set:

| Model             | Precision | Recall |    F1 |    AUC |
| ----------------- | --------: | -----: | ----: | -----: |
| Random Forest     |     93.16 |  98.63 | 95.82 | 99.827 |
| RF + SSM features |     93.35 |  98.84 | 96.02 | 99.823 |

The hybrid model improves F1 by approximately **0.20 percentage points**, while AUC is effectively unchanged.

Therefore, ThreatFlow does **not** claim that the Switching SSM materially improves the underlying classifier.

### 2. Temporal regime context

The Switching State-Space Model provides probabilistic temporal context about the current traffic regime.

Its purpose is to answer questions such as:

* What behavioral regime is the stream currently in?
* How confident is the model in that regime?
* Is the stream transitioning between regimes?
* Is suspicious activity persistent rather than isolated?

This temporal information is used by the streaming layer rather than being presented as a replacement for the flow-level detector.

### 3. Incident-level alerting

The main operational contribution is the alert layer.

Rather than generating an alert for every suspicious flow, ThreatFlow maintains streaming state and requires sustained evidence before promoting activity to an incident-level alert.

The current evaluation uses:

* Window: **10 flows**
* Trigger threshold: **20%**
* Hold: **30**
* Settings selected on the first half of the held-out test split
* Evaluation performed on the second half

Results:

| Metric             |      Result |
| ------------------ | ----------: |
| Incidents detected | **11 / 11** |
| Incident coverage  |    **100%** |
| Alert episodes     |       **3** |
| False episodes     |       **0** |
| Flagged flows      |   **1,081** |

This demonstrates the intended transformation:

```text
1,081 flow-level flags
        ↓
temporal aggregation
        ↓
3 alert episodes
        ↓
11 / 11 incidents covered
```

The alert layer is therefore the primary operational contribution of the prototype.

## Evaluation

Evaluation uses the first **50,000 CICIDS2017 flows** with a chronological **80/20 split**, giving **10,000 held-out test flows**.

The alert settings are selected using the first half of the held-out test split and evaluated on the second half to reduce direct tuning on the final evaluation segment.

The evaluation artifact is stored at:

```text
artifacts/eval_summary.json
```

## Project structure

```text
ThreatFlow/
├── model/
│   ├── alerts.py
│   ├── inference.py
│   ├── switching_ssm.py
│   └── __init__.py
│
├── backend/
│   ├── main.py
│   └── __init__.py
│
├── frontend/
│   ├── index.html
│   └── static/
│       ├── app.js
│       └── style.css
│
├── tests/
│   └── test_streaming.py
│
├── data/
│   └── replay_sample.npz
│
├── artifacts/
│   ├── eval_summary.json
│   └── pard_model.joblib
│
├── docs/
│   ├── threatflow-dashboard-overview.png
│   └── threatflow-dashboard-alerts.png
│
├── train.py
├── evaluate.py
├── diagnose.py
├── make_replay.py
├── requirements.txt
├── .gitignore
└── README.md
```

The full CICIDS2017 dataset is intentionally not included in the repository because of its size. A small replay sample is included for demonstrating the streaming pipeline.

## Running ThreatFlow

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the API:

```bash
uvicorn backend.main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

FastAPI documentation:

```text
http://127.0.0.1:8000/docs
```

Open the ThreatFlow dashboard at:

http://127.0.0.1:8000/

## Running the tests

Run:

```bash
python -m pytest -q
```

Current test status:

```text
3 passed
```

The tests cover the streaming alert behavior and related state transitions.

## Reproducibility

The repository includes:

* Trained model artifact
* Evaluation summary
* Replay data
* Training and evaluation scripts
* Streaming tests

Large raw datasets and local runtime logs are excluded through `.gitignore`.

## Screenshots

The `docs/` directory contains screenshots of the ThreatFlow dashboard.

The interface presents the streaming detection pipeline, regime information, alert state, and operational metrics in a single monitoring view.

## Limitations

This is a hackathon prototype rather than a production network-security platform.

In particular:

* Evaluation is performed on a subset of CICIDS2017.
* The underlying Random Forest remains the primary flow-level detector.
* The SSM provides temporal regime context rather than a large standalone classification improvement.
* The alert thresholds are currently manually configured/tuned.
* Production deployment would require additional validation on live and cross-dataset traffic.

## Key takeaway

ThreatFlow's goal is not to claim that a more complicated model automatically produces better classification metrics.

The prototype demonstrates a different operational idea:

```text
Flow-level detection
        ↓
Temporal context
        ↓
Persistence / hysteresis
        ↓
Incident-level alert
```

**ThreatFlow turns thousands of individual network detections into a smaller number of persistent, interpretable security alerts.**
