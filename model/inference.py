"""
Streaming inference for the PARD-SSM hybrid detector.

Pipeline per flow (all causal, state carried between calls):
  raw row -> z-score selected features -> Kalman-bank regime posterior
          -> EMA smoothing -> [features | temporal diff | smoothed regime probs]
          -> Random Forest -> p_attack -> hysteresis alert state
"""

import joblib
import numpy as np

from .alerts import WindowedAlert
from .switching_ssm import build_ssm


class FeatureStream:
    """Stateful, causal feature builder. Use reset() to start a new stream."""

    def __init__(self, art: dict, alpha: float = 0.7):
        self.art = art
        self.alpha = alpha
        self.reset()

    def reset(self):
        self.ssm = build_ssm(len(self.art["top_idx"]), self.art["attack_ratio"])
        self.prev_rf = None
        self.prev_smooth = None

    def transform(self, rows):
        """rows: (n, F) or (F,). Returns (features, raw_regime_probs, smoothed_regime_probs)."""
        a = self.art
        rows = np.asarray(rows, dtype=np.float64)
        if rows.ndim == 1:
            rows = rows[None, :]
        # A single NaN/inf would poison the Kalman state for the rest of the stream.
        rows = np.nan_to_num(rows, nan=0.0, posinf=0.0, neginf=0.0)

        rf = (rows[:, a["sel_idx"]] - a["rf_mean"]) / a["rf_std"]
        obs = (rows[:, a["top_idx"]] - a["sssm_mean"]) / a["sssm_std"]

        n = len(rows)
        raw = np.empty((n, 2))
        smooth = np.empty((n, 2))
        diff = np.zeros_like(rf)
        for i in range(n):
            p = self.ssm.step(obs[i])
            s = p if self.prev_smooth is None else (
                self.alpha * p + (1 - self.alpha) * self.prev_smooth
            )
            if self.prev_rf is not None:
                diff[i] = rf[i] - self.prev_rf
            raw[i], smooth[i] = p, s
            self.prev_smooth, self.prev_rf = s, rf[i]

        return np.hstack([rf, diff, smooth]), raw, smooth


class StreamingDetector:
    def __init__(self, art: dict, window=50, on_rate=0.30, off_rate=0.10, flag_thr=0.5, hold=None):
        self.art = art
        self.feats = FeatureStream(art, art.get("alpha", 0.7))
        self.clf = art["clf_hybrid"]
        self.base = art["clf_baseline"]
        for c in (self.clf, self.base):
            c.n_jobs = 1  # per-chunk calls: threading overhead dominates otherwise
        self.alerter = WindowedAlert(window, on_rate, off_rate, flag_thr, hold=hold)
        self.reset()

    @classmethod
    def load(cls, path="artifacts/pard_model.joblib", **kw):
        return cls(joblib.load(path), **kw)

    def reset(self):
        self.feats.reset()
        self.alerter.reset()

    def process(self, rows) -> dict:
        """Process one or many rows in order; returns dict of per-row arrays."""
        F, raw, smooth = self.feats.transform(rows)
        k = F.shape[1] - 2  # [rf | diff] columns, without regime probs
        p = self.clf.predict_proba(F)[:, 1]
        pb = self.base.predict_proba(F[:, :k])[:, 1]

        alert = np.empty(len(p), dtype=int)
        rate = np.empty(len(p))
        for i, v in enumerate(p):
            alert[i], rate[i] = self.alerter.update(v)

        return {
            "p_attack": p,            # hybrid (regime features + RF)
            "p_baseline": pb,         # RF without regime features
            "regime_raw": raw,        # SSM posterior [normal, attack]
            "regime_smooth": smooth,  # EMA-smoothed posterior
            "alert": alert,           # incident alert state (0/1), windowed flag rate
            "alert_rate": rate,       # share of flagged flows in the current window
        }

    def step(self, row) -> dict:
        return {k: v[0] for k, v in self.process(row).items()}
