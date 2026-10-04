"""
Incident-level alerting for flow streams.

CICIDS2017 attack traffic is interleaved with benign background flows, so
"N consecutive flagged rows" almost never happens. Instead, track the SHARE of
flagged flows in a sliding window.

Two OFF rules:
  rate mode (hold=None): OFF when the window's flagged share falls to off_rate.
                         Lingers ~window rows after an attack ends.
  hold mode (hold=N):    OFF after N consecutive unflagged flows ("N flows of silence"),
                         then the window is cleared so the next alert needs fresh evidence.
                         Linger is exactly N rows, independent of the ON speed.
"""

from collections import deque

import numpy as np


class WindowedAlert:
    def __init__(self, window=50, on_rate=0.30, off_rate=0.10, flag_thr=0.5, min_fill=None, hold=None):
        self.window, self.on_rate, self.off_rate, self.flag_thr = window, on_rate, off_rate, flag_thr
        self.min_fill = min_fill if min_fill is not None else window // 2  # rate mode: no alert on a near-empty window
        self.hold = hold
        self.on_count = max(1, int(np.ceil(on_rate * window)))             # hold mode: flags needed inside the window
        self.reset()

    def reset(self):
        self.buf, self.count, self.on, self.silence = deque(), 0, False, 0

    def update(self, p):
        """p: attack probability of the newest flow. Returns (alert_state, window_rate)."""
        f = int(p >= self.flag_thr)
        self.silence = 0 if f else self.silence + 1
        self.buf.append(f)
        self.count += f
        if len(self.buf) > self.window:
            self.count -= self.buf.popleft()
        rate = self.count / len(self.buf)

        if self.hold is None:  # rate mode
            if not self.on:
                if len(self.buf) >= self.min_fill and rate >= self.on_rate:
                    self.on = True
            elif rate <= self.off_rate:
                self.on = False
        else:                  # hold mode
            if not self.on:
                if self.count >= self.on_count:
                    self.on = True
            elif self.silence >= self.hold:
                self.on = False
                self.buf.clear()
                self.count = 0
        return int(self.on), rate


def segments(mask, gap):
    """(start, end) index pairs of True runs; runs separated by <= gap-1 False rows are merged
    (gap=1 -> strictly contiguous runs)."""
    idx = np.flatnonzero(mask)
    if len(idx) == 0:
        return []
    breaks = np.flatnonzero(np.diff(idx) > gap)
    starts = np.r_[idx[0], idx[breaks + 1]]
    ends = np.r_[idx[breaks], idx[-1]]
    return list(zip(starts.tolist(), ends.tolist()))


def incident_metrics(y, alert, margin=20):
    """
    y: 0/1 ground truth per row; alert: 0/1 alert state per row.
    Incident  = attack rows merged when separated by <= margin rows.
    Quiet row = more than `margin` rows away from ANY attack row. An alert may linger up to
                `margin` rows after an attack without being counted as spurious.
    """
    y, alert = np.asarray(y), np.asarray(alert)
    n = len(y)
    incidents = segments(y == 1, margin)
    episodes = segments(alert == 1, 1)

    cs = np.r_[0, np.cumsum(y == 1)]
    idx = np.arange(n)
    near = (cs[np.clip(idx + margin + 1, 0, n)] - cs[np.clip(idx - margin, 0, n)]) > 0

    detected, delays = 0, []
    for s_, e_ in incidents:
        hit = np.flatnonzero(alert[s_:e_ + 1])
        if len(hit):
            detected += 1
            delays.append(int(hit[0]))

    false_eps = sum(1 for s_, e_ in episodes if not near[s_:e_ + 1].any())
    quiet = ~near
    return {
        "incidents": len(incidents),
        "detected": detected,
        "median_delay_rows": float(np.median(delays)) if delays else float("nan"),
        "coverage": float(alert[y == 1].mean()) if (y == 1).any() else float("nan"),
        "episodes": len(episodes),
        "false_episodes": false_eps,
        "quiet_alert_frac": float(alert[quiet].mean()) if quiet.any() else 0.0,
    }
