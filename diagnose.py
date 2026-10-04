"""
Why did the alert layer hurt, and what does the SSM add?

    python diagnose.py --data <npy> --labels <npy> [--margin 20]

Same split as train.py (first --max-samples rows, last 20% = test).
Alert settings are CHOSEN on the first half of the test split and REPORTED on the second half.

Metric definitions (all in rows/flows):
  incident        attack rows merged when <= margin apart
  quiet row       more than `margin` rows from ANY attack row (alert may linger `margin` rows
                  after an attack without counting as spurious)
  spurious-time   share of quiet rows where the alert is ON
  coverage        share of attack rows where the alert is ON
"""

import argparse

import numpy as np
from sklearn.metrics import precision_recall_curve, precision_recall_fscore_support

from model.alerts import WindowedAlert, incident_metrics, segments
from model.inference import StreamingDetector


def consecutive_alert(p, on=0.5, off=0.35, min_on=3, min_off=5):
    """The ORIGINAL logic: N consecutive flagged rows to turn on, M consecutive low rows to turn off."""
    state, up, down, out = False, 0, 0, []
    for v in p:
        if not state:
            up = up + 1 if v >= on else 0
            if up >= min_on:
                state, up, down = True, 0, 0
        else:
            down = down + 1 if v < off else 0
            if down >= min_off:
                state, up, down = False, 0, 0
        out.append(int(state))
    return np.array(out)


def windowed(p, **kw):
    a = WindowedAlert(**kw)
    return np.array([a.update(v)[0] for v in p])


def row(name, m):
    print(f"{name:<46} detected {m['detected']}/{m['incidents']}  delay {m['median_delay_rows']:>4.0f}  "
          f"coverage {m['coverage']:>4.0%}  episodes {m['episodes']:>3} (false {m['false_episodes']})  "
          f"spurious-time {m['quiet_alert_frac']:.1%}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--max-samples", type=int, default=50_000)
    ap.add_argument("--model", default="artifacts/pard_model.joblib")
    ap.add_argument("--margin", type=int, default=20, help="incident merge distance AND allowed alert linger (rows)")
    ap.add_argument("--max-spurious", type=float, default=0.05, help="spurious-time budget when choosing settings")
    ap.add_argument("--max-episode-ratio", type=float, default=2.0,
                    help="max alert episodes per incident (limits flicker) when choosing settings")
    args = ap.parse_args()
    M = args.margin

    X = np.load(args.data)[: args.max_samples].astype(np.float64)
    y = (np.load(args.labels)[: args.max_samples] != 0).astype(int)
    split = int(0.8 * len(X))
    X_te, y_te = X[split:], y[split:]

    out = StreamingDetector.load(args.model).process(X_te)
    p, sm = out["p_attack"], out["regime_smooth"][:, 1]
    n, half = len(y_te), len(y_te) // 2

    # 1. Structure of the stream
    runs = segments(y_te == 1, 1)
    lens = [e - s + 1 for s, e in runs]
    nb = np.mean((y_te[1:-1] == 1) & (y_te[:-2] == 1) & (y_te[2:] == 1)) / max(y_te.mean(), 1e-9)
    print(f"test rows {n} | attack rows {y_te.sum()} | contiguous attack runs {len(runs)} "
          f"(median length {np.median(lens) if lens else 0:.0f})")
    print("incidents by merge distance: " + "  ".join(f"{g}->{len(segments(y_te == 1, g))}" for g in (5, 10, 20, 50, 100, 200)))
    print(f"attack rows whose two neighbours are also attack: {nb:.0%}")
    print(f"flagged by hybrid (p>=0.5): {(p >= 0.5).sum()} rows\n")

    # 2. SSM alone: threshold chosen on 1st half, scored on 2nd half
    pr, rc, th = precision_recall_curve(y_te[:half], sm[:half])
    f1 = 2 * pr * rc / (pr + rc + 1e-12)
    t = th[np.argmax(f1[:-1])]
    P, R, F, _ = precision_recall_fscore_support(y_te[half:], sm[half:] >= t, average="binary", zero_division=0)
    print(f"SSM alone, threshold {t:.3f} (tuned on 1st half) -> 2nd half  P={P:.3f} R={R:.3f} F1={F:.3f}\n")

    # 3. Alert layers
    def metrics(alert, a, b, margin=M):
        return incident_metrics(y_te[a:b], alert[a:b], margin=margin)

    grid = (
        [dict(window=w, on_rate=on, off_rate=off) for w in (10, 20, 50) for on in (0.2, 0.3) for off in (0.1, 0.2)]
        + [dict(window=w, on_rate=on, hold=h) for w in (10, 20, 50) for on in (0.2, 0.3, 0.5) for h in (5, 10, 15, 20, 30)]
    )
    first = [(kw, metrics(windowed(p, **kw), 0, half)) for kw in grid]
    ok = [(kw, m) for kw, m in first
          if m["detected"] == m["incidents"] and m["quiet_alert_frac"] <= args.max_spurious
          and m["episodes"] <= max(2, args.max_episode_ratio * m["incidents"])]
    if ok:
        best, _ = min(ok, key=lambda km: (km[1]["median_delay_rows"], km[1]["quiet_alert_frac"]))
        how = (f"fastest config detecting every incident with spurious-time <= {args.max_spurious:.0%} "
               f"and <= {args.max_episode_ratio:g} episodes per incident")
    else:
        best, _ = max(first, key=lambda km: km[1]["detected"] / max(km[1]["incidents"], 1) - km[1]["quiet_alert_frac"])
        how = "NO config met the spurious-time / flicker budget; best detection-minus-spurious instead"

    print(f"Alert layers, 2nd half of test (margin {M}):")
    row("original consecutive-row hysteresis", metrics(consecutive_alert(p), half, n))
    row("rate mode default (50, .30, .10)", metrics(windowed(p), half, n))
    chosen = windowed(p, **best)
    mc = metrics(chosen, half, n)
    row(f"CHOSEN {best}", mc)
    for mm in (10, 50):
        row(f"  same config judged at margin {mm}", metrics(chosen, half, n, margin=mm))
    flagged = int((p[half:] >= 0.5).sum())
    print(f"\nchosen = {how}")
    print(f"compression on 2nd half: {flagged} flagged flows -> {mc['episodes']} alert episodes")
    print(f"StreamingDetector kwargs: {best}")
    print("(~10 incidents per half is a small sample: prefer a simple setting over a lucky one)")


if __name__ == "__main__":
    main()
