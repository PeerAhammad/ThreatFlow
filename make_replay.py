"""
Pick the demo replay window from the SECOND half of the held-out test split (the half the alert
settings were NOT tuned on), preferring a window that starts quiet and contains several separate attacks,
so the dashboard shows the alert turning on, holding, and clearing.

    python make_replay.py --data <npy> --labels <npy> [--rows 3000]

Same split as train.py: first --max-samples rows, last 20% = test, second half of that = candidates.
Restart the API afterwards (the sample is loaded at startup).
"""

import argparse
import os

import numpy as np

from model.alerts import segments


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--max-samples", type=int, default=50_000)
    ap.add_argument("--rows", type=int, default=3000, help="window length")
    ap.add_argument("--gap", type=int, default=30, help="attack rows closer than this count as one attack")
    ap.add_argument("--lead", type=int, default=30, help="rows at the start of the window that must be attack-free")
    ap.add_argument("--out", default="data/replay_sample.npz")
    args = ap.parse_args()

    X = np.load(args.data)[: args.max_samples]
    y = (np.load(args.labels)[: args.max_samples] != 0).astype(int)
    split = int(0.8 * len(X))
    half = (len(X) - split) // 2
    Xs, ys = X[split + half:], y[split + half:]
    n = min(args.rows, len(ys))

    best, best_score = 0, (-1, -1)
    for s in range(0, len(ys) - n + 1, 50):
        w = ys[s:s + n]
        score = (int(w[: args.lead].sum() == 0), len(segments(w == 1, args.gap)))  # quiet start first, then #attacks
        if score > best_score:
            best, best_score = s, score

    w = ys[best:best + n]
    clusters = best_score[1]
    print(f"second half of test: {len(ys)} rows | window rows {best}..{best + n} of it")
    print(f"attack rows in window: {int(w.sum())} | separate attacks (gap>{args.gap}): {clusters} | starts quiet: {bool(best_score[0])}")
    if clusters < 2:
        print("WARNING: fewer than 2 separate attacks in the second half; the alert may stay on once. "
              "Try --gap 15, or a longer --rows.")

    if os.path.exists(args.out) and not os.path.exists(args.out.replace(".npz", "_full.npz")):
        os.replace(args.out, args.out.replace(".npz", "_full.npz"))
        print(f"previous sample kept as {args.out.replace('.npz', '_full.npz')}")
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    np.savez_compressed(args.out, X=Xs[best:best + n].astype(np.float32), y=w)
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
