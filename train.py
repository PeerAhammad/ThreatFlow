"""
Train + export the PARD-SSM hybrid detector.

    python train.py --data path/to/cicids2017_features.npy --labels path/to/cicids2017_labels.npy

Writes:
    artifacts/pard_model.joblib   scaler stats, feature indices, Kalman prior, both Random Forests
    data/replay_sample.npz        contiguous test window with the most normal<->attack transitions

Prints an ablation table on the held-out (last 20%) split, evaluated in streaming
mode from a fresh state: SSM alone / RF without regime features / hybrid / hybrid+alerts.
"""

import argparse
import os

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

from model.inference import FeatureStream, StreamingDetector


def oversample(X, y, seed=42):
    rng = np.random.default_rng(seed)
    X_min, X_maj = X[y == 1], X[y == 0]
    y_min, y_maj = y[y == 1], y[y == 0]
    idx = rng.choice(len(X_min), size=len(X_maj), replace=True)
    return np.vstack([X_maj, X_min[idx]]), np.hstack([y_maj, y_min[idx]])


def fit_rf(X, y, args):
    Xb, yb = oversample(X, y)
    clf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        min_samples_leaf=5,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    return clf.fit(Xb, yb)


def report(name, y, pred, score=None):
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    auc = roc_auc_score(y, score) if score is not None and len(set(y)) > 1 else float("nan")
    flips = int(np.abs(np.diff(pred)).sum())
    print(f"{name:<30} P={p:.3f}  R={r:.3f}  F1={f:.3f}  AUC={auc:.3f}  label flips={flips}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--max-samples", type=int, default=50_000)
    ap.add_argument("--n-estimators", type=int, default=100)
    ap.add_argument("--max-depth", type=int, default=14)
    ap.add_argument("--out", default="artifacts/pard_model.joblib")
    ap.add_argument("--sample-out", default="data/replay_sample.npz")
    ap.add_argument("--sample-rows", type=int, default=10_000)
    args = ap.parse_args()

    X = np.load(args.data)[: args.max_samples].astype(np.float64)
    y = (np.load(args.labels)[: args.max_samples] != 0).astype(int)
    split = int(0.8 * len(X))
    X_tr, X_te, y_tr, y_te = X[:split], X[split:], y[:split], y[split:]
    print(f"train={len(X_tr)} test={len(X_te)} attack ratio train={y_tr.mean():.3f} test={y_te.mean():.3f}")

    # Feature selection / scaling: fit on train only
    F_dim = X.shape[1]
    sel = SelectKBest(f_classif, k=min(20, F_dim)).fit(X_tr, y_tr)
    sel_idx = np.flatnonzero(sel.get_support())
    scores = np.nan_to_num(sel.scores_, nan=-np.inf)  # constant columns score NaN: rank them last
    top_idx = np.argsort(scores)[::-1][: min(8, F_dim)]

    rf_raw = X_tr[:, sel_idx]
    s_raw = X_tr[:, top_idx]
    art = {
        "sel_idx": sel_idx,
        "rf_mean": rf_raw.mean(0),
        "rf_std": rf_raw.std(0) + 1e-6,
        "top_idx": top_idx,
        "sssm_mean": s_raw.mean(0),
        "sssm_std": s_raw.std(0) + 1e-6,
        "attack_ratio": float(y_tr.mean()),
        "alpha": 0.7,
    }

    # Training features: run the causal SSM over the train split
    F_tr, _, _ = FeatureStream(art, art["alpha"]).transform(X_tr)
    k = 2 * len(sel_idx)  # [rf | diff] columns
    print("fitting Random Forests ...")
    art["clf_hybrid"] = fit_rf(F_tr, y_tr, args)
    art["clf_baseline"] = fit_rf(F_tr[:, :k], y_tr, args)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump(art, args.out, compress=3)
    mb = os.path.getsize(args.out) / 1e6
    print(f"saved {args.out} ({mb:.1f} MB)" + ("  <-- over 50 MB, lower --n-estimators" if mb > 50 else ""))

    # Held-out evaluation, streaming, fresh state (what the demo actually does)
    out = StreamingDetector(art).process(X_te)
    print(f"\nHeld-out streaming results (ground-truth label flips = {int(np.abs(np.diff(y_te)).sum())})")
    sm = out["regime_smooth"][:, 1]
    report("SSM alone (smoothed>=0.5)", y_te, (sm >= 0.5).astype(int), sm)
    report("RF, no regime features", y_te, (out["p_baseline"] >= 0.5).astype(int), out["p_baseline"])
    report("Hybrid (SSM + RF) >=0.5", y_te, (out["p_attack"] >= 0.5).astype(int), out["p_attack"])
    report("Hybrid + hysteresis alert", y_te, out["alert"])

    # Replay sample: contiguous window with the most normal<->attack transitions
    n = min(args.sample_rows, len(X_te))
    trans = np.r_[0, np.abs(np.diff(y_te))]
    cs = np.r_[0, np.cumsum(trans)]
    starts = np.arange(len(X_te) - n + 1)
    best = int(starts[np.argmax(cs[starts + n] - cs[starts])])
    os.makedirs(os.path.dirname(args.sample_out) or ".", exist_ok=True)
    np.savez_compressed(args.sample_out, X=X_te[best:best + n].astype(np.float32), y=y_te[best:best + n])
    print(f"saved {args.sample_out} (rows {best}..{best + n} of test split)")


if __name__ == "__main__":
    main()
