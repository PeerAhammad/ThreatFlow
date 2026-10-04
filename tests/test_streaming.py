import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from model.inference import FeatureStream  # noqa: E402


def original_causal_smooth(probs, alpha, seed=None):
    """Verbatim from the original experiment script."""
    smoothed = probs.copy().astype(float)
    start_row = seed if seed is not None else smoothed[0]
    smoothed[0] = alpha * smoothed[0] + (1 - alpha) * start_row
    for i in range(1, len(smoothed)):
        smoothed[i] = alpha * smoothed[i] + (1 - alpha) * smoothed[i - 1]
    return smoothed


def make_art(F=30, seed=0):
    rng = np.random.default_rng(seed)
    sel_idx = np.arange(20)
    top_idx = np.arange(8)
    return {
        "sel_idx": sel_idx, "rf_mean": rng.normal(size=20), "rf_std": np.ones(20),
        "top_idx": top_idx, "sssm_mean": rng.normal(size=8), "sssm_std": np.ones(8),
        "attack_ratio": 0.3, "alpha": 0.7,
    }


def make_rows(n=600, F=30, seed=1):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, F))
    X[200:350] += 2.5  # an "attack" burst
    return X


def test_chunked_equals_row_by_row():
    art, X = make_art(), make_rows()
    a = FeatureStream(art).transform(X)
    fs = FeatureStream(art)
    rows = [fs.transform(x) for x in X]
    for j in range(3):
        b = np.vstack([r[j] for r in rows])
        assert np.allclose(a[j], b)


def test_online_ema_matches_original_causal_smooth():
    art, X = make_art(), make_rows()
    _, raw, smooth = FeatureStream(art).transform(X)
    assert np.allclose(smooth, original_causal_smooth(raw, art["alpha"]))


def test_nan_does_not_poison_state():
    art, X = make_art(), make_rows()
    X = X.copy()
    X[100, 3] = np.nan
    X[101, 5] = np.inf
    F, raw, smooth = FeatureStream(art).transform(X)
    assert np.isfinite(F).all() and np.isfinite(smooth).all()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
