"""
Kalman-filter bank + Markov regime posterior.

Faithful extraction of the PARD-SSM hybrid model: two independent Kalman
filters (normal / attack dynamics) whose predictive likelihoods are combined
with a Markov prior into a 2-regime posterior, one observation at a time.
Parameters are hand-set (no learned weights), so there is nothing to train here.
"""

import numpy as np


class KalmanFilter:
    def __init__(self, A, C, Q, R, x0, P0):
        self.A = A
        self.C = C
        self.Q = Q
        self.R = R
        self.x = x0.copy()
        self.P = P0.copy()

    def predict(self):
        self.x = self.A @ self.x
        self.P = self.A @ self.P @ self.A.T + self.Q

    def update(self, y):
        S = self.C @ self.P @ self.C.T + self.R
        S += np.eye(S.shape[0]) * 1e-6

        K = self.P @ self.C.T @ np.linalg.inv(S)
        y_pred = self.C @ self.x
        diff = y - y_pred

        self.x = self.x + K @ diff

        I_KC = np.eye(self.P.shape[0]) - K @ self.C
        self.P = I_KC @ self.P @ I_KC.T + K @ self.R @ K.T

        sign, log_det_S = np.linalg.slogdet(S)
        log_det_S = max(log_det_S, -1e6)
        dim = y.shape[0]
        log_like = (
            -0.5 * float(diff.T @ np.linalg.inv(S) @ diff)
            - 0.5 * log_det_S
            - 0.5 * dim * np.log(2 * np.pi)
        )
        log_like = np.clip(log_like, -500, 0)
        return np.exp(log_like)


class SwitchingStateSpaceModel:
    def __init__(self, filters, transition_matrix, prior=None):
        self.filters = filters
        self.M = len(filters)
        self.T = transition_matrix
        self.regime_probs = prior if prior is not None else np.ones(self.M) / self.M

    def step(self, y):
        likelihoods = np.zeros(self.M)
        for i, kf in enumerate(self.filters):
            kf.predict()
            likelihoods[i] = kf.update(y)

        prior = self.T.T @ self.regime_probs
        posterior = likelihoods * prior + 1e-8
        posterior = posterior / posterior.sum()

        self.regime_probs = posterior
        return posterior.copy()


def build_ssm(dim: int, attack_ratio: float) -> SwitchingStateSpaceModel:
    """Same constants as the original experiment script."""
    A1, Q1 = np.eye(dim) * 0.95, np.eye(dim) * 0.001   # normal: stable, quiet
    A2, Q2 = np.eye(dim) * 1.5, np.eye(dim) * 0.5      # attack: explosive, noisy
    C = np.eye(dim)
    R = np.eye(dim) * 0.2
    x0 = np.zeros(dim)
    P0 = np.eye(dim)

    kf1 = KalmanFilter(A1, C, Q1, R, x0, P0)
    kf2 = KalmanFilter(A2, C, Q2, R, x0, P0)

    transition = np.array([[0.90, 0.10],
                           [0.15, 0.85]])
    prior = np.array([1 - attack_ratio, attack_ratio])
    return SwitchingStateSpaceModel([kf1, kf2], transition, prior=prior)
