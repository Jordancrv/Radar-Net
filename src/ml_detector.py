from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """Modelo base para detectar desviaciones del tráfico normal."""

    def __init__(self) -> None:
        self.model = IsolationForest(
            n_estimators=150,
            contamination=0.08,
            random_state=42
        )
        self.feature_names = ["packet_rate", "avg_size", "unique_ports", "syn_ratio"]
        self._train()

    def _train(self) -> None:
        rng = np.random.default_rng(42)
        normal = np.column_stack([
            rng.normal(45, 10, 800).clip(5, None),        # packet_rate
            rng.normal(500, 120, 800).clip(64, None),     # avg_size
            rng.normal(4, 2, 800).clip(1, None),          # unique_ports
            rng.normal(0.10, 0.05, 800).clip(0, 1),       # syn_ratio
        ])
        self.model.fit(normal)

    def predict(self, packet_rate: float, avg_size: float,
                unique_ports: float, syn_ratio: float) -> tuple[bool, float]:
        x = np.array([[packet_rate, avg_size, unique_ports, syn_ratio]])
        pred = self.model.predict(x)[0]
        score = float(self.model.decision_function(x)[0])
        return pred == -1, score
