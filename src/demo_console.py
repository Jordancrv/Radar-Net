from __future__ import annotations

import sys
from pathlib import Path
import random

sys.path.append(str(Path(__file__).resolve().parent))

from hybrid_engine import HybridEngine


def main() -> None:
    engine = HybridEngine()

    samples = [
        {
            "name": "TRAFICO NORMAL",
            "packet_rate": 45,
            "avg_size": 500,
            "unique_ports": 3,
            "syn_ratio": 0.10,
            "failed_logins": 1,
        },
        {
            "name": "PORT SCAN",
            "packet_rate": 100,
            "avg_size": 200,
            "unique_ports": 30,
            "syn_ratio": 0.50,
            "failed_logins": 1,
        },
        {
            "name": "BRUTE FORCE",
            "packet_rate": 90,
            "avg_size": 300,
            "unique_ports": 2,
            "syn_ratio": 0.15,
            "failed_logins": 15,
        },
        {
            "name": "SYN FLOOD",
            "packet_rate": 500,
            "avg_size": 400,
            "unique_ports": 4,
            "syn_ratio": 0.90,
            "failed_logins": 0,
        },
    ]

    for sample in samples:
        print("\\n===", sample["name"], "===")
        data = sample.copy()
        data.pop("name")
        decisions = engine.analyze(data)
        if not decisions:
            print("NORMAL: no se generaron alertas")
            continue

        for d in decisions:
            print(
                f"{d.attack} | nivel={d.severity} | confianza={d.confidence}% "
                f"| motor={d.source} | accion={d.action}"
            )


if __name__ == "__main__":
    main()
