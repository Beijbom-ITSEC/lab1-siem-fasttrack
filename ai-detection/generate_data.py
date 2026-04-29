#!/usr/bin/env python3
"""Genererar realistisk Wazuh-larmdata med inbyggda anomalier för träning."""

import json, random
from datetime import datetime, timedelta

def generate_alerts(days=7, seed=42):
    random.seed(seed)
    start = datetime.now() - timedelta(days=days)
    alerts = []
    rule_ids = [5501, 5502, 5503, 5710, 5715, 5716, 1002, 31100, 31101, 80792]
    src_ips  = [f"192.168.1.{i}" for i in range(10, 30)] + ["10.0.0.5", "172.16.0.1"]

    for hour in range(days * 24):
        ts = start + timedelta(hours=hour)
        h = ts.hour

        # Normalt trafikmönster: låg aktivitet nattetid, normal dagtid
        if 0 <= h < 6:
            count = random.randint(0, 3)
        elif 8 <= h < 18:
            count = random.randint(5, 20)
        else:
            count = random.randint(1, 8)

        # Injicera anomalier: dag 3 kl 02:00 och dag 5 kl 14:00
        day = hour // 24
        if (day == 3 and 2 <= h < 4) or (day == 5 and 14 <= h < 16):
            count = random.randint(80, 150)

        for _ in range(count):
            alerts.append({
                "timestamp": (ts + timedelta(minutes=random.randint(0, 59))).isoformat(),
                "rule": {
                    "id": str(random.choice(rule_ids)),
                    "level": random.choices([3, 5, 7, 10, 12], weights=[40, 30, 15, 10, 5])[0],
                    "description": "Simulated event"
                },
                "agent": {"name": "wsl-test"},
                "data": {
                    "srcip": random.choice(src_ips),
                    "dstport": str(random.choice([22, 80, 443, 3389, 8080]))
                }
            })

    # Formatera som Wazuh API-svar
    return {"hits": {"hits": [{"_source": a} for a in alerts]}}

if __name__ == "__main__":
    data = generate_alerts(days=7)
    with open("baseline_alerts.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"Genererade {len(data['hits']['hits'])} händelser → baseline_alerts.json")
    print("Anomalier injicerade: dag 3 kl 02-04, dag 5 kl 14-16")
