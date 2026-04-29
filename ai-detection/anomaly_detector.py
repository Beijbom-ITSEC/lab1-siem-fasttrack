#!/usr/bin/env python3
"""AI-stödd anomalidetektering för Wazuh-loggar med Isolation Forest."""

import json, sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings("ignore")


def load_alerts(filepath):
    with open(filepath) as f:
        data = json.load(f)
    records = []
    for hit in data["hits"]["hits"]:
        s = hit["_source"]
        records.append({
            "timestamp":  s.get("timestamp", ""),
            "rule_id":    s.get("rule", {}).get("id", 0),
            "rule_level": s.get("rule", {}).get("level", 0),
            "src_ip":     s.get("data", {}).get("srcip", "unknown"),
            "dst_port":   s.get("data", {}).get("dstport", 0),
        })
    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def extract_features(df, window="1h"):
    df = df.set_index("timestamp").sort_index()
    features = df.resample(window).agg(
        event_count  = ("rule_id",    "count"),
        unique_rules = ("rule_id",    "nunique"),
        avg_severity = ("rule_level", "mean"),
        max_severity = ("rule_level", "max"),
        unique_ips   = ("src_ip",     "nunique"),
    ).fillna(0)

    features["hour"]     = features.index.hour
    features["is_night"] = (features["hour"].lt(6) | features["hour"].gt(22)).astype(int)

    mean = features["event_count"].mean()
    std  = features["event_count"].std()
    features["zscore"] = (features["event_count"] - mean) / (std if std > 0 else 1)
    return features


def detect(features, contamination=0.1):
    cols = ["event_count", "unique_rules", "avg_severity", "max_severity", "unique_ips", "is_night", "zscore"]
    X = StandardScaler().fit_transform(features[cols].values)
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    features["anomaly_score"] = model.fit_predict(X)
    features["is_anomaly"]    = features["anomaly_score"] == -1
    return features


def report(features):
    anomalies = features[features["is_anomaly"]]
    print("=" * 58)
    print("  ANOMALIDETEKTERINGSRAPPORT — Isolation Forest")
    print("=" * 58)
    print(f"Period:               {features.index.min().date()} — {features.index.max().date()}")
    print(f"Tidsperioder totalt:  {len(features)}")
    print(f"Anomalier hittade:    {len(anomalies)}")
    if len(anomalies):
        print("\nDetaljer:")
        for ts, row in anomalies.iterrows():
            print(f"  {ts}  |  {int(row['event_count']):4d} händelser  "
                  f"|  avg severity {row['avg_severity']:.1f}  "
                  f"|  {int(row['unique_ips'])} unika IP:n")
    print("=" * 58)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "baseline_alerts.json"
    print(f"Laddar {path}...")
    df       = load_alerts(path)
    features = extract_features(df)
    features = detect(features)
    report(features)
    features.to_csv("anomaly_results.csv")
    print("\nResultat → anomaly_results.csv")
