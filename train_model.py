"""
NetGuard AI - Model Training Script
Trains a Random Forest Classifier on synthetic network telemetry data.
Evaluates accuracy, precision, recall, and F1-score, and persists traffic_model.pkl.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

from data_generator import generate_dataset

FEATURE_COLS = [
    "bandwidth",
    "latency",
    "packet_loss",
    "cpu_utilization",
    "memory_utilization",
    "active_connections",
    "packets_sent",
    "packets_received"
]

MODEL_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "traffic_model.pkl")
CSV_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "network_data.csv")

def train():
    print("=" * 60)
    print("  NETGUARD AI - RANDOM FOREST MODEL TRAINING")
    print("=" * 60)

    # 1. Generate or load dataset
    if not os.path.exists(CSV_OUTPUT_PATH):
        print(f"[1/5] Generating 5,000 synthetic telemetry samples...")
        df = generate_dataset(n_samples=5000, anomaly_ratio=0.28, output_csv=CSV_OUTPUT_PATH)
    else:
        print(f"[1/5] Loading existing dataset from {CSV_OUTPUT_PATH}...")
        df = pd.read_csv(CSV_OUTPUT_PATH)

    print(f"      Total records: {len(df)}")
    print(f"      Normal samples: {len(df[df['label'] == 0])}")
    print(f"      Anomalous samples: {len(df[df['label'] == 1])}")

    # 2. Features and Target
    print("[2/5] Preparing feature matrix X and target y...")
    X = df[FEATURE_COLS]
    y = df["label"]

    # 3. Train/Test Split
    print("[3/5] Splitting into 80% train / 20% test sets...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. Train Random Forest Classifier
    print("[4/5] Training Random Forest Classifier (n_estimators=100, max_depth=12)...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced"
    )
    rf_model.fit(X_train, y_train)

    # 5. Evaluation
    print("[5/5] Evaluating model performance...")
    y_pred = rf_model.predict(X_test)
    y_prob = rf_model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n" + "-" * 40)
    print(f"  MODEL PERFORMANCE METRICS:")
    print(f"  * Accuracy:  {acc * 100:.2f}%")
    print(f"  * Precision: {prec * 100:.2f}%")
    print(f"  * Recall:    {rec * 100:.2f}%")
    print(f"  * F1-Score:  {f1 * 100:.2f}%")
    print("-" * 40)

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Anomaly"]))

    # Feature importances
    print("Feature Importances:")
    importances = rf_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for idx in sorted_idx:
        print(f"  * {FEATURE_COLS[idx]:<20}: {importances[idx] * 100:.2f}%")

    # Persist model
    joblib.dump(rf_model, MODEL_OUTPUT_PATH)
    print(f"\n[OK] Saved trained Random Forest model to: {MODEL_OUTPUT_PATH}")
    print("=" * 60)

    return rf_model

if __name__ == "__main__":
    train()
