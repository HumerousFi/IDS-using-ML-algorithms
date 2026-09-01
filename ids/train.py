"""Trains and compares classifiers, reporting real per-class metrics.

Two departures from the tutorial version worth calling out:

1. The train/test split is stratified. KDD99 is severely imbalanced
   (in the 10% sample, 'smurf' alone is ~57% of all rows while U2R attacks
   are a few dozen rows total) - an unstratified split risks a test set
   with too few U2R/R2L examples to evaluate meaningfully at all.

2. Results report precision/recall/F1 per class, not just overall
   accuracy. With this much imbalance, a classifier that never predicts
   U2R or R2L at all can still post a high accuracy score - which is
   exactly the failure mode accuracy alone hides and per-class metrics
   expose.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import MinMaxScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

# LinearSVC, not SVC(gamma='scale'): the RBF-kernel SVC the tutorial version
# uses is roughly O(n^2)-O(n^3) in the number of training rows, which is
# impractical on KDD99's ~500k rows (the tutorial doesn't mention how long
# it actually took to run). LinearSVC scales roughly linearly and is the
# standard choice for a linearly-separable-ish, high-row-count problem like
# this one.
MODELS = {
    "Naive Bayes": GaussianNB(),
    "Decision Tree": DecisionTreeClassifier(random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    "Linear SVM": LinearSVC(max_iter=5000, dual="auto"),
    "Logistic Regression": LogisticRegression(max_iter=1000),
}


@dataclass
class ModelResult:
    name: str
    train_seconds: float
    accuracy: float
    report: str  # full sklearn classification_report, per-class precision/recall/F1


def split_data(X: pd.DataFrame, y: pd.Series, test_size: float = 0.3, random_state: int = 42):
    return train_test_split(X, y, test_size=test_size, random_state=random_state, stratify=y)


def train_and_evaluate(X_train, X_test, y_train, y_test) -> list[ModelResult]:
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    results = []
    for name, model in MODELS.items():
        start = time.time()
        model.fit(X_train_scaled, y_train)
        train_seconds = time.time() - start

        y_pred = model.predict(X_test_scaled)
        accuracy = (y_pred == y_test.values).mean()
        report = classification_report(y_test, y_pred, zero_division=0)

        results.append(
            ModelResult(name=name, train_seconds=train_seconds, accuracy=accuracy, report=report)
        )
    return results
