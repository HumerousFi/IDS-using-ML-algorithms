"""Feature preprocessing: categorical encoding and correlation-based pruning.

Two deliberate departures from the common tutorial version of this
pipeline (see git history / README for the full comparison):

1. Categorical columns (protocol_type, service, flag) are encoded with
   sklearn's LabelEncoder, not hand-typed dictionaries mapping each known
   category to a hardcoded integer. A hand-typed dict silently breaks the
   moment the data contains a category it doesn't list; LabelEncoder
   derives its mapping from whatever's actually in the data.

2. Highly-correlated numeric columns are dropped via a programmatic
   threshold against the actual computed correlation matrix, not a fixed
   list of column names decided in advance. Which columns end up
   correlated is a property of the data, not something to hardcode once
   and reuse regardless of what you're actually looking at.
"""

from __future__ import annotations

import pandas as pd
from sklearn.preprocessing import LabelEncoder

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]


def encode_categoricals(df: pd.DataFrame, columns: list[str] = CATEGORICAL_COLUMNS) -> pd.DataFrame:
    df = df.copy()
    for col in columns:
        df[col] = LabelEncoder().fit_transform(df[col])
    return df


def find_correlated_columns(df: pd.DataFrame, threshold: float = 0.95) -> list[str]:
    """Returns columns to drop: for each pair of numeric columns whose
    absolute correlation exceeds `threshold`, keeps the first and marks the
    second for dropping - so highly redundant features are pruned without
    hardcoding which ones in advance."""
    numeric = df.select_dtypes(include="number")
    corr = numeric.corr().abs()

    to_drop: set[str] = set()
    columns = corr.columns
    for i, col_a in enumerate(columns):
        if col_a in to_drop:
            continue
        for col_b in columns[i + 1 :]:
            if col_b in to_drop:
                continue
            if corr.loc[col_a, col_b] > threshold:
                to_drop.add(col_b)
    return sorted(to_drop)


def prepare_features(df: pd.DataFrame, correlation_threshold: float = 0.95) -> tuple[pd.DataFrame, pd.Series, list[str]]:
    """Returns (X, y, dropped_columns)."""
    df = encode_categoricals(df)
    y = df["attack_type"]
    X = df.drop(columns=["attack_type"])

    dropped = find_correlated_columns(X, threshold=correlation_threshold)
    X = X.drop(columns=dropped)
    return X, y, dropped
