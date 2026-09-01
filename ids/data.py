"""Loads the KDD Cup 1999 dataset and maps raw attack labels to categories.

Uses scikit-learn's built-in fetcher rather than a manual curl of the UCI
archive's raw .gz files — that URL now returns 403 Forbidden (checked
2026-09), so the original manual-download approach is dead anyway.
sklearn's fetcher handles caching, decompression, and column naming for
you, which is also just less code to maintain.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.datasets import fetch_kddcup99

# Maps each raw attack label (as it appears in the dataset) to one of the
# four attack categories the KDD Cup task defines, plus "normal". This
# mapping is a fact about the dataset itself (it's the same file KDD Cup
# published as `training_attack_types`, already tracked in dataset/) - not
# a methodology choice, so there's nothing to "make original" about it.
def load_attack_type_map(path: Path | str = "dataset/training_attack_types") -> dict[str, str]:
    mapping = {"normal": "normal"}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            name, category = line.split()
            mapping[name] = category
    return mapping


def load_dataset(percent10: bool = True) -> pd.DataFrame:
    """Returns a DataFrame with all original KDD99 columns plus
    'attack_type' (one of normal/dos/u2r/r2l/probe)."""
    bunch = fetch_kddcup99(percent10=percent10, as_frame=True)
    df = bunch.frame.copy()

    # sklearn returns label/categorical columns as bytes (b'smurf.'); decode
    # to plain str so they behave like every other string column.
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].apply(lambda v: v.decode() if isinstance(v, bytes) else v)

    attack_map = load_attack_type_map()
    df["attack_type"] = df["labels"].str.rstrip(".").map(attack_map)
    df = df.drop(columns=["labels"])
    return df
