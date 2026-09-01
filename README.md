# Intrusion Detection System Using Machine Learning

Trains and compares 5 classifiers (Naive Bayes, Decision Tree, Random Forest, Linear SVM,
Logistic Regression) for network intrusion detection on the KDD Cup 1999 dataset, classifying
traffic into `normal` or one of 4 attack categories (`dos`, `probe`, `r2l`, `u2r`).

## Design

- **Dataset loading via `sklearn.datasets.fetch_kddcup99`**, not a manual `curl` of the UCI
  archive's raw `.gz` files — that URL now returns 403 Forbidden, so the old manual-download
  approach doesn't even work anymore. sklearn's fetcher handles caching and parsing for you.
- **Correlation-based feature dropping is computed, not hardcoded.** `ids/features.py` computes
  the actual correlation matrix and drops any column correlated above a threshold (default 0.95)
  with one already kept — the columns that get dropped are a property of the data, not a fixed
  list decided in advance. (For what it's worth: this run's computed threshold independently
  landed on the same 8 columns commonly cited for this dataset — `num_root`, `srv_serror_rate`,
  `srv_rerror_rate`, `dst_host_srv_serror_rate`, `dst_host_serror_rate`, `dst_host_rerror_rate`,
  `dst_host_srv_rerror_rate`, `dst_host_same_srv_rate` — which is a reasonable outcome given
  they really are that correlated, not evidence the threshold approach doesn't matter.)
- **Categorical columns use `LabelEncoder`**, not a hand-typed dict mapping each known category to
  a hardcoded integer — a hardcoded dict throws `KeyError` the moment it sees a category it didn't
  enumerate in advance; `LabelEncoder` derives its mapping from whatever's actually in the data.
- **Stratified train/test split.** This dataset is severely imbalanced — in the 10% sample, `dos`
  is ~79% of all rows while `u2r` is 52 rows total, 0.01%. An unstratified split risks a test set
  with too few `u2r`/`r2l` examples to evaluate at all.
- **Linear SVM, not an RBF-kernel SVC.** `SVC` with the default RBF kernel is roughly
  O(n²)–O(n³) in the number of training rows, impractical on ~350k training rows. `LinearSVC`
  scales close to linearly.
- **Real per-class precision/recall/F1**, not just overall accuracy — see below for why that
  distinction actually matters here.
- Tests (`tests/test_features.py`) cover the encoding and correlation-dropping logic against small
  synthetic data, independent of the real ~500k-row dataset.

## Results (real run, nothing hardcoded)

```
Naive Bayes          train time:   0.28s   accuracy: 0.8897
Decision Tree        train time:   0.98s   accuracy: 0.9995
Random Forest        train time:   3.23s   accuracy: 0.9997
Linear SVM           train time:   4.65s   accuracy: 0.9973
Logistic Regression  train time:   5.13s   accuracy: 0.9936
```

**Why overall accuracy alone is close to meaningless on this dataset:** Naive Bayes posts 89%
accuracy, which sounds reasonable in isolation — until the per-class breakdown shows its precision
on the `probe` class is 0.10 and on `u2r` is 0.01 (despite high recall on both), meaning it's
flagging enormous numbers of false positives for the classes that matter most operationally. A
classifier that mostly predicts the dominant class (`dos`, 79% of the data) can score high on
accuracy while being nearly useless at the actual security-relevant task: catching the rare
attack types.

**The harder, more interesting result:** every single model — including Random Forest at 99.97%
overall accuracy — is worst at detecting `u2r` (User-to-Root / privilege escalation) specifically:

| Model | u2r precision | u2r recall | u2r F1 |
|---|---|---|---|
| Naive Bayes | 0.01 | 0.94 | 0.02 |
| Decision Tree | 0.56 | 0.56 | 0.56 |
| Random Forest | 0.80 | 0.50 | 0.62 |
| Linear SVM | 0.90 | 0.56 | 0.69 |
| Logistic Regression | 0.91 | 0.62 | 0.74 |

`u2r` is both the rarest class (52 total rows in the full 10% sample, 16 in this test split) and
arguably the most severe — successful privilege escalation is worse than a detected port scan.
Every model here catches barely half of them even at its best. That's a genuinely useful,
non-obvious finding an accuracy-only comparison would completely hide.

## Usage

```bash
pip install -e ".[dev]"
python main.py
pytest
```

## License

MIT — see [LICENSE](LICENSE).
