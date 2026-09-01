"""Entrypoint: load KDD Cup 99, prepare features, train and compare classifiers.

Every number printed below comes from an actual run of this script against
the real dataset - nothing here is a hardcoded/copied result.
"""

from ids.data import load_dataset
from ids.features import prepare_features
from ids.train import split_data, train_and_evaluate


def main() -> None:
    print("Loading KDD Cup 1999 (10% sample) via scikit-learn...")
    df = load_dataset(percent10=True)
    print(f"Loaded {df.shape[0]} rows, {df.shape[1]} columns.")
    print(df["attack_type"].value_counts())
    print()

    X, y, dropped = prepare_features(df, correlation_threshold=0.95)
    print(f"Dropped {len(dropped)} highly-correlated columns: {dropped}")
    print(f"Feature matrix: {X.shape}")
    print()

    X_train, X_test, y_train, y_test = split_data(X, y)
    print(f"Train: {X_train.shape[0]} rows, Test: {X_test.shape[0]} rows (stratified split)")
    print()

    results = train_and_evaluate(X_train, X_test, y_train, y_test)

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for r in results:
        print(f"{r.name:<20} train time: {r.train_seconds:6.2f}s   accuracy: {r.accuracy:.4f}")

    print()
    for r in results:
        print("=" * 70)
        print(r.name)
        print("=" * 70)
        print(r.report)


if __name__ == "__main__":
    main()
