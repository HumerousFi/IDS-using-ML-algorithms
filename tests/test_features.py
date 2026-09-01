import pandas as pd

from ids.features import encode_categoricals, find_correlated_columns, prepare_features


def test_encode_categoricals_produces_numeric_columns():
    df = pd.DataFrame(
        {
            "protocol_type": ["tcp", "udp", "tcp", "icmp"],
            "service": ["http", "dns", "http", "ecr_i"],
            "flag": ["SF", "S0", "SF", "REJ"],
            "duration": [1, 2, 3, 4],
        }
    )
    encoded = encode_categoricals(df)
    for col in ["protocol_type", "service", "flag"]:
        assert pd.api.types.is_numeric_dtype(encoded[col])
    # unrelated column untouched
    assert encoded["duration"].tolist() == [1, 2, 3, 4]


def test_encode_categoricals_handles_unseen_categories_without_crashing():
    # A hardcoded pmap/fmap dict (the tutorial's approach) throws a KeyError
    # the moment it sees a category it didn't enumerate in advance.
    # LabelEncoder derives its mapping from whatever's actually present.
    df = pd.DataFrame({"protocol_type": ["tcp", "sctp", "quic"], "service": ["x"] * 3, "flag": ["y"] * 3})
    encoded = encode_categoricals(df)
    assert len(encoded) == 3


def test_find_correlated_columns_drops_one_of_a_perfectly_correlated_pair():
    df = pd.DataFrame({"a": [1, 2, 3, 4, 5], "b": [2, 4, 6, 8, 10], "c": [5, 3, 1, 9, 2]})
    dropped = find_correlated_columns(df, threshold=0.95)
    assert dropped == ["b"]  # b = 2*a, perfectly correlated; c is unrelated


def test_find_correlated_columns_keeps_uncorrelated_features():
    df = pd.DataFrame({"a": [1, 2, 3, 4, 5], "c": [5, 3, 1, 9, 2]})
    assert find_correlated_columns(df, threshold=0.95) == []


def test_find_correlated_columns_respects_threshold():
    df = pd.DataFrame({"a": [1, 2, 3, 4, 5], "b": [1, 2, 3, 4, 6]})  # highly but not perfectly correlated
    assert find_correlated_columns(df, threshold=0.999) == []
    assert find_correlated_columns(df, threshold=0.9) == ["b"]


def test_prepare_features_returns_feature_matrix_target_and_dropped_list():
    df = pd.DataFrame(
        {
            "protocol_type": ["tcp", "udp", "tcp", "icmp"],
            "service": ["http", "dns", "http", "ecr_i"],
            "flag": ["SF", "S0", "SF", "REJ"],
            "duration": [1, 2, 3, 4],
            "duration_copy": [1, 2, 3, 4],  # perfectly correlated with duration
            "attack_type": ["normal", "dos", "normal", "probe"],
        }
    )
    X, y, dropped = prepare_features(df, correlation_threshold=0.95)
    assert "attack_type" not in X.columns
    assert "duration_copy" in dropped
    assert list(y) == ["normal", "dos", "normal", "probe"]
