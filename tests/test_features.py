"""Smoke tests for the Feature seed data."""

from __future__ import annotations

from src.models.feature import INITIAL_FEATURES, Feature, clone_features


def test_initial_features_has_14_rows() -> None:
    assert len(INITIAL_FEATURES) == 14


def test_initial_features_ids_are_unique_and_sequential() -> None:
    ids = [f.id for f in INITIAL_FEATURES]
    assert ids == list(range(1, 15))


def test_clone_features_returns_independent_copy() -> None:
    a = clone_features()
    b = clone_features()
    a[0].status = "Disabled"
    assert b[0].status != "Disabled"


def test_locked_features_match_react_mock() -> None:
    locked = {f.id for f in INITIAL_FEATURES if f.locked}
    # Per the React prototype: VT-x, WMI, and Smart App Control are locked.
    assert locked == {1, 2, 13}


def test_feature_model_validation_rejects_missing_fields() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Feature(id=99, name="X")  # type: ignore[call-arg]
