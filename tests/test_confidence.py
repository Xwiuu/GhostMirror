from __future__ import annotations

import pytest

from ghostmirror.modules.zero_day.confidence_engine import ConfidenceEngine


class TestConfidenceEngine:
    def test_init(self):
        engine = ConfidenceEngine()
        assert engine is not None

    def test_evaluate_from_signals_empty(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_from_signals([]) == "LOW"

    def test_evaluate_from_signals_low(self):
        engine = ConfidenceEngine()
        signals = [
            {"signal_type": "size_inconsistency", "source": "test"},
        ]
        assert engine.evaluate_from_signals(signals) == "LOW"

    def test_evaluate_from_signals_medium(self):
        engine = ConfidenceEngine()
        signals = [
            {"signal_type": "rare_endpoint", "source": "test"},
            {"signal_type": "rare_header", "source": "test"},
        ]
        assert engine.evaluate_from_signals(signals) == "MEDIUM"

    def test_evaluate_from_signals_high(self):
        engine = ConfidenceEngine()
        signals = [
            {"signal_type": "feature_flag", "source": "js_intel"},
            {"signal_type": "debug_route", "source": "endpoint_analysis"},
            {"signal_type": "sensitive_header", "source": "web"},
        ]
        assert engine.evaluate_from_signals(signals) == "HIGH"

    def test_evaluate_from_signals_very_high(self):
        engine = ConfidenceEngine()
        signals = [
            {"signal_type": "feature_flag", "source": "js_intel"},
            {"signal_type": "debug_route", "source": "endpoint_analysis"},
            {"signal_type": "sourcemap_exposed", "source": "sourcemap"},
            {"signal_type": "sensitive_header", "source": "web"},
            {"signal_type": "rare_endpoint", "source": "web"},
        ]
        assert engine.evaluate_from_signals(signals) == "VERY_HIGH"

    def test_evaluate_from_hypothesis_data_empty(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_from_hypothesis_data([], [], []) == "LOW"

    def test_evaluate_from_hypothesis_data_medium(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_from_hypothesis_data(
            [{"severity": "HIGH"}],
            [],
            [{"priority": "MEDIUM"}],
        ) == "MEDIUM"

    def test_evaluate_from_hypothesis_data_high(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_from_hypothesis_data(
            [{"severity": "HIGH"}, {"severity": "MEDIUM"}],
            [{"severity": "HIGH"}],
            [{"priority": "HIGH"}],
        ) == "HIGH"

    def test_evaluate_from_hypothesis_data_very_high(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_from_hypothesis_data(
            [{"severity": "CRITICAL"}, {"severity": "HIGH"}],
            [{"severity": "CRITICAL"}, {"severity": "HIGH"}],
            [{"priority": "CRITICAL"}, {"priority": "HIGH"}],
        ) == "VERY_HIGH"

    def test_evaluate_correlation_low(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_correlation(["size_inconsistency"], 1.0) == "LOW"

    def test_evaluate_correlation_medium(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_correlation(["rare_endpoint", "rare_header"], 1.0) == "MEDIUM"

    def test_evaluate_correlation_high(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_correlation(
            ["feature_flag", "debug_route", "sourcemap_exposed"], 1.0
        ) == "HIGH"

    def test_evaluate_correlation_very_high(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_correlation(
            ["feature_flag", "debug_route", "sourcemap_exposed", "sensitive_header", "rare_endpoint"], 1.0
        ) == "VERY_HIGH"

    def test_evaluate_correlation_weak(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_correlation(
            ["rare_endpoint", "debug_route"], 0.5
        ) == "LOW"

    def test_signal_quality_mapping(self):
        from ghostmirror.modules.zero_day.confidence_engine import SIGNAL_QUALITY_MAP
        assert SIGNAL_QUALITY_MAP["feature_flag"] == 40
        assert SIGNAL_QUALITY_MAP["sourcemap_exposed"] == 45
        assert SIGNAL_QUALITY_MAP["rare_header"] == 20
        assert SIGNAL_QUALITY_MAP["size_inconsistency"] == 15

    def test_evaluate_from_hypothesis_data_low_anomaly(self):
        engine = ConfidenceEngine()
        result = engine.evaluate_from_hypothesis_data(
            [{"severity": "LOW"}],
            [{"severity": "LOW"}],
            [{"priority": "LOW"}],
        )
        assert result in ("LOW", "MEDIUM")

    def test_evaluate_from_hypothesis_data_medium_attack_chain(self):
        engine = ConfidenceEngine()
        result = engine.evaluate_from_hypothesis_data(
            [{"severity": "MEDIUM"}],
            [{"severity": "MEDIUM"}],
            [],
        )
        assert result == "MEDIUM"

    def test_evaluate_from_hypothesis_data_low_priority(self):
        engine = ConfidenceEngine()
        result = engine.evaluate_from_hypothesis_data(
            [{"severity": "LOW"}, {"severity": "LOW"}],
            [{"severity": "LOW"}],
            [{"priority": "LOW"}],
        )
        assert result in ("LOW", "MEDIUM")

    def test_evaluate_correlation_low_strength(self):
        engine = ConfidenceEngine()
        assert engine.evaluate_correlation(["rare_endpoint", "debug_route"], 0.3) == "LOW"
