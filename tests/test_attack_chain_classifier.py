from __future__ import annotations

from ghostmirror.modules.attack_chain.chain_classifier import ChainClassifier


class TestChainClassifier:
    def test_classify_critical(self):
        c = ChainClassifier()
        assert c.classify(85, 0.9) == "critical"

    def test_classify_high(self):
        c = ChainClassifier()
        assert c.classify(70, 0.8) == "high"

    def test_classify_medium(self):
        c = ChainClassifier()
        assert c.classify(50, 0.6) == "medium"

    def test_classify_low(self):
        c = ChainClassifier()
        assert c.classify(20, 0.3) == "low"

    def test_get_priority_label_critical(self):
        c = ChainClassifier()
        assert "Immediate" in c.get_priority_label("critical")

    def test_get_priority_label_high(self):
        c = ChainClassifier()
        assert "High" in c.get_priority_label("high")

    def test_get_priority_label_medium(self):
        c = ChainClassifier()
        assert "Standard" in c.get_priority_label("medium")

    def test_get_priority_label_low(self):
        c = ChainClassifier()
        assert "Informational" in c.get_priority_label("low")

    def test_get_priority_label_unknown(self):
        c = ChainClassifier()
        assert c.get_priority_label("unknown") == "Unknown"
