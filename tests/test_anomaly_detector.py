import pytest

class TestAnomalyDetector:
    def test_agent_name(self, anomaly):
        assert anomaly.AGENT_NAME == "AnomalyDetector"
    
    def test_zscore_detector_init(self):
        from src.agents.anomaly_detector import ZScoreDetector
        det = ZScoreDetector(threshold=2.5)
        assert det.threshold == 2.5
    
    def test_zscore_fit(self):
        from src.agents.anomaly_detector import ZScoreDetector
        det = ZScoreDetector(threshold=2.5)
        det.fit([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        assert det.mean is not None
    
    def test_iqr_detector(self):
        from src.agents.anomaly_detector import IQRDetector
        det = IQRDetector(multiplier=1.5)
        det.fit([1, 2, 3, 4, 5, 6, 7, 8, 9, 100])
        anomalies = det.detect([1, 2, 3, 4, 5, 6, 7, 8, 9, 100])
        assert len(anomalies) >= 1
    
    def test_velocity_detector(self):
        from src.agents.anomaly_detector import VelocityDetector
        det = VelocityDetector()
        assert hasattr(det, "detect_velocity_anomalies")
        assert hasattr(det, "window_hours")
    
    def test_isolation_forest(self):
        from src.agents.anomaly_detector import IsolationForestSimple
        forest = IsolationForestSimple(n_trees=10)
        data = [[float(i), float(i*2)] for i in range(100)]
        forest.fit(data)
        assert forest.predict([50.0, 100.0]) in [True, False]
    
    def test_isolation_forest_detects_outlier(self):
        from src.agents.anomaly_detector import IsolationForestSimple
        forest = IsolationForestSimple(n_trees=50)
        normal = [[float(i), float(i)] for i in range(100)]
        forest.fit(normal)
        assert forest.predict([999.0, 999.0]) == True
