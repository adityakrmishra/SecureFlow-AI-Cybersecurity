"""
Network Flow Classification using Machine Learning
"""

import joblib
import numpy as np
import pandas as pd
from typing import Dict, List
from sklearn.ensemble import RandomForestClassifier

class FlowClassifier:
    """Classify network flows as normal/suspicious/malicious"""
    
    def __init__(self, model_path: str = "models/flow_classifier.pkl"):
        self.model = joblib.load(model_path)
        self.features = [
            'duration', 'proto', 'src_bytes', 'dst_bytes',
            'packets', 'bytes_per_sec', 'dst_host_srv_count'
        ]

    def classify_flow(self, flow_data: Dict) -> Dict:
        """Classify single network flow"""
        try:
            X = self._preprocess(flow_data)
            prediction = self.model.predict(X)
            probabilities = self.model.predict_proba(X)
            
            return {
                'verdict': prediction[0],
                'confidence': np.max(probabilities[0]),
                'features': flow_data
            }
        except Exception as e:
            raise RuntimeError(f"Classification failed: {str(e)}")

    def batch_classify(self, flows: List[Dict]) -> List[Dict]:
        """Classify multiple flows"""
        df = pd.DataFrame(flows)
        X = self._preprocess(df)
        predictions = self.model.predict(X)
        return [
            {"flow": flow, "verdict": verdict}
            for flow, verdict in zip(flows, predictions)
        ]

    def _preprocess(self, data: Union[Dict, pd.DataFrame]) -> np.ndarray:
        """Preprocess flow features"""
        df = pd.DataFrame([data]) if isinstance(data, dict) else data
        return df[self.features].values

    def get_feature_importance(self) -> Dict:
        """Get model feature importance"""
        return dict(zip(self.features, self.model.feature_importances_))

if __name__ == "__main__":
    classifier = FlowClassifier()
    sample_flow = {
        'duration': 12.5,
        'proto': 6,
        'src_bytes': 1500,
        'dst_bytes': 800,
        'packets': 10,
        'bytes_per_sec': 120.4,
        'dst_host_srv_count': 3
    }
    result = classifier.classify_flow(sample_flow)
    print(f"Flow classification: {result}")
