"""
Isolation Forest-based Anomaly Detection for Cybersecurity
Enhanced with dynamic thresholding and SIEM integration
"""

import json
import logging
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
from typing import Union, Dict, List
from datetime import datetime
from dotenv import load_dotenv
import warnings

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Suppress sklearn warnings
warnings.filterwarnings("ignore", category=UserWarning)

class CyberAnomalyDetector:
    """Enhanced Isolation Forest implementation for network anomaly detection"""
    
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.pipeline = Pipeline([
            ('scaler', RobustScaler()),
            ('detector', IsolationForest(
                n_estimators=150,
                max_samples='auto',
                contamination=contamination,
                random_state=random_state,
                behaviour='new',
                n_jobs=-1
            ))
        ])
        self.feature_names = []
        self.trained_at = None
        self.metadata = {
            "version": "1.2.0",
            "threshold": None,
            "data_stats": {}
        }

    def _preprocess_data(self, X: pd.DataFrame) -> pd.DataFrame:
        """Preprocess network traffic data with cybersecurity-specific features"""
        # Feature engineering
        X = X.assign(
            bytes_per_second=lambda x: x['tx_bytes'] / x['duration'],
            packet_size_var=lambda x: x[['tx_packets', 'rx_packets']].var(axis=1),
            protocol_entropy=lambda x: x['protocol'].apply(self._calculate_entropy)
        )
        
        # Select final features
      # Select final features
# ---------------------
# Automated feature selection based on variance threshold
from sklearn.feature_selection import VarianceThreshold

# Create initial feature set including engineered features
potential_features = [
    'duration', 'tx_bytes', 'rx_bytes', 
    'bytes_per_second', 'packet_size_var',
    'protocol_entropy', 'tls_ratio', 'dns_query_freq'
]

# Filter low-variance features (threshold=0.01 for cybersecurity metrics)
selector = VarianceThreshold(threshold=0.01)
X_filtered = selector.fit_transform(X[potential_features])

# Get selected feature names
selected_indices = selector.get_support(indices=True)
self.feature_names = [potential_features[i] for i in selected_indices]

# Ensure minimum required features are present
required_core_features = {'bytes_per_second', 'protocol_entropy'}
if not required_core_features.issubset(self.feature_names):
    logger.warning("Missing core features in selection, using fallback")
    self.feature_names = list(required_core_features.union(
        set(self.feature_names)
    ))

# Final feature validation
if len(self.feature_names) < 3:
    raise ValueError("Insufficient features selected for reliable detection")

# Create final feature set
X = X[self.feature_names]

# Track feature selection metrics
self.metadata.update({
    'feature_selection': {
        'initial_candidates': potential_features,
        'selected_features': self.feature_names,
        'variance_threshold': 0.01,
        'removed_features': list(set(potential_features) - set(self.feature_names))
    }
})
