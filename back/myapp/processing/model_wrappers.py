from __future__ import annotations

import os
from typing import Any, Dict
import numpy as np

from .model_base import BaseModel, FeatureDict, InferenceResult
THRESHOLD_FILE = os.path.join(os.path.dirname(__file__), 'threshold.txt')

_cached_threshold = None

def get_anomaly_threshold() -> float:
    global _cached_threshold
    if _cached_threshold is not None:
        return _cached_threshold
    try:
        if os.path.exists(THRESHOLD_FILE):
            with open(THRESHOLD_FILE, 'r') as f:
                val = float(f.read().strip())
                if 0.0 <= val <= 1.0:
                    _cached_threshold = val
                    import logging
                    logging.getLogger(__name__).info(f"Loaded anomaly threshold {val:.4f} from file")
                    return val
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to read anomaly threshold: {e}")
        pass
    _cached_threshold = 0.85
    return 0.85

def set_anomaly_threshold(val: float) -> None:
    global _cached_threshold
    _cached_threshold = val
    try:
        with open(THRESHOLD_FILE, 'w') as f:
            f.write(f"{val:.4f}")
        import logging
        logging.getLogger(__name__).info(f"Anomaly threshold successfully updated to {val:.4f}")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to save anomaly threshold: {e}")
        pass

class MockModel(BaseModel):
    def __init__(self) -> None:
        self.loaded = False

    def load(self, model_path: str) -> None:
        self.loaded = True

    def predict(self, features: FeatureDict) -> InferenceResult:
        if not self.loaded:
            raise RuntimeError('Model must be loaded before inference')

        packet_size = float(features.get('packet_size', 0))
        has_syn = 'S' in str(features.get('tcp_flags', '')).upper()
        score = min(1.0, 0.2 + packet_size / 1500.0 * 0.6 + (0.2 if has_syn else 0.0))
        label = 'attack' if score >= 0.7 else 'normal'
        return InferenceResult(label=label, score=round(score, 4), features=features)

    def metadata(self) -> Dict[str, Any]:
        return {
            'name': 'MockModel',
            'framework': 'mock',
            'type': 'mock',
            'description': 'Development placeholder model',
        }


class RandomForestModel(BaseModel):
    """Base wrapper for all Scikit-Learn Random Forest classifiers."""

    def __init__(self, feature_order: list[str] | None = None) -> None:
        self.model = None
        self.loaded = False
        self.feature_order = feature_order or [
            'Flow Duration', 'Flow Bytes/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Total', 'Bwd IAT Total', 'Active Mean', 'Idle Mean',
            'Bwd Bulk Rate Avg', 'Fwd Bulk Rate Avg', 'Total TCP Flow Time',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Total Fwd Packet', 'Total Bwd packets',
            'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s',
            'Packet Length Mean', 'Packet Length Std',
            'Fwd URG Flags', 'Bwd URG Flags', 'ICMP Code', 'ICMP Type'
        ]

    def load(self, model_path: str) -> None:
        try:
            import joblib
        except ImportError as exc:
            raise ImportError('joblib is required to load RandomForest models') from exc

        if not os.path.exists(model_path):
            raise FileNotFoundError(f'Random Forest model file not found: {model_path}')

        self.model = joblib.load(model_path)
        self.loaded = True

    def predict(self, features: FeatureDict) -> InferenceResult:
        if not self.loaded or self.model is None:
            raise RuntimeError('Random Forest model is not loaded')

        vector = self._vectorize(features)
        prediction = int(self.model.predict(vector)[0])
        probabilities = self.model.predict_proba(vector)[0]
        score = float(probabilities[prediction])
        label = 'attack' if prediction == 1 else 'normal'
        return InferenceResult(label=label, score=score, features=features)

    def metadata(self) -> Dict[str, Any]:
        return {
            'name': 'RandomForestModel',
            'framework': 'scikit-learn',
            'type': 'sklearn_rf',
        }

    def _vectorize(self, features: FeatureDict) -> np.ndarray:
        values = [float(features.get(key, 0.0) or 0.0) for key in self.feature_order]
        return np.asarray([values], dtype=np.float32)


class BinaryAnomalyClassifierRF(RandomForestModel):
    def metadata(self) -> Dict[str, Any]:
        meta = super().metadata()
        meta.update({'name': 'BinaryAnomalyClassifierRF', 'role': 'tier_1_anomaly_detector'})
        return meta


class PortscanClassifierRF(RandomForestModel):
    def metadata(self) -> Dict[str, Any]:
        meta = super().metadata()
        meta.update({'name': 'PortscanClassifierRF', 'role': 'tier_2_portscan_detector'})
        return meta


class SynFloodClassifierRF(RandomForestModel):
    def metadata(self) -> Dict[str, Any]:
        meta = super().metadata()
        meta.update({'name': 'SynFloodClassifierRF', 'role': 'tier_2_synflood_detector'})
        return meta


class DDoSClassifierRF(RandomForestModel):
    def metadata(self) -> Dict[str, Any]:
        meta = super().metadata()
        meta.update({'name': 'DDoSClassifierRF', 'role': 'tier_2_ddos_detector'})
        return meta




class HierarchicalIDSClassifier(BaseModel):
    """Composite classifier implementing two-tier hierarchical classification."""

    def __init__(self, models_dir: str | None = None) -> None:
        self.scaler = None
        self.binary_model = None
        self.synflood_model = None
        self.ddos_model = None
        self.portscan_model = None
        self.loaded = False

        self.feature_columns = [
            'Flow Duration', 'Flow Bytes/s', 'Flow IAT Mean', 'Flow IAT Std',
            'Fwd IAT Total', 'Bwd IAT Total', 'Active Mean', 'Idle Mean',
            'Bwd Bulk Rate Avg', 'Fwd Bulk Rate Avg', 'Total TCP Flow Time',
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Total Fwd Packet', 'Total Bwd packets',
            'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s',
            'Packet Length Mean', 'Packet Length Std',
            'Fwd URG Flags', 'Bwd URG Flags', 'ICMP Code', 'ICMP Type'
        ]

        if models_dir:
            self.load(models_dir)

    def load(self, model_dir: str) -> None:
        try:
            import joblib
        except ImportError as exc:
            raise ImportError('joblib is required to load serialized model files') from exc

        scaler_path = os.path.join(model_dir, 'network_scaler.pkl')
        binary_path = os.path.join(model_dir, 'binary_anomaly_rf.pkl')
        synflood_path = os.path.join(model_dir, 'synflood_rf.pkl')
        ddos_path = os.path.join(model_dir, 'ddos_rf.pkl')
        portscan_path = os.path.join(model_dir, 'portscan_rf.pkl')

        # Load scaler
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler file not found: {scaler_path}")
        self.scaler = joblib.load(scaler_path)

        # Load Tier 1 binary model
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary anomaly detector not found: {binary_path}")
        self.binary_model = joblib.load(binary_path)

        # Load Tier 2 specialized models (gracefully fallback to None if missing)
        if os.path.exists(synflood_path):
            self.synflood_model = joblib.load(synflood_path)
        if os.path.exists(ddos_path):
            self.ddos_model = joblib.load(ddos_path)
        if os.path.exists(portscan_path):
            self.portscan_model = joblib.load(portscan_path)

        self.loaded = True

    def predict(self, features: FeatureDict) -> InferenceResult:
        if not self.loaded:
            raise RuntimeError('Hierarchical IDS Classifier must be loaded before predicting.')

        try:
            import pandas as pd
        except ImportError as exc:
            raise ImportError('pandas is required for feature vector formatting') from exc

        # 1. Represent features as a 1-row DataFrame matching training layout
        df = pd.DataFrame([features], columns=self.feature_columns)

        # 2. Preprocess features using the ColumnTransformer
        X_scaled = self.scaler.transform(df)

        # 3. Tier 1 classification: Get anomaly score (used for fallback gating)
        binary_probs = self.binary_model.predict_proba(X_scaled)[0]
        anomaly_score = float(binary_probs[1]) if len(binary_probs) > 1 else float(binary_probs[0])

        # 4. Tier 2: ALWAYS run all specialized classifiers regardless of Tier 1
        #    The specialist models are authoritative for their attack types.
        positives: Dict[str, float] = {}
        threshold = get_anomaly_threshold()

        if self.synflood_model is not None:
            pred = self.synflood_model.predict(X_scaled)[0]
            probs = self.synflood_model.predict_proba(X_scaled)[0]
            score = float(probs[1]) if len(probs) > 1 else float(probs[0])
            if pred == 1 and score >= threshold:
                positives['sync flood'] = score

        if self.ddos_model is not None:
            pred = self.ddos_model.predict(X_scaled)[0]
            probs = self.ddos_model.predict_proba(X_scaled)[0]
            score = float(probs[1]) if len(probs) > 1 else float(probs[0])
            if pred == 1 and score >= threshold:
                positives['ddos'] = score

        if self.portscan_model is not None:
            pred = self.portscan_model.predict(X_scaled)[0]
            probs = self.portscan_model.predict_proba(X_scaled)[0]
            score = float(probs[1]) if len(probs) > 1 else float(probs[0])
            if pred == 1 and score >= threshold:
                positives['portscan'] = score

        # 5. Decision logic:
        #    - If ANY Tier 2 specialist fires → classify as that attack (Tier 2 is authoritative)
        #    - If NO specialist fires AND Tier 1 anomaly is above threshold → "unknown anomaly"
        #    - Otherwise → normal
        if positives:
            best_label = max(positives, key=positives.get)
            best_score = positives[best_label]
            return InferenceResult(label=best_label, score=best_score, features=features)
        if anomaly_score >= threshold:
            # Tier 1 says anomalous but no specialist claimed it
            return InferenceResult(label='unknown', score=anomaly_score, features=features)

        # Both tiers agree: normal traffic
        return InferenceResult(label='normal', score=1.0 - anomaly_score, features=features)

    def metadata(self) -> Dict[str, Any]:
        return {
            'name': 'HierarchicalIDSClassifier',
            'type': 'hierarchical_rf_composite',
            'loaded_submodels': {
                'binary_anomaly': self.binary_model is not None,
                'synflood': self.synflood_model is not None,
                'ddos': self.ddos_model is not None,
                'portscan': self.portscan_model is not None,
            }
        }
