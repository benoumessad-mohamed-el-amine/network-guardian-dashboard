from __future__ import annotations

from typing import Iterable, Iterator

from .extractor import extract_packet_features
from .model_base import BaseModel, InferenceResult
from .signatures import SignatureEngine


class InferenceEngine:
    """Core component that wires feature extraction to ML inference."""

    def __init__(self, model: BaseModel) -> None:
        self.model = model
        self.signature_engine = SignatureEngine()

    def analyze_packet(self, packet: dict) -> InferenceResult:
        features = extract_packet_features(packet)
        
        # 1. Check if packet matches any signature or whitelist rule
        signature_label = self.signature_engine.check_packet(features)
        if signature_label is not None:
            # High-confidence signature detection (score=1.0)
            return InferenceResult(label=signature_label, score=1.0, features=features)
            
        # 2. Fall back to ML inference
        return self.model.predict(features)

    def analyze_stream(self, packets: Iterable[dict]) -> Iterator[InferenceResult]:
        for packet in packets:
            yield self.analyze_packet(packet)

