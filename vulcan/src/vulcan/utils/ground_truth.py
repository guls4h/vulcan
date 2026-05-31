import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)


@dataclass
class GroundTruthEntry:
    timestamp: str
    endpoint: str
    method: str
    user_session: int
    target_id: int
    is_vulnerable: bool
    vulnerability_type: str
    status_code: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> 'GroundTruthEntry':
        return cls(**data)


@dataclass
class AnalysisResult:
    vulnerability_found: bool
    vulnerability_type: Optional[str] = None
    confidence_score: int = 0
    reasoning: str = ""


class GroundTruthValidator:
    def __init__(self, ground_truth_file: str) -> None:
        self.ground_truth_file = Path(ground_truth_file)
        self.entries: List[GroundTruthEntry] = []
        self._load_ground_truth()

    def _load_ground_truth(self) -> None:
        if not self.ground_truth_file.exists():
            logger.warning(f"Ground truth file not found: {self.ground_truth_file}")
            return
        try:
            with open(self.ground_truth_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        self.entries.append(GroundTruthEntry.from_dict(json.loads(line)))
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"Failed to parse ground truth line: {e}")
            logger.info(f"Loaded {len(self.entries)} ground truth entries")
        except Exception as e:
            logger.error(f"Error loading ground truth: {e}")

    def find_matching_entries(
        self,
        endpoint: str,
        method: str,
        session_user_id: Optional[int] = None,
    ) -> List[GroundTruthEntry]:
        matches = []
        for entry in self.entries:
            if entry.endpoint == endpoint and entry.method == method:
                if session_user_id is None or entry.user_session == session_user_id:
                    matches.append(entry)
        return matches

    def validate(
        self,
        endpoint: str,
        method: str,
        scan_result: AnalysisResult,
        session_user_id: Optional[int] = None,
        target_id: Optional[int] = None,
    ) -> Tuple[bool, bool, bool]:
        matches = self.find_matching_entries(endpoint, method, session_user_id)

        if not matches:
            logger.warning(f"No ground truth entry found for {method} {endpoint}")
            return (False, False, False)

        is_actual = any(e.is_vulnerable for e in matches)
        detected = scan_result.vulnerability_found

        if detected and is_actual:
            return (True, False, False)
        if detected and not is_actual:
            return (False, True, False)
        if not detected and not is_actual:
            return (False, False, True)
        return (False, False, False)

    def add_entry(self, entry: GroundTruthEntry) -> None:
        self.entries.append(entry)
        self.ground_truth_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ground_truth_file, 'a') as f:
            f.write(entry.to_json() + '\n')


class AccuracyMetrics:
    @staticmethod
    def calculate(
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        true_negatives: int,
    ) -> dict[str, float]:
        total_positives = true_positives + false_positives
        total_actual_positives = true_positives + false_negatives
        total_samples = true_positives + false_positives + false_negatives + true_negatives

        precision = true_positives / total_positives if total_positives > 0 else 0.0
        recall = true_positives / total_actual_positives if total_actual_positives > 0 else 0.0
        f1_score = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        accuracy = (true_positives + true_negatives) / total_samples if total_samples > 0 else 0.0

        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'true_negatives': true_negatives,
            'total_samples': total_samples,
        }

    @staticmethod
    def format_metrics(metrics: dict[str, float]) -> str:
        return (
            "\nAccuracy Metrics:\n"
            f"  Precision:      {metrics['precision']:.1%}  (TP / (TP + FP))\n"
            f"  Recall:         {metrics['recall']:.1%}    (TP / (TP + FN))\n"
            f"  F1-Score:       {metrics['f1_score']:.3f}     (Harmonic mean)\n"
            f"  Accuracy:       {metrics['accuracy']:.1%}  ((TP + TN) / Total)\n\n"
            "Confusion Matrix:\n"
            f"  True Positive:   {metrics['true_positives']}\n"
            f"  False Positive:  {metrics['false_positives']}\n"
            f"  False Negative:  {metrics['false_negatives']}\n"
            f"  True Negative:   {metrics['true_negatives']}\n\n"
            f"Total Samples: {metrics['total_samples']}\n"
        )
