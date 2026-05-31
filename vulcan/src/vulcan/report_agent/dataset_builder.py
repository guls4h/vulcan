from typing import Any
import json
from pathlib import Path

SFT_MIN_CONFIDENCE = 90


class DatasetBuilder:
    def __init__(self, vulnerability_log: str, min_confidence: int = SFT_MIN_CONFIDENCE) -> None:
        self.log_path = Path(vulnerability_log)
        self.min_confidence = min_confidence

    def build_training_dataset(self, output_path: str) -> dict[str, int]:
        if not self.log_path.exists():
            return {'total': 0, 'positive': 0, 'negative': 0, 'skipped_low_confidence': 0}

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        positive_count = 0
        total_count = 0
        skipped = 0

        with open(self.log_path, 'r') as infile, open(output, 'w') as outfile:
            for line in infile:
                if not line.strip():
                    continue

                try:
                    vuln = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not vuln.get('vulnerability_found'):
                    skipped += 1
                    continue
                if vuln.get('human_validated') is False:
                    skipped += 1
                    continue
                if int(vuln.get('confidence_score', 0)) < self.min_confidence and not vuln.get('human_validated'):
                    skipped += 1
                    continue

                training_example = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a security expert analyzing HTTP traffic for vulnerabilities."
                        },
                        {
                            "role": "user",
                            "content": f"Analyze: {vuln.get('method')} {vuln.get('url')}"
                        },
                        {
                            "role": "assistant",
                            "content": json.dumps({
                                "vulnerability_found": True,
                                "vulnerability_type": vuln.get('vulnerability_type', ''),
                                "confidence_score": vuln.get('confidence_score', 0),
                                "risk_level": vuln.get('risk_level', 'Low')
                            })
                        }
                    ]
                }

                outfile.write(json.dumps(training_example) + '\n')
                total_count += 1
                positive_count += 1

        return {
            'total': total_count,
            'positive': positive_count,
            'negative': total_count - positive_count,
            'skipped_low_confidence': skipped,
        }
    
    def get_statistics(self) -> dict[str, Any]:
        if not self.log_path.exists():
            return {}
        
        stats = {
            'total_vulnerabilities': 0,
            'by_type': {},
            'by_risk': {},
            'avg_confidence': 0
        }
        
        confidences = []
        
        with open(self.log_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                
                try:
                    vuln = json.loads(line)
                    stats['total_vulnerabilities'] += 1
                    
                    vuln_type = vuln.get('vulnerability_type', 'Unknown')
                    stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
                    
                    risk = vuln.get('risk_level', 'Unknown')
                    stats['by_risk'][risk] = stats['by_risk'].get(risk, 0) + 1
                    
                    if 'confidence_score' in vuln:
                        confidences.append(vuln['confidence_score'])
                
                except json.JSONDecodeError:
                    continue
        
        if confidences:
            stats['avg_confidence'] = sum(confidences) / len(confidences)
        
        return stats
