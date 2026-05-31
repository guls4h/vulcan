import json
import re
from typing import Any

from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)


class JSONRepair:
    REQUIRED_FIELDS = {'vulnerability_found', 'confidence_score'}

    @staticmethod
    def repair(broken_json: str, require_all_fields: bool = False) -> dict[str, Any]:
        try:
            return JSONRepair._validate_response(json.loads(broken_json))
        except json.JSONDecodeError:
            pass

        extracted = JSONRepair._stage1_markdown_extraction(broken_json)
        cleaned = JSONRepair._stage2_syntax_cleaning(extracted)
        completed = JSONRepair._stage3_bracket_completion(cleaned)

        for stage, content in (("syntax_cleaning", cleaned), ("bracket_completion", completed)):
            try:
                result = json.loads(content)
                logger.info(f"JSON repaired at stage {stage}")
                return JSONRepair._validate_response(result)
            except json.JSONDecodeError:
                continue

        logger.error("All repair stages failed, using fallback response")
        return JSONRepair._stage4_validation_fallback(broken_json)

    @staticmethod
    def _stage1_markdown_extraction(text: str) -> str:
        match = re.search(r'```json\s*\n?(.*?)\n?```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        match = re.search(r'```\s*\n?(.*?)\n?```', text, re.DOTALL)
        if match:
            return match.group(1).strip()
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            return match.group(0)
        return text

    @staticmethod
    def _stage2_syntax_cleaning(text: str) -> str:
        cleaned = text.strip()
        cleaned = re.sub(r',(\s*[}\]])', r'\1', cleaned)
        cleaned = re.sub(r'([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', cleaned)
        cleaned = re.sub(r'//.*$', '', cleaned, flags=re.MULTILINE)
        cleaned = re.sub(r'([}\]"])\s*\n\s*"', r'\1, "', cleaned)
        return cleaned

    @staticmethod
    def _stage3_bracket_completion(text: str) -> str:
        cleaned = text.strip()
        if not cleaned.startswith('{'):
            match = re.search(r'\{', cleaned)
            if match:
                cleaned = cleaned[match.start():]
        open_braces = cleaned.count('{') - cleaned.count('}')
        if open_braces > 0:
            cleaned += '}' * open_braces
        open_brackets = cleaned.count('[') - cleaned.count(']')
        if open_brackets > 0:
            cleaned += ']' * open_brackets
        return cleaned

    @staticmethod
    def _stage4_validation_fallback(original_text: str) -> dict[str, Any]:
        return {
            "vulnerability_found": False,
            "confidence_score": 0,
            "vulnerability_type": "PARSE_ERROR",
            "risk_level": "Low",
            "reasoning": "Failed to parse LLM response - repair pipeline exhausted",
            "proof_of_concept": "N/A",
            "remediation_suggestion": "Check LLM API configuration and try again",
            "raw_response_preview": original_text[:200],
        }

    @staticmethod
    def _validate_response(response: dict[str, Any]) -> dict[str, Any]:
        for field in JSONRepair.REQUIRED_FIELDS:
            if field not in response:
                response[field] = False if field == 'vulnerability_found' else 0

        if isinstance(response.get('confidence_score'), str):
            try:
                response['confidence_score'] = int(response['confidence_score'])
            except (ValueError, TypeError):
                response['confidence_score'] = 0

        if not isinstance(response.get('vulnerability_found'), bool):
            response['vulnerability_found'] = bool(response.get('vulnerability_found'))

        return response

    @staticmethod
    def extract_json_from_text(text: str) -> dict[str, Any]:
        return JSONRepair.repair(text)

    @staticmethod
    def validate_analysis_response(response: dict[str, Any]) -> bool:
        if not isinstance(response, dict):
            return False
        if 'vulnerability_found' not in response or 'confidence_score' not in response:
            return False
        try:
            score = int(response['confidence_score'])
            if not 0 <= score <= 100:
                return False
        except (ValueError, TypeError):
            return False
        return True
