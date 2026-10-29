"""Standard SARIF 2.1.0 exporter for CI/CD and GitHub Security integration."""

import json
from pathlib import Path
from typing import Any
from scannex.db.models import Finding, Severity


class SarifExporter:
    """Exports ScanneX findings to standard SARIF 2.1.0 JSON format."""

    @classmethod
    def export(cls, findings: list[Finding], output_path: Path | str) -> str:
        """Serialize findings into SARIF 2.1.0 and write to disk."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        sarif_data = cls.generate_sarif_dict(findings)
        json_content = json.dumps(sarif_data, indent=2)
        out.write_text(json_content, encoding="utf-8")
        return json_content

    @classmethod
    def generate_sarif_dict(cls, findings: list[Finding]) -> dict[str, Any]:
        """Build the in-memory SARIF JSON structure."""
        rules = []
        results = []
        rule_ids = set()

        for f in findings:
            rule_id = f"SCANNEX-{f.vuln_type}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.vuln_type,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {
                        "level": cls._map_level(f.severity),
                    },
                    "properties": {
                        "cwe": f.cwe,
                    "mitigation": f.mitigation,
                        "tags": ["security", f.vuln_type.lower()],
                    },
                })

            level = cls._map_level(f.severity)

            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"[{f.status.value.upper()}] {f.title}: {f.description}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path.replace("\\", "/"),
                            },
                            "region": {
                                "startLine": f.line_number,
                            },
                        }
                    }
                ],
                "properties": {
                    "status": f.status.value,
                    "source": f.source,
                    "cwe": f.cwe,
                    "mitigation": f.mitigation,
                    "evidence_trace": f.evidence_trace,
                },
            }

            if f.patch_spec and f.patch_spec.unified_diff:
                result["fixes"] = [
                    {
                        "description": {"text": f.patch_spec.explanation or "Automated ScanneX patch"},
                        "artifactChanges": [
                            {
                                "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                                "replacements": [
                                    {
                                        "deletedRegion": {"startLine": f.line_number},
                                        "insertedContent": {"text": f.patch_spec.replace_block},
                                    }
                                ],
                            }
                        ],
                    }
                ]

            results.append(result)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ScanneX",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/team-gravitas/scannex",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    @staticmethod
    def _map_level(severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        elif severity == Severity.MEDIUM:
            return "warning"
        return "note"
