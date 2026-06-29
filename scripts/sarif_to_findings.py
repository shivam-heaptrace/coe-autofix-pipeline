#!/usr/bin/env python3
"""
sarif_to_findings.py
────────────────────
Collapses one or more SARIF files into a compact JSON payload that the
Claude autofix workflow can read without hitting token limits.

Usage:
    python3 scripts/sarif_to_findings.py \
        --input-dir security-artifacts/ \
        --output    findings.json

Output schema:
    {
      "total": <int>,
      "findings": [
        {
          "tool":      <str>,      # e.g. "trivy", "codeql", "gitleaks"
          "ruleId":    <str>,      # e.g. "CVE-2023-1234" or "js/sql-injection"
          "severity":  <str>,      # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
          "file":      <str>,      # path relative to repo root
          "startLine": <int|null>,
          "endLine":   <int|null>,
          "message":   <str>
        },
        ...
      ]
    }
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Severities we care about; anything below MEDIUM is skipped by default.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
MIN_SEVERITY  = "MEDIUM"


def sarif_severity(level: str | None) -> str:
    """Map SARIF notification level to our severity vocabulary."""
    mapping = {
        "error":   "HIGH",
        "warning": "MEDIUM",
        "note":    "LOW",
        "none":    "LOW",
    }
    return mapping.get((level or "").lower(), "UNKNOWN")


def extract_findings(sarif_path: Path, tool_name: str) -> list[dict]:
    findings = []

    with sarif_path.open() as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"[warn] Could not parse {sarif_path}; skipping.", file=sys.stderr)
            return findings

    for run in data.get("runs", []):
        # Build a ruleId → severity index from the run's rules table
        rules: dict[str, str] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid  = rule.get("id", "")
            # SARIF stores severity under defaultConfiguration.level
            lvl  = (
                rule.get("defaultConfiguration", {}).get("level")
                or rule.get("properties", {}).get("security-severity")
            )
            if isinstance(lvl, (int, float)):
                # numeric CVSS → bucket
                score = float(lvl)
                if score >= 9.0:
                    sev = "CRITICAL"
                elif score >= 7.0:
                    sev = "HIGH"
                elif score >= 4.0:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"
            else:
                sev = sarif_severity(lvl)
            rules[rid] = sev

        for result in run.get("results", []):
            rule_id  = result.get("ruleId", "unknown")
            level    = result.get("level")           # may override rule default
            severity = sarif_severity(level) if level else rules.get(rule_id, "UNKNOWN")

            if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(MIN_SEVERITY, 2):
                continue

            message = result.get("message", {}).get("text", "")

            # First physical location wins
            file_path  = None
            start_line = None
            end_line   = None
            locations  = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                art  = phys.get("artifactLocation", {})
                file_path = art.get("uri")
                region    = phys.get("region", {})
                start_line = region.get("startLine")
                end_line   = region.get("endLine")

            findings.append(
                {
                    "tool":      tool_name,
                    "ruleId":    rule_id,
                    "severity":  severity,
                    "file":      file_path or "",
                    "startLine": start_line,
                    "endLine":   end_line,
                    "message":   message,
                }
            )

    return findings


def infer_tool_name(filename: str) -> str:
    name = filename.lower()
    if "trivy"    in name: return "trivy"
    if "codeql"   in name: return "codeql"
    if "gitleaks" in name: return "gitleaks"
    if "sonar"    in name: return "sonarcloud"
    return Path(filename).stem


def collect_sarif_files(input_dir: Path) -> list[Path]:
    """Return SARIF files under input_dir, skipping artifact wrapper directories."""
    files: set[Path] = set()
    for path in input_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() == ".sarif":
            files.add(path)
        elif path.is_dir() and path.name.endswith(".sarif"):
            # dawidd6/action-download-artifact may create a folder named *.sarif
            for inner in path.rglob("*.sarif"):
                if inner.is_file():
                    files.add(inner)
    return sorted(files)


def main():
    global MIN_SEVERITY

    parser = argparse.ArgumentParser(description="Collapse SARIF files into findings.json")
    parser.add_argument("--input-dir", required=True, help="Directory containing *.sarif files")
    parser.add_argument("--output",    required=True, help="Output JSON path")
    parser.add_argument("--min-severity", default=MIN_SEVERITY,
                        choices=list(SEVERITY_RANK.keys()),
                        help="Minimum severity to include (default: MEDIUM)")
    args = parser.parse_args()

    MIN_SEVERITY = args.min_severity

    input_dir = Path(args.input_dir)
    if not input_dir.exists():
        print(f"[warn] Input directory {input_dir} does not exist; writing empty findings.", file=sys.stderr)
        result = {"total": 0, "findings": []}
    else:
        all_findings: list[dict] = []
        sarif_files = collect_sarif_files(input_dir)
        if not sarif_files:
            print(f"[warn] No .sarif files found in {input_dir}", file=sys.stderr)

        for sarif_file in sarif_files:
            tool = infer_tool_name(sarif_file.name)
            found = extract_findings(sarif_file, tool)
            print(f"  {sarif_file.relative_to(input_dir)}: {len(found)} findings ({tool})")
            all_findings.extend(found)

        # Sort: CRITICAL first, then HIGH, then by file for predictable diffs
        all_findings.sort(
            key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["file"] or "")
        )

        # Deduplicate: same tool + ruleId + file + startLine
        seen  = set()
        deduped = []
        for f in all_findings:
            key = (f["tool"], f["ruleId"], f["file"], f["startLine"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        result = {"total": len(deduped), "findings": deduped}

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as out:
        json.dump(result, out, indent=2)

    print(f"\nWrote {result['total']} finding(s) to {output_path}")


if __name__ == "__main__":
    main()
