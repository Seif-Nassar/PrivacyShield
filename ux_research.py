#!/usr/bin/env python3
"""
PrivacyShield v3 — Metadata Analyzer
Security and Privacy Module | Project 13

Standalone module for detecting Personally Identifying Information (PII)
in message text before encryption. Can be used as a CLI tool or imported
as a library into other Python scripts.

UX Research Context:
    This module was designed in response to usability study finding that
    users did not consider metadata risk before encrypting. The tool forces
    awareness of PII exposure at the point of composition, not after the fact.

Usage:
    python3 metadata_analyzer.py -f message.txt --redact -o clean.txt
    python3 metadata_analyzer.py -t "Call me on 07700900123"
    python3 metadata_analyzer.py --json -f message.txt
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict


# ─────────────────────────────────────────────
# COLOUR OUTPUT
# ─────────────────────────────────────────────

class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ─────────────────────────────────────────────
# PII PATTERN DEFINITIONS
# ─────────────────────────────────────────────

@dataclass
class PIIPattern:
    """
    Represents a single PII detection pattern with metadata for the
    usability-oriented risk report.
    """
    name:       str
    pattern:    str
    risk:       str   # HIGH / MEDIUM / LOW
    advice:     str
    flags:      int = re.IGNORECASE

    def compile(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)


PII_PATTERNS: List[PIIPattern] = [

    PIIPattern(
        name    = "Email address",
        pattern = r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b",
        risk    = "HIGH",
        advice  = "Remove or replace with a pseudonym agreed in advance. "
                  "Email addresses are tied to real identities and are directly "
                  "searchable in public records."
    ),

    PIIPattern(
        name    = "Phone number",
        pattern = r"(\+?\d[\d\s\-(). ]{6,}\d)",
        risk    = "HIGH",
        advice  = "Replace with an agreed code word or use a Signal number. "
                  "Phone numbers are tied to SIM card registrations and often to "
                  "national identity documents."
    ),

    PIIPattern(
        name    = "IPv4 address",
        pattern = r"\b(\d{1,3}\.){3}\d{1,3}\b",
        risk    = "HIGH",
        advice  = "Remove IP addresses. They reveal your network provider and "
                  "geographic location and can be subpoenaed from your ISP."
    ),

    PIIPattern(
        name    = "Street address",
        pattern = r"\b\d+\s+[A-Z][a-z]+\s+(Street|St|Road|Rd|Avenue|Ave|"
                  r"Lane|Ln|Drive|Dr|Boulevard|Blvd|Close|Court|Ct|Place|Pl)\b",
        risk    = "HIGH",
        advice  = "Physical addresses are strong location identifiers. "
                  "Use a code name for a location instead."
    ),

    PIIPattern(
        name    = "UK Postcode",
        pattern = r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s*\d[A-Z]{2}\b",
        risk    = "HIGH",
        advice  = "UK postcodes narrow your location to fewer than 100 addresses. "
                  "Remove or generalise to a broader area."
    ),

    PIIPattern(
        name    = "US ZIP code",
        pattern = r"\b\d{5}(-\d{4})?\b",
        risk    = "HIGH",
        advice  = "US ZIP codes identify a specific geographic delivery area. "
                  "Remove from sensitive messages."
    ),

    PIIPattern(
        name    = "Credit card number",
        pattern = r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        risk    = "HIGH",
        advice  = "Never include card numbers in any message, encrypted or not. "
                  "This is a critical financial identifier."
    ),

    PIIPattern(
        name    = "Passport / document number",
        pattern = r"\b[A-Z]{1,2}\d{7,9}\b",
        risk    = "HIGH",
        advice  = "Document numbers are unique national identifiers. "
                  "Remove entirely from digital messages."
    ),

    PIIPattern(
        name    = "National Insurance / SSN pattern",
        pattern = r"\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-Z]\b"
                  r"|\b\d{3}-\d{2}-\d{4}\b",
        risk    = "HIGH",
        advice  = "National insurance and social security numbers are "
                  "primary government identifiers. Never include in messages."
    ),

    PIIPattern(
        name    = "Full name pattern",
        pattern = r"\b([A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20})\b",
        risk    = "MEDIUM",
        advice  = "Full names in messages link content to a real identity. "
                  "Replace with agreed pseudonyms or code names.",
        flags   = 0   # Case-sensitive so we only catch Title Case names
    ),

    PIIPattern(
        name    = "URL with potential tracking",
        pattern = r"https?://[^\s]+|www\.[^\s]+",
        risk    = "MEDIUM",
        advice  = "URLs may contain tracking tokens (utm_source, fbclid, etc.) "
                  "or reveal browsing context. Strip tracking parameters "
                  "or use a URL shortener before including links."
    ),

    PIIPattern(
        name    = "Date of birth pattern",
        pattern = r"\b(0?[1-9]|[12]\d|3[01])[/\-](0?[1-9]|1[012])[/\-]"
                  r"(19|20)\d{2}\b",
        risk    = "MEDIUM",
        advice  = "Dates of birth in combination with other data are a "
                  "strong identity signal. Avoid including in messages."
    ),

    PIIPattern(
        name    = "Specific calendar date",
        pattern = r"\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        risk    = "LOW",
        advice  = "Specific dates can be correlated with known public events "
                  "to narrow authorship within a population. Use relative "
                  "references (next Thursday) when possible."
    ),

    PIIPattern(
        name    = "Vehicle registration (UK)",
        pattern = r"\b[A-Z]{2}\d{2}\s?[A-Z]{3}\b",
        risk    = "MEDIUM",
        advice  = "UK vehicle registrations are publicly searchable and "
                  "tied to a registered keeper."
    ),
]


# ─────────────────────────────────────────────
# ANALYSIS ENGINE
# ─────────────────────────────────────────────

@dataclass
class Finding:
    name:    str
    risk:    str
    matches: List[str]
    advice:  str
    count:   int


@dataclass
class AnalysisResult:
    original:    str
    redacted:    str
    findings:    List[Finding] = field(default_factory=list)
    high_count:  int = 0
    med_count:   int = 0
    low_count:   int = 0
    is_clean:    bool = True

    def to_dict(self) -> dict:
        return {
            "is_clean":   self.is_clean,
            "high_count": self.high_count,
            "med_count":  self.med_count,
            "low_count":  self.low_count,
            "findings":   [asdict(f) for f in self.findings],
            "redacted":   self.redacted,
        }


def analyse(text: str) -> AnalysisResult:
    """
    Run all PII patterns against the input text.
    Returns an AnalysisResult with findings and a redacted copy.

    UX Design note:
        Results are sorted HIGH -> MEDIUM -> LOW to present the
        most critical issues first, matching the priority order
        used in the usability study task scenarios.
    """
    redacted  = text
    findings  = []
    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

    for pat in PII_PATTERNS:
        compiled = pat.compile()
        raw_matches = compiled.findall(text)

        if not raw_matches:
            continue

        # Flatten tuple groups if the regex has capture groups
        flat = []
        for m in raw_matches:
            if isinstance(m, tuple):
                flat.append(m[0])
            else:
                flat.append(m)

        # Deduplicate while preserving order
        seen, unique = set(), []
        for m in flat:
            if m not in seen:
                seen.add(m)
                unique.append(m)

        findings.append(Finding(
            name    = pat.name,
            risk    = pat.risk,
            matches = unique,
            advice  = pat.advice,
            count   = len(flat),
        ))

        # Replace all matches in the redacted copy
        redacted = compiled.sub("[REDACTED]", redacted)

    findings.sort(key=lambda f: risk_order.get(f.risk, 3))

    result = AnalysisResult(
        original   = text,
        redacted   = redacted,
        findings   = findings,
        high_count = sum(1 for f in findings if f.risk == "HIGH"),
        med_count  = sum(1 for f in findings if f.risk == "MEDIUM"),
        low_count  = sum(1 for f in findings if f.risk == "LOW"),
        is_clean   = len(findings) == 0
    )
    return result


# ─────────────────────────────────────────────
# REPORT RENDERING
# ─────────────────────────────────────────────

def print_report(result: AnalysisResult, show_redacted: bool = False):
    """Print a human-readable risk report to stdout."""

    if result.is_clean:
        print(f"\n{C.GREEN}[+]{C.RESET} No metadata risks detected. Message appears clean.\n")
        return

    total = result.high_count + result.med_count + result.low_count
    print(f"\n{C.YELLOW}[!]{C.RESET} Found {C.BOLD}{total} risk type(s){C.RESET}: "
          f"{C.RED}{result.high_count} HIGH{C.RESET}  "
          f"{C.YELLOW}{result.med_count} MEDIUM{C.RESET}  "
          f"{C.GREEN}{result.low_count} LOW{C.RESET}\n")

    for f in result.findings:
        if f.risk == "HIGH":
            rc = C.RED
        elif f.risk == "MEDIUM":
            rc = C.YELLOW
        else:
            rc = C.GREEN

        sample = ", ".join(f'"{m}"' for m in f.matches[:3])
        if len(f.matches) > 3:
            sample += f"  ...+{len(f.matches) - 3} more"

        print(f"  {rc}[{f.risk:<6}]{C.RESET}  {C.BOLD}{f.name:<30}{C.RESET}")
        print(f"           Found: {C.DIM}{sample}{C.RESET}")
        print(f"           Advice: {f.advice}")
        print()

    if show_redacted:
        print(f"{C.CYAN}Redacted version:{C.RESET}")
        print(f"{C.DIM}{result.redacted}{C.RESET}\n")


# ─────────────────────────────────────────────
# UX RESEARCH: USABILITY METRICS LOGGER
# ─────────────────────────────────────────────

class UsabilityLogger:
    """
    Lightweight event logger for recording usability study observations.

    UX Research Methodology: Think-Aloud Protocol
        During the usability study, evaluators used this class to log
        task completions, error events, and help requests in real time.
        The log was exported as JSON and analysed post-session to
        compute task success rates, error rates, and time-on-task.
    """

    def __init__(self, participant_id: str, task_id: str):
        self.participant_id = participant_id
        self.task_id        = task_id
        self.events: List[dict] = []

    def log(self, event_type: str, detail: str = ""):
        import time
        self.events.append({
            "participant": self.participant_id,
            "task":        self.task_id,
            "event":       event_type,
            "detail":      detail,
            "timestamp":   time.time(),
        })

    def task_start(self):
        self.log("TASK_START")

    def task_success(self):
        self.log("TASK_SUCCESS")

    def task_failure(self, reason: str = ""):
        self.log("TASK_FAILURE", reason)

    def error(self, description: str):
        self.log("ERROR", description)

    def help_request(self, context: str = ""):
        self.log("HELP_REQUEST", context)

    def export_json(self, path: str):
        with open(path, "w") as f:
            json.dump(self.events, f, indent=2)

    def summary(self) -> dict:
        return {
            "participant":      self.participant_id,
            "task":             self.task_id,
            "total_events":     len(self.events),
            "errors":           sum(1 for e in self.events if e["event"] == "ERROR"),
            "help_requests":    sum(1 for e in self.events if e["event"] == "HELP_REQUEST"),
            "task_succeeded":   any(e["event"] == "TASK_SUCCESS" for e in self.events),
        }


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="metadata_analyzer",
        description="PrivacyShield — Metadata PII Analyzer (Project 13)"
    )
    p.add_argument("-t", "--text",        help="Text string to analyse")
    p.add_argument("-f", "--file",        help="File to analyse")
    p.add_argument("-r", "--redact",      action="store_true",
                   help="Print redacted version of the text")
    p.add_argument("-o", "--output",      help="Save redacted text to this file")
    p.add_argument("--json",              action="store_true",
                   help="Output results as JSON (for integration)")
    p.add_argument("--strict",           action="store_true",
                   help="Exit with code 1 if ANY findings are detected")
    p.add_argument("--high-only",        action="store_true",
                   help="Only report HIGH-risk findings")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        print("  Paste your message (Ctrl+D when done):")
        text = sys.stdin.read()

    result = analyse(text)

    if args.high_only:
        result.findings = [f for f in result.findings if f.risk == "HIGH"]
        result.is_clean = len(result.findings) == 0

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_report(result, show_redacted=args.redact)

    if args.output and not result.is_clean:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result.redacted)
        print(f"{C.GREEN}[+]{C.RESET} Redacted version saved to: {args.output}")

    if args.strict and not result.is_clean:
        sys.exit(1)


if __name__ == "__main__":
    main()
