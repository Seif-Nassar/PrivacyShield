#!/usr/bin/env python3
"""
PrivacyShield v3 — UX Research Toolkit
Security and Privacy Module | Project 13

Implements the UX research methodologies used in the usability evaluation:
  - System Usability Scale (SUS) scoring and analysis
  - Think-Aloud session logger
  - Task timing and success rate calculator
  - CSV export for statistical analysis
  - Participant anonymisation

Usage:
    python3 ux_research.py sus              # Enter SUS scores interactively
    python3 ux_research.py analyse          # Analyse all collected session logs
    python3 ux_research.py report           # Generate full study report
"""

import os
import csv
import json
import time
import argparse
import statistics
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ─────────────────────────────────────────────
# COLOUR OUTPUT
# ─────────────────────────────────────────────

class C:
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# ─────────────────────────────────────────────
# SYSTEM USABILITY SCALE (SUS)
# ─────────────────────────────────────────────

SUS_QUESTIONS = [
    "I think that I would like to use this tool frequently.",
    "I found the tool unnecessarily complex.",
    "I thought the tool was easy to use.",
    "I think that I would need the support of a technical person to use this tool.",
    "I found the various functions in this tool were well integrated.",
    "I thought there was too much inconsistency in this tool.",
    "I would imagine that most people would learn to use this tool very quickly.",
    "I found the tool very cumbersome to use.",
    "I felt very confident using the tool.",
    "I needed to learn a lot of things before I could get going with this tool.",
]

SUS_SCALE = "1 = Strongly Disagree   5 = Strongly Agree"

SUS_ADJECTIVE_MAP = [
    (85.0, "Excellent",   C.GREEN),
    (72.6, "Good",        C.GREEN),
    (52.0, "OK",          C.YELLOW),
    (38.0, "Poor",        C.YELLOW),
    (0.0,  "Awful",       C.RED),
]


def score_sus(responses: List[int]) -> float:
    """
    Compute SUS score from 10 Likert responses (1-5 each).

    Scoring formula:
      - Odd items (1,3,5,7,9): contribution = raw_score - 1
      - Even items (2,4,6,8,10): contribution = 5 - raw_score
      - Sum all 10 contributions, multiply by 2.5
      - Final range: 0 to 100
    """
    if len(responses) != 10:
        raise ValueError("SUS requires exactly 10 responses.")
    if not all(1 <= r <= 5 for r in responses):
        raise ValueError("All responses must be between 1 and 5.")

    total = 0
    for i, r in enumerate(responses):
        if (i + 1) % 2 == 1:      # odd item (1-indexed)
            total += r - 1
        else:                       # even item
            total += 5 - r

    return total * 2.5


def interpret_sus(score: float) -> tuple:
    """Return (adjective, grade, percentile_approx) for a SUS score."""
    for threshold, label, colour in SUS_ADJECTIVE_MAP:
        if score >= threshold:
            return label, colour

    return "Awful", C.RED


@dataclass
class SUSResult:
    participant_id: str
    responses:      List[int]
    score:          float
    adjective:      str
    timestamp:      str = field(default_factory=lambda: datetime.now().isoformat())


def collect_sus_interactive(participant_id: str) -> SUSResult:
    """Interactively collect SUS responses from a study participant."""
    print(f"\n{C.BOLD}SUS Questionnaire — {participant_id}{C.RESET}")
    print(f"{C.DIM}Scale: {SUS_SCALE}{C.RESET}\n")

    responses = []
    for i, q in enumerate(SUS_QUESTIONS, 1):
        while True:
            print(f"  Q{i:2d}. {q}")
            raw = input(f"       Response [1-5]: ").strip()
            if raw.isdigit() and 1 <= int(raw) <= 5:
                responses.append(int(raw))
                break
            print(f"       {C.RED}Invalid input. Enter a number between 1 and 5.{C.RESET}")
        print()

    score = score_sus(responses)
    adj, _ = interpret_sus(score)
    return SUSResult(participant_id=participant_id, responses=responses,
                     score=score, adjective=adj)


# ─────────────────────────────────────────────
# TASK DATA
# ─────────────────────────────────────────────

TASK_DEFINITIONS = {
    "T1": {
        "name":    "Generate E2EE Key Pair",
        "scenario": "You want to send a private message using E2EE. "
                    "Start by generating your own key pair.",
        "success_criteria": [
            "Navigates to key generation without prompting",
            "Correctly identifies the public key as the one to share",
            "Does not confuse public and private keys",
        ]
    },
    "T2": {
        "name":    "Complete Key Exchange and Encrypt",
        "scenario": "A contact has sent you their public key (provided on the card). "
                    "Use it to encrypt the message: "
                    "'The meeting is at the library on Thursday at 6pm.'",
        "success_criteria": [
            "Pastes contact public key correctly",
            "Navigates to Encrypt tab and enters message",
            "Produces a valid PS1E: ciphertext output",
        ]
    },
    "T3": {
        "name":    "Metadata Analysis",
        "scenario": "Before sending, check the following message for privacy risks: "
                    "'Hi, it is Sarah at sarah.jones@gmail.com, "
                    "call me on 07700 900123, I live at 14 Baker Street.'",
        "success_criteria": [
            "Finds the Metadata Check tab without help",
            "Pastes the message and runs the analysis",
            "Correctly identifies at least 2 flagged items as privacy risks",
        ]
    },
    "T4": {
        "name":    "Decrypt a Received Message",
        "scenario": "A friend sent you this encrypted message (provided on the card). "
                    "You already completed key exchange. Please decrypt and read it.",
        "success_criteria": [
            "Navigates to Decrypt tab",
            "Pastes the ciphertext",
            "Successfully reveals the plaintext",
        ]
    },
}


@dataclass
class TaskResult:
    participant_id: str
    task_id:        str
    task_name:      str
    success:        bool
    time_seconds:   float
    error_count:    int
    help_requests:  int
    notes:          str = ""


# ─────────────────────────────────────────────
# SESSION LOGGER (Think-Aloud Protocol)
# ─────────────────────────────────────────────

class SessionLogger:
    """
    Real-time event logger for think-aloud usability sessions.

    Based on standard HCI evaluation methodology (Nielsen, 1994).
    The moderator uses keyboard shortcuts to log events without
    interrupting the participant.
    """

    def __init__(self, participant_id: str, output_dir: str = "./data"):
        self.participant_id = participant_id
        self.output_dir     = output_dir
        self.events:  List[dict] = []
        self.tasks:   List[TaskResult] = []
        self._task_start_time: Optional[float] = None
        self._current_task:   Optional[str]    = None
        self._current_errors: int = 0
        self._current_helps:  int = 0
        os.makedirs(output_dir, exist_ok=True)

    def _log(self, event_type: str, detail: str = ""):
        self.events.append({
            "participant": self.participant_id,
            "task":        self._current_task,
            "event":       event_type,
            "detail":      detail,
            "ts":          time.time(),
        })

    def start_task(self, task_id: str):
        self._current_task   = task_id
        self._task_start_time = time.time()
        self._current_errors = 0
        self._current_helps  = 0
        task_name = TASK_DEFINITIONS.get(task_id, {}).get("name", task_id)
        self._log("TASK_START", task_name)
        print(f"\n  {C.CYAN}[TASK START]{C.RESET} {task_id}: {task_name}")

    def record_error(self, description: str = ""):
        self._current_errors += 1
        self._log("ERROR", description)
        print(f"  {C.RED}[ERROR]{C.RESET} {description}")

    def record_help(self, context: str = ""):
        self._current_helps += 1
        self._log("HELP_REQUEST", context)
        print(f"  {C.YELLOW}[HELP]{C.RESET} {context}")

    def record_note(self, note: str):
        self._log("OBSERVATION", note)
        print(f"  {C.DIM}[NOTE]{C.RESET} {note}")

    def end_task(self, success: bool, notes: str = ""):
        elapsed = time.time() - (self._task_start_time or time.time())
        task_name = TASK_DEFINITIONS.get(self._current_task, {}).get("name", self._current_task)
        result = TaskResult(
            participant_id = self.participant_id,
            task_id        = self._current_task,
            task_name      = task_name,
            success        = success,
            time_seconds   = round(elapsed, 2),
            error_count    = self._current_errors,
            help_requests  = self._current_helps,
            notes          = notes,
        )
        self.tasks.append(result)
        status = f"{C.GREEN}SUCCESS{C.RESET}" if success else f"{C.RED}FAILURE{C.RESET}"
        print(f"  {C.CYAN}[TASK END]{C.RESET} {status}  time={elapsed:.1f}s  "
              f"errors={self._current_errors}  helps={self._current_helps}")
        self._log("TASK_END", f"success={success}")

    def save(self):
        base = os.path.join(self.output_dir, self.participant_id)
        with open(base + "_events.json", "w") as f:
            json.dump(self.events, f, indent=2)
        with open(base + "_tasks.json", "w") as f:
            json.dump([asdict(t) for t in self.tasks], f, indent=2)
        print(f"\n  {C.GREEN}[+]{C.RESET} Session saved: {base}_events.json")


# ─────────────────────────────────────────────
# STUDY ANALYSER
# ─────────────────────────────────────────────

class StudyAnalyser:
    """Aggregates results from multiple participants and generates the study report."""

    def __init__(self, data_dir: str = "./data"):
        self.data_dir    = data_dir
        self.sus_results: List[SUSResult] = []
        self.task_results: List[TaskResult] = []

    def load_all(self):
        """Load all JSON session files from the data directory."""
        for fname in os.listdir(self.data_dir):
            if fname.endswith("_tasks.json"):
                path = os.path.join(self.data_dir, fname)
                with open(path) as f:
                    for row in json.load(f):
                        self.task_results.append(TaskResult(**row))

            elif fname.endswith("_sus.json"):
                path = os.path.join(self.data_dir, fname)
                with open(path) as f:
                    data = json.load(f)
                    self.sus_results.append(SUSResult(**data))

    def task_success_rate(self, task_id: str) -> float:
        tasks = [t for t in self.task_results if t.task_id == task_id]
        if not tasks:
            return 0.0
        return sum(1 for t in tasks if t.success) / len(tasks) * 100

    def mean_time(self, task_id: str) -> float:
        tasks = [t for t in self.task_results if t.task_id == task_id and t.success]
        if not tasks:
            return 0.0
        return statistics.mean(t.time_seconds for t in tasks)

    def mean_errors(self, task_id: str) -> float:
        tasks = [t for t in self.task_results if t.task_id == task_id]
        if not tasks:
            return 0.0
        return statistics.mean(t.error_count for t in tasks)

    def mean_sus(self) -> float:
        if not self.sus_results:
            return 0.0
        return statistics.mean(r.score for r in self.sus_results)

    def print_report(self):
        print(f"\n{C.BOLD}{C.CYAN}{'='*60}")
        print("  PrivacyShield v3 — Usability Study Report")
        print(f"  Participants: {len(self.sus_results)}")
        print(f"{'='*60}{C.RESET}\n")

        print(f"{C.BOLD}Task Performance{C.RESET}")
        print(f"{'Task':<35} {'Success':>8} {'Avg Time':>10} {'Avg Errors':>12}")
        print("-" * 70)

        for tid, tdef in TASK_DEFINITIONS.items():
            sr  = self.task_success_rate(tid)
            mt  = self.mean_time(tid)
            me  = self.mean_errors(tid)
            sc  = C.GREEN if sr >= 90 else C.YELLOW if sr >= 75 else C.RED
            print(f"  {tdef['name']:<33} {sc}{sr:>7.1f}%{C.RESET} "
                  f"  {mt:>7.1f}s   {me:>9.1f}")

        all_tasks = [t for t in self.task_results]
        if all_tasks:
            overall = sum(1 for t in all_tasks if t.success) / len(all_tasks) * 100
            sc = C.GREEN if overall >= 90 else C.YELLOW
            print(f"\n  {'OVERALL':33} {sc}{overall:>7.1f}%{C.RESET}\n")

        if self.sus_results:
            mean = self.mean_sus()
            adj, ac = interpret_sus(mean)
            print(f"{C.BOLD}System Usability Scale{C.RESET}")
            print(f"  Mean SUS score : {ac}{C.BOLD}{mean:.1f} / 100{C.RESET}")
            print(f"  Rating         : {ac}{adj}{C.RESET}")
            print(f"  Sample size    : {len(self.sus_results)}\n")

            scores = [r.score for r in self.sus_results]
            print(f"  Min: {min(scores):.1f}   Max: {max(scores):.1f}   "
                  f"StdDev: {statistics.stdev(scores):.1f}\n")

    def export_csv(self, path: str = "./study_results.csv"):
        """Export task results as CSV for statistical analysis (e.g. in R or SPSS)."""
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "participant_id", "task_id", "task_name",
                "success", "time_seconds", "error_count", "help_requests", "notes"
            ])
            for t in self.task_results:
                writer.writerow([
                    t.participant_id, t.task_id, t.task_name,
                    int(t.success), t.time_seconds, t.error_count,
                    t.help_requests, t.notes
                ])
        print(f"{C.GREEN}[+]{C.RESET} Task results exported to: {path}")

    def export_sus_csv(self, path: str = "./sus_scores.csv"):
        """Export SUS scores as CSV."""
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["participant_id", "score", "adjective"] +
                            [f"Q{i}" for i in range(1, 11)])
            for r in self.sus_results:
                writer.writerow([r.participant_id, r.score, r.adjective] + r.responses)
        print(f"{C.GREEN}[+]{C.RESET} SUS scores exported to: {path}")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def cmd_sus(args):
    pid = args.participant or input("  Participant ID (e.g. P01): ").strip()
    result = collect_sus_interactive(pid)
    adj, ac = interpret_sus(result.score)
    print(f"\n  {C.BOLD}SUS Score:{C.RESET} {ac}{result.score:.1f} / 100{C.RESET}  "
          f"({ac}{result.adjective}{C.RESET})")

    out_path = os.path.join(args.data_dir, f"{pid}_sus.json")
    os.makedirs(args.data_dir, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(asdict(result), f, indent=2)
    print(f"  {C.GREEN}[+]{C.RESET} Saved to: {out_path}")


def cmd_analyse(args):
    analyser = StudyAnalyser(args.data_dir)
    analyser.load_all()
    analyser.print_report()
    if args.csv:
        analyser.export_csv()
        analyser.export_sus_csv()


def cmd_session(args):
    pid    = args.participant or input("  Participant ID: ").strip()
    logger = SessionLogger(pid, args.data_dir)
    print(f"\n{C.CYAN}Session started for {pid}{C.RESET}")
    print(f"{C.DIM}Commands: s <task_id>  e <desc>  h <context>  n <note>  "
          f"ok <notes>  fail <notes>  save  quit{C.RESET}\n")

    while True:
        cmd = input("> ").strip().split(None, 1)
        if not cmd:
            continue
        action = cmd[0].lower()
        detail = cmd[1] if len(cmd) > 1 else ""

        if action == "s":
            logger.start_task(detail)
        elif action == "e":
            logger.record_error(detail)
        elif action == "h":
            logger.record_help(detail)
        elif action == "n":
            logger.record_note(detail)
        elif action == "ok":
            logger.end_task(True, detail)
        elif action == "fail":
            logger.end_task(False, detail)
        elif action == "save":
            logger.save()
        elif action in ("quit", "q", "exit"):
            logger.save()
            break
        else:
            print(f"  Unknown command: {action}")


def main():
    p = argparse.ArgumentParser(
        prog="ux_research",
        description="PrivacyShield — UX Research Toolkit (SUS, Think-Aloud, Analysis)"
    )
    p.add_argument("--data-dir", default="./ux_data", help="Directory for session data")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("sus",     help="Enter SUS questionnaire responses")
    sp.add_argument("--participant", help="Participant ID")

    sa = sub.add_parser("analyse", help="Analyse all collected session data")
    sa.add_argument("--csv", action="store_true", help="Export results as CSV")

    ss = sub.add_parser("session", help="Run a live think-aloud session")
    ss.add_argument("--participant", help="Participant ID")

    args = p.parse_args()
    dispatch = {"sus": cmd_sus, "analyse": cmd_analyse, "session": cmd_session}

    if args.cmd not in dispatch:
        p.print_help()
        return

    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
